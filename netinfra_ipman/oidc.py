"""Browser-bound authorization-code OIDC login without retained provider tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import math
import secrets
import time
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

import httpx
from joserfc import jwt
from joserfc.jwk import KeySet
from authlib.oidc.core import CodeIDToken

from .config import AppConfig
from .persistence import RuntimeStore
from .security import Principal, Role


class OIDCError(Exception):
    """A deliberately non-diagnostic error safe to display to a browser."""

    def __init__(self):
        super().__init__("OpenID Connect login failed.")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _endpoint(value: object, *, issuer: bool = False) -> str:
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise OIDCError()
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise OIDCError()
    # Accessing port also rejects malformed ports, even when no request is made.
    parsed.port
    if parsed.port == 0 or "\\" in value:
        raise OIDCError()
    if parsed.fragment or (issuer and parsed.query):
        raise OIDCError()
    if parsed.scheme != "https":
        if parsed.scheme != "http":
            raise OIDCError()
        host = parsed.hostname.lower()
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise OIDCError()
    return value


def _claim_values(claims: dict, path: str) -> list[str]:
    value = claims
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return []
        value = value[part]
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise OIDCError()


class OidcClient:
    TRANSACTION_SECONDS = 600

    def __init__(self, config: AppConfig, store: RuntimeStore,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self.store = store
        self._http = httpx.AsyncClient(
            transport=transport, timeout=httpx.Timeout(10.0),
            follow_redirects=False, trust_env=False,
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def _json(self, method: str, url: str, **kwargs) -> dict:
        response = await self._http.request(method, _endpoint(url), **kwargs)
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict) or "error" in value:
            raise OIDCError()
        return value

    def _identity(self) -> dict:
        return {"issuer": _endpoint(self.config.oidc_issuer, issuer=True),
                "client_id": self.config.oidc_client_id,
                "redirect_uri": _endpoint(self.config.oidc_redirect_uri)}

    async def begin(self, browser_binding: str) -> str:
        try:
            if not self.config.oidc_enabled or not isinstance(browser_binding, str) or not browser_binding:
                raise OIDCError()
            self.store.purge_expired_security_state(time.time())
            identity = self._identity()
            if not identity["client_id"]:
                raise OIDCError()
            metadata = await self._json(
                "GET", identity["issuer"].rstrip("/") + "/.well-known/openid-configuration",
            )
            if metadata.get("issuer") != identity["issuer"]:
                raise OIDCError()
            for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                _endpoint(metadata.get(name))
            for name in ("response_types_supported", "code_challenge_methods_supported",
                         "token_endpoint_auth_methods_supported"):
                if name in metadata and (not isinstance(metadata[name], list)
                                         or not all(isinstance(item, str) for item in metadata[name])):
                    raise OIDCError()
            if "response_types_supported" in metadata and "code" not in metadata["response_types_supported"]:
                raise OIDCError()
            if "code_challenge_methods_supported" in metadata and "S256" not in metadata["code_challenge_methods_supported"]:
                raise OIDCError()
            state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
            transaction = {**identity, "binding": browser_binding, "nonce": nonce,
                           "verifier": verifier, "metadata": metadata}
            self.store.save_oidc_transaction(_digest(state), transaction,
                                             time.time() + self.TRANSACTION_SECONDS)
            parsed = urlsplit(metadata["authorization_endpoint"])
            parameters = dict(parse_qsl(parsed.query, keep_blank_values=True))
            parameters.update(response_type="code", client_id=identity["client_id"],
                              redirect_uri=identity["redirect_uri"], scope="openid profile",
                              state=state, nonce=nonce, code_challenge=challenge,
                              code_challenge_method="S256")
            return urlunsplit(parsed._replace(query=urlencode(parameters)))
        except Exception:
            raise OIDCError() from None

    async def complete(self, state: str, code: str, browser_binding: str) -> Principal:
        try:
            if not isinstance(state, str) or not state:
                raise OIDCError()
            # Consume before all other checks, including missing code and binding.
            transaction = self.store.consume_oidc_transaction(_digest(state), time.time())
            if not transaction or not self.config.oidc_enabled:
                raise OIDCError()
            if not isinstance(browser_binding, str) or not hmac.compare_digest(
                transaction["binding"], browser_binding,
            ):
                raise OIDCError()
            if not isinstance(code, str) or not code:
                raise OIDCError()
            identity = self._identity()
            if any(transaction.get(key) != value for key, value in identity.items()):
                raise OIDCError()
            metadata = transaction["metadata"]
            data = {"grant_type": "authorization_code", "code": code,
                    "redirect_uri": identity["redirect_uri"],
                    "code_verifier": transaction["verifier"]}
            methods = metadata.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
            auth = None
            secret = self.config.oidc_client_secret
            if secret and "client_secret_basic" in methods:
                auth = httpx.BasicAuth(quote_plus(identity["client_id"]), quote_plus(secret))
            elif secret and "client_secret_post" in methods:
                data.update(client_id=identity["client_id"], client_secret=secret)
            elif not secret and "none" in methods:
                data["client_id"] = identity["client_id"]
            else:
                raise OIDCError()
            tokens = await self._json("POST", metadata["token_endpoint"], data=data, auth=auth)
            encoded = tokens.get("id_token")
            if not isinstance(encoded, str) or not encoded:
                raise OIDCError()
            jwks = await self._json("GET", metadata["jwks_uri"])
            keys = jwks.get("keys")
            if not isinstance(keys, list):
                raise OIDCError()
            keys = [key for key in keys if isinstance(key, dict)
                    and key.get("kty") == "RSA" and key.get("use", "sig") == "sig"
                    and key.get("alg", "RS256") == "RS256"
                    and "verify" in key.get("key_ops", ["verify"])
                    and "d" not in key]
            if not keys:
                raise OIDCError()
            decoded = jwt.decode(encoded, KeySet.import_key_set({"keys": keys}), algorithms=["RS256"])
            if not isinstance(decoded.claims, dict):
                raise OIDCError()
            claims = CodeIDToken(
                decoded.claims, decoded.header,
                options={"iss": {"essential": True, "value": identity["issuer"]},
                         "aud": {"essential": True, "value": identity["client_id"]}},
                params={"nonce": transaction["nonce"], "client_id": identity["client_id"],
                        "access_token": tokens.get("access_token")},
            )
            for name in ("exp", "iat"):
                value = claims.get(name)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise OIDCError()
            audience = claims.get("aud")
            if not (isinstance(audience, str) or
                    (isinstance(audience, list) and audience and all(isinstance(a, str) for a in audience))):
                raise OIDCError()
            if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != identity["client_id"]:
                raise OIDCError()
            if "azp" in claims and claims["azp"] != identity["client_id"]:
                raise OIDCError()
            if "at_hash" in claims and (not isinstance(claims["at_hash"], str)
                                        or not claims["at_hash"]
                                        or not isinstance(tokens.get("access_token"), str)
                                        or not tokens["access_token"]):
                raise OIDCError()
            claims.validate(now=time.time(), leeway=0)
            if claims["exp"] <= time.time():
                raise OIDCError()
            subject = claims.get("sub")
            username = claims.get("preferred_username", subject)
            if not isinstance(subject, str) or not subject or not isinstance(username, str) or not username:
                raise OIDCError()
            roles = []
            for path, mapping in ((self.config.oidc_groups_claim, self.config.oidc_group_role_map),
                                  (self.config.oidc_roles_claim, self.config.oidc_claim_role_map)):
                for value in _claim_values(claims, path):
                    if value in mapping:
                        roles.append(Role(mapping[value]))
            if not roles:
                raise OIDCError()
            rank = {Role.viewer: 0, Role.editor: 1, Role.administrator: 2}
            return Principal(subject=identity["issuer"] + "|" + subject,
                             username=username, role=max(roles, key=rank.__getitem__), auth_method="oidc")
        except Exception:
            raise OIDCError() from None
