import asyncio
import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from netinfra_ipman import oidc
from netinfra_ipman.config import AppConfig
from netinfra_ipman.oidc import OIDCError, OidcClient
from netinfra_ipman.persistence import RuntimeStore
from netinfra_ipman.security import Role


@pytest.fixture(scope="module")
def signing_keys():
    result = []
    for _ in range(2):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        jwk = RSAKey.import_key(public, {"kid": "signing", "use": "sig", "alg": "RS256"}).as_dict()
        result.append((private, jwk))
    return result


class Provider:
    def __init__(self, keys):
        self.keys = keys
        self.issuer = "https://idp.example/tenant"
        self.metadata = {
            "issuer": self.issuer,
            "authorization_endpoint": self.issuer + "/authorize?provider_option=keep",
            "token_endpoint": self.issuer + "/token",
            "jwks_uri": self.issuer + "/jwks",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }
        self.parameters = None
        self.claim_updates = {}
        self.remove_claims = []
        self.signing_key = 0
        self.algorithm = "RS256"
        self.token_override = None
        self.jwks_override = None
        self.failure = None
        self.requests = []
        self.token_requests = []
        self.access_token = "provider-access-token-must-not-leak"

    def handle(self, request):
        self.requests.append(request)
        if self.failure == "network":
            raise httpx.ConnectError("secret-provider-diagnostic", request=request)
        if self.failure == "redirect":
            return httpx.Response(302, headers={"location": "http://attacker.example/steal"})
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.metadata)
        if request.url.path.endswith("/jwks"):
            return httpx.Response(200, json=self.jwks_override if self.jwks_override is not None
                                  else {"keys": [self.keys[0][1]]})
        if request.url.path.endswith("/token"):
            form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
            self.token_requests.append((request, form))
            if self.failure == "provider":
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "secret-provider-diagnostic"})
            if self.failure == "malformed":
                return httpx.Response(200, content="not json secret-provider-diagnostic")
            if self.token_override is not None:
                return httpx.Response(200, json=self.token_override)
            # The simulated provider independently verifies the S256 challenge.
            verifier_hash = hashlib.sha256(form["code_verifier"].encode()).digest()
            challenge = base64.urlsafe_b64encode(verifier_hash).rstrip(b"=").decode()
            assert challenge == self.parameters["code_challenge"]
            assert form["redirect_uri"] == "https://ipman.example/oidc/callback"
            assert form["grant_type"] == "authorization_code"
            assert form["code"] == "authorization-code"
            now = int(time.time())
            at_hash = base64.urlsafe_b64encode(hashlib.sha256(self.access_token.encode()).digest()[:16]).rstrip(b"=").decode()
            claims = {"iss": self.issuer, "sub": "user-42", "aud": "ipman-client",
                      "iat": now - 1, "exp": now + 300, "nonce": self.parameters["nonce"],
                      "preferred_username": "alice", "groups": ["operators"], "at_hash": at_hash}
            claims.update(self.claim_updates)
            for name in self.remove_claims:
                claims.pop(name, None)
            key = (RSAKey.import_key(self.keys[self.signing_key][0]) if self.algorithm == "RS256"
                   else OctKey.import_key("symmetric-attacker-key-material-at-least-32-bytes"))
            encoded = jwt.encode(
                {"alg": self.algorithm, "kid": "signing"}, claims, key, algorithms=[self.algorithm],
            )
            return httpx.Response(200, json={"id_token": encoded, "access_token": self.access_token,
                                            "token_type": "Bearer"})
        raise AssertionError("Unexpected provider request")


@pytest.fixture
def flow(tmp_path, signing_keys):
    config = AppConfig(oidc_enabled=True, oidc_issuer="https://idp.example/tenant",
                       oidc_client_id="ipman-client", oidc_client_secret="client-secret-must-not-leak",
                       oidc_redirect_uri="https://ipman.example/oidc/callback",
                       oidc_group_role_map={"operators": "editor"})
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()
    provider = Provider(signing_keys)
    client = OidcClient(config, store, transport=httpx.MockTransport(provider.handle))
    yield client, provider, config, store
    asyncio.run(client.close())
    store.close()


async def begin(client, provider, binding="verified-cookie-hash"):
    url = await client.begin(binding)
    provider.parameters = {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}
    return provider.parameters["state"]


def test_complete_signed_pkce_login_and_single_use_state(flow, tmp_path):
    client, provider, config, store = flow

    async def scenario():
        assert provider.requests == []  # No constructor/startup discovery.
        state = await begin(client, provider)
        parameters = provider.parameters
        assert parameters["client_id"] == config.oidc_client_id
        assert parameters["response_type"] == "code"
        assert parameters["redirect_uri"] == config.oidc_redirect_uri
        assert parameters["scope"] == "openid profile"
        assert parameters["code_challenge_method"] == "S256"
        assert parameters["provider_option"] == "keep"
        assert len(state) >= 43 and len(parameters["nonce"]) >= 43
        principal = await client.complete(state, "authorization-code", "verified-cookie-hash")
        assert principal.subject == provider.issuer + "|user-42"
        assert principal.username == "alice"
        assert principal.role == Role.editor and principal.auth_method == "oidc"
        assert provider.token_requests[0][0].headers["authorization"].startswith("Basic ")
        assert not any("userinfo" in str(request.url) for request in provider.requests)
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
        assert len(provider.token_requests) == 1
        assert store.consume_oidc_transaction(hashlib.sha256(state.encode()).hexdigest(), time.time()) is None
    asyncio.run(scenario())
    # Durable storage contains no raw state, authorization code, or provider tokens.
    persisted = (tmp_path / "runtime.sqlite3").read_bytes()
    assert provider.access_token.encode() not in persisted


@pytest.mark.parametrize("updates,expected", [
    ({"realm_access": {"roles": ["read", "admin"]}, "groups": ["operators"]}, Role.administrator),
    ({"realm_access": {"roles": "read"}, "groups": []}, Role.viewer),
])
def test_dotted_roles_highest_privilege_and_username_fallback(flow, updates, expected):
    client, provider, config, _ = flow
    config.oidc_roles_claim = "realm_access.roles"
    config.oidc_claim_role_map = {"read": "viewer", "admin": "administrator"}
    provider.claim_updates = updates
    provider.remove_claims = ["preferred_username", "at_hash"]

    async def scenario():
        state = await begin(client, provider)
        principal = await client.complete(state, "authorization-code", "verified-cookie-hash")
        assert principal.role == expected and principal.username == "user-42"
    asyncio.run(scenario())


@pytest.mark.parametrize("updates", [
    {"iss": "https://attacker.example"}, {"aud": "other-client"},
    {"aud": ["ipman-client", "other-client"]}, {"azp": "other-client"},
    {"nonce": "wrong-nonce"}, {"exp": 1}, {"iat": 9999999999},
    {"exp": "9999999999"}, {"exp": True}, {"iat": False},
    {"groups": ["unmapped"]}, {"groups": {"operators": True}},
    {"groups": ["operators", 3]}, {"sub": ""}, {"sub": 42},
    {"at_hash": "invalid-access-token-hash"}, {"at_hash": ""},
])
def test_invalid_signed_claims_deny_login_without_replay(flow, updates):
    client, provider, _, _ = flow
    provider.claim_updates = updates

    async def scenario():
        state = await begin(client, provider)
        with pytest.raises(OIDCError, match=r"^OpenID Connect login failed\.$"):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
        assert len(provider.token_requests) == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "exp", "iat", "nonce"])
def test_required_signed_claims_cannot_be_omitted(flow, missing):
    client, provider, _, _ = flow
    provider.remove_claims = [missing]

    async def scenario():
        state = await begin(client, provider)
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
    asyncio.run(scenario())


def test_multi_audience_requires_matching_authorized_party(flow):
    client, provider, _, _ = flow
    provider.claim_updates = {"aud": ["other-client", "ipman-client"], "azp": "ipman-client"}

    async def scenario():
        state = await begin(client, provider)
        assert (await client.complete(state, "authorization-code", "verified-cookie-hash")).role == Role.editor
    asyncio.run(scenario())


@pytest.mark.parametrize("attack", ["wrong-signature", "symmetric", "unsigned", "untrusted-jwks", "no-id-token"])
def test_signature_and_signed_token_required(flow, attack):
    client, provider, _, _ = flow
    if attack == "wrong-signature":
        provider.signing_key = 1
    elif attack == "symmetric":
        provider.algorithm = "HS256"
    elif attack == "unsigned":
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "unsigned", "groups": ["operators"]}).encode()).rstrip(b"=").decode()
        provider.token_override = {"id_token": header + "." + payload + "."}
    elif attack == "untrusted-jwks":
        provider.jwks_override = {"keys": [{"kty": "oct", "kid": "signing", "k": "c2VjcmV0"}]}
    else:
        provider.token_override = {"access_token": provider.access_token,
                                   "groups": ["operators"], "sub": "unsigned"}

    async def scenario():
        state = await begin(client, provider)
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
    asyncio.run(scenario())


@pytest.mark.parametrize("binding,code", [("attacker-cookie", "authorization-code"),
                                         ("", "authorization-code"),
                                         ("verified-cookie-hash", ""),
                                         ("verified-cookie-hash", None)])
def test_invalid_binding_and_missing_code_consume_transaction(flow, binding, code):
    client, provider, _, _ = flow

    async def scenario():
        state = await begin(client, provider)
        with pytest.raises(OIDCError):
            await client.complete(state, code, binding)
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
        assert provider.token_requests == []
    asyncio.run(scenario())


def test_expired_and_unknown_state_never_exchange_code(flow, monkeypatch):
    client, provider, _, _ = flow

    async def scenario():
        state = await begin(client, provider)
        future = time.time() + client.TRANSACTION_SECONDS + 1
        monkeypatch.setattr(oidc.time, "time", lambda: future)
        for candidate in (state, "unknown-state", ""):
            with pytest.raises(OIDCError):
                await client.complete(candidate, "authorization-code", "verified-cookie-hash")
        assert provider.token_requests == []
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["provider", "malformed", "network", "redirect"])
def test_provider_failures_are_sanitized_and_state_is_consumed(flow, failure):
    client, provider, config, _ = flow

    async def scenario():
        state = await begin(client, provider)
        provider.failure = failure
        with pytest.raises(OIDCError) as caught:
            await client.complete(state, "authorization-code", "verified-cookie-hash")
        assert str(caught.value) == "OpenID Connect login failed."
        assert "secret" not in str(caught.value)
        assert config.oidc_client_secret not in str(caught.value)
        provider.failure = None
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
    asyncio.run(scenario())


@pytest.mark.parametrize("field,value", [
    ("issuer", "https://other.example/tenant"),
    ("authorization_endpoint", "http://idp.example/authorize"),
    ("token_endpoint", "http://192.168.1.2/token"),
    ("jwks_uri", "https://user:secret@idp.example/jwks"),
    ("jwks_uri", "https://idp.example/jwks#fragment"),
    ("jwks_uri", None), ("response_types_supported", "code"),
    ("code_challenge_methods_supported", ["plain"]),
])
def test_unsafe_or_malformed_discovery_is_rejected(flow, field, value):
    client, provider, _, _ = flow
    provider.metadata[field] = value
    with pytest.raises(OIDCError):
        asyncio.run(client.begin("verified-cookie-hash"))
    assert len(provider.requests) == 1 and provider.token_requests == []


@pytest.mark.parametrize("url", ["http://localhost:8080/authorize", "http://127.0.0.1/authorize", "http://[::1]/authorize"])
def test_loopback_http_development_endpoints_permitted(flow, url):
    client, provider, _, _ = flow
    provider.metadata["authorization_endpoint"] = url
    assert asyncio.run(client.begin("verified-cookie-hash")).startswith(url + "?")


@pytest.mark.parametrize("method,secret", [("client_secret_post", "client-secret-must-not-leak"), ("none", "")])
def test_standard_token_endpoint_authentication_methods(flow, method, secret):
    client, provider, config, _ = flow
    provider.metadata["token_endpoint_auth_methods_supported"] = [method]
    config.oidc_client_secret = secret

    async def scenario():
        state = await begin(client, provider)
        assert (await client.complete(state, "authorization-code", "verified-cookie-hash")).role == Role.editor
        request, form = provider.token_requests[0]
        assert "authorization" not in request.headers
        assert form["client_id"] == config.oidc_client_id
        if secret:
            assert form["client_secret"] == secret
        else:
            assert "client_secret" not in form
    asyncio.run(scenario())


def test_configuration_change_invalidates_in_flight_login(flow):
    client, provider, config, _ = flow

    async def scenario():
        state = await begin(client, provider)
        config.oidc_client_id = "changed-client"
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
        assert provider.token_requests == []
    asyncio.run(scenario())


def test_transaction_survives_runtime_store_and_client_reopen(flow, tmp_path):
    client, provider, config, store = flow

    async def scenario():
        state = await begin(client, provider)
        await client.close()
        store.close()
        reopened = RuntimeStore(tmp_path / "runtime.sqlite3")
        reopened.initialize()
        replacement = OidcClient(config, reopened, transport=httpx.MockTransport(provider.handle))
        try:
            principal = await replacement.complete(state, "authorization-code", "verified-cookie-hash")
            assert principal.role == Role.editor
        finally:
            await replacement.close()
            reopened.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("document", [[], {"keys": "not-an-array"}, {"keys": []},
                                     {"keys": [{"kty": "RSA", "kid": "signing", "n": "invalid", "e": "AQAB"}]},
                                     {"keys": [{"kty": "RSA", "use": "enc"}]}])
def test_malformed_or_non_signing_jwks_denies_login(flow, document):
    client, provider, _, _ = flow
    provider.jwks_override = document

    async def scenario():
        state = await begin(client, provider)
        with pytest.raises(OIDCError, match=r"^OpenID Connect login failed\.$"):
            await client.complete(state, "authorization-code", "verified-cookie-hash")
    asyncio.run(scenario())




def test_disabled_login_and_unbound_browser_cannot_begin(flow):
    client, provider, config, _ = flow

    async def scenario():
        with pytest.raises(OIDCError):
            await client.begin("")
        config.oidc_enabled = False
        with pytest.raises(OIDCError):
            await client.begin("verified-cookie-hash")
        assert provider.requests == []
    asyncio.run(scenario())


def test_signed_non_object_claims_cannot_be_coerced_into_an_identity(flow):
    from joserfc import jws

    client, provider, config, _ = flow

    async def scenario():
        state = await begin(client, provider)
        now = int(time.time())
        pairs = [
            ["iss", provider.issuer], ["sub", "user-42"], ["aud", config.oidc_client_id],
            ["exp", now + 300], ["iat", now - 1], ["nonce", provider.parameters["nonce"]],
            ["groups", ["operators"]],
        ]
        encoded = jws.serialize_compact(
            {"alg": "RS256", "kid": "signing"}, json.dumps(pairs).encode(),
            RSAKey.import_key(provider.keys[0][0]), algorithms=["RS256"],
        )
        provider.token_override = {"id_token": encoded}
        with pytest.raises(OIDCError):
            await client.complete(state, "authorization-code", "verified-cookie-hash")

    asyncio.run(scenario())
