# NetInfra IP Manager

A Python/FastAPI application for managing host configuration in `NetInfra.yml`
and comparing intended configuration with network observations. The
[approved design](DESIGN.md) defines v1 behavior; the
[implementation plan](IMPLEMENTATION_PLAN.md) tracks delivery order.

## Implementation status

Phases 1–3 (foundation, reconciliation, and secure access) are implemented:

- `create_app()` constructs independent applications without creating configuration,
  credentials, logs, or database files at import time.
- FastAPI lifespan explicitly validates settings, initializes/version-checks SQLite,
  starts one scan manager, and closes probes, storage, and audit handlers on shutdown.
- SQLite on persistent local storage retains latest observations, job summaries,
  and schedule definitions. Redis and process-memory fallback are removed. Database
  initialization errors fail startup; newer schema versions are rejected.
- Queued/running jobs found after restart become `interrupted` and incomplete.
  Graceful shutdown cancels active work and awaits outstanding probes.
- One scan job runs at a time. Targets are streamed through bounded workers;
  raw ping/DNS/MAC observations are stored separately from job summaries. Silent undocumented
  addresses do not create observation rows. Completed job retention defaults to 100.
- Administrators are provisioned only through the CLI, never during web startup.
- Inventory includes IPv4 A/default-A and `no_dns` records with optional MACs.
  Shared addresses retain all definitions and prefer MAC-bearing records. Agreeing
  MACs retain their associated identities; conflicting/invalid definitions have
  no arbitrarily selected authority.
- DNS owners use `Source`, then `AltHostName`, then host `Name`. Absolute owners
  remain absolute; relative owners append `ZoneName`. `star` renders as `*` and
  `___` is removed. Original fields, comments, custom properties, and other
  record types remain intact and visible through read-only host details.
- Checks compare complete expected A-answer sets exactly. Missing/extra answers
  and observable MAC differences are mismatches; DNS failures, ping timeouts,
  and unavailable MACs remain incomplete evidence. `no_dns` skips DNS; missing
  MAC skips MAC lookup/comparison.
- Diagnostics and `/outliers` expose invalid structures/assignments and addresses
  outside declared subnets. Probe entry points reject undeclared targets.
- Raw observations retain their exact file revision and semantic expectation
  fingerprint. Relevant edits mark affected evidence stale, including another
  address changing the same DNS answer set. Unrelated comments/custom-field edits
  do not invalidate otherwise current evidence.
- Refresh and full subnet checks share the single durable runner. Concurrent
  probe requests are rejected as busy rather than starting independent workers.
  Address/outlier pages are bounded to 256 rows; large subnet pagination uses
  direct address arithmetic, not enumeration of earlier pages.

**This is not production-ready v1.** Authentication and access controls are
implemented, but host write-back still has the starter's direct-write and unbound
preview limitations. Use a disposable NetInfra copy until phase 4 delivers
revision-bound reviewed changes, validation, backups, and atomic saves.

Full host editing/import, reviewed atomic writes, complete scan scope/mode controls,
start-rate limits, scheduling execution, age-based freshness, discovery coverage,
filters, and progressive updates remain pending. The starter full-scan web route
still uses prefix-based limits, including its default `/16` restriction; known-only
refresh and address browsing have no CIDR-size cutoff. Stored schedules have no
execution/UI yet and default to disabled. Latest undocumented ping responses are
visible, but DHCP-pool context and discovery-to-host review are not implemented.
Git behavior remains starter code, not the approved safe local-commit flow.

## Development quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp ipman-config.example.yml ipman-config.yml
chmod 600 ipman-config.yml
# Local HTTP only: edit ipman-config.yml and set session_cookie_secure: false.
netinfra-ipman-init
uvicorn netinfra_ipman.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers --no-access-log
```

Open <http://127.0.0.1:8000>. The example configuration points at
`examples/NetInfra.yml`; copy it to a disposable location before exercising writes.
The initializer prompts for an emergency local administrator password. It honors
`IPMAN_CONFIG` just like the application. Web startup never generates credentials.
Sessions default to Secure cookies. For real deployments, retain
`session_cookie_secure: true` and serve HTTPS through the reverse proxy. The
explicit insecure setting above is only for loopback development.

## Configuration and storage

Set `IPMAN_CONFIG=/path/to/ipman-config.yml` to select the settings file; the default
is `./ipman-config.yml`. Missing files use validated defaults without writing a
configuration file. Unknown settings and invalid types/values are rejected.
Paths are relative to the process working directory unless absolute.

Replace the retired `redis_url` setting with `sqlite_path` (default
`./ipman.sqlite3`). Redis state is not migrated. Select a persistent **local disk**
path, separate from NetInfra, settings, credentials, and audit logs. SQLite is
required: there is no memory fallback. Parent directories are created at explicit
startup. `completed_job_retention` defaults to 100; zero keeps no terminal jobs.
Latest observations and schedule definitions are retained across restarts.

SQLite schema 3 adds durable hashed sessions and expiring, one-use OIDC
transactions. The schema-2 migration of phase-1 observations is retained: old
verdicts become raw evidence without intended values. Historical observations
without a semantic fingerprint remain stale until checked again.

Scanner resolvers are separate from NetInfra DHCP options. `dns_servers` is the
global list; `subnet_dns_servers` maps canonical IPv4 CIDRs to resolver lists.
The most-specific matching override wins; an empty selected override falls back
to the global list. With neither configured, use the server resolver. DNS queries
are absolute and do not use resolver search suffixes. The Options page accepts
resolver overrides as a JSON object; the configuration file uses YAML mappings.

Administrator-only `/options` and `/audit` pages enforce permissions server-side.
Secrets are omitted from settings HTML and rejected on settings POSTs. Sensitive
OIDC/session/proxy/path fields are restart-only; edit the protected configuration
file rather than trying to switch them live. Redacted values in other fields
are also read-only, so masks cannot accidentally overwrite real configuration.
Accepted settings are validated and atomically saved with mode `0600`.

Run exactly one application worker against a runtime database. Multi-worker or
multi-server coordination is unsupported. SQLite contains runtime state only;
`NetInfra.yml` remains authoritative for intended configuration. Recovery marks
interrupted jobs incomplete rather than automatically replaying them.


## Access, OIDC, and recovery

Anonymous viewing defaults to **disabled**. With `allow_anonymous_viewing: true`,
anonymous users can browse inventory only; no probes or mutations are authorized.

| Identity / role | Permissions |
| --- | --- |
| Viewer | Inventory, host details, outliers, and existing observations. |
| Editor | Viewer access plus host-change routes and manual scan launch/cancellation. |
| Administrator | Editor access plus settings and audit access. |

All unsafe application routes validate a browser-bound CSRF token, including
login and logout. Forms supply it automatically; programmatic requests may send
`X-CSRF-Token`. The OIDC callback instead validates one-use state bound to the
same verified browser session. Pre-login sessions never grant viewing or editing
permissions.

Sessions use high-entropy opaque cookies whose hashes are stored in SQLite, with
absolute expiry from `session_timeout_minutes` (default 60). Cookies are HttpOnly,
SameSite=Lax, and Secure by default. Logout revokes the local session immediately.
Old `ipman_user` cookies are ignored. Provider tokens are not retained.

### Generic OIDC

Configure the provider to sign ID tokens with **RS256**, allow authorization code
flow with PKCE S256, and register the exact configured callback URI. Discovery,
token exchange, JWKS signatures, issuer/audience, time claims, nonce, and state
are validated. Endpoints require HTTPS, except explicit loopback HTTP for local
development. Public PKCE clients and confidential clients using discovery's
`client_secret_basic` or `client_secret_post` are supported.

Example non-secret settings (replace deployment-specific URLs and mappings):

```yaml
oidc_enabled: true
oidc_issuer: https://idp.example.com/realms/infrastructure
oidc_client_id: netinfra-ipman
oidc_redirect_uri: https://ipman.example.com/oidc/callback
oidc_groups_claim: groups
oidc_roles_claim: realm_access.roles
oidc_group_role_map:
  ipman-viewers: viewer
  ipman-editors: editor
  ipman-administrators: administrator
oidc_claim_role_map: {}
```

For a confidential client, supply `oidc_client_secret` only in the protected
configuration file. Never put it in a URL, command argument, page, or repository.
Role/group claim paths can be dotted paths. The highest explicitly mapped role
wins; unmapped identities are denied. Relevant OIDC configuration changes
invalidate existing OIDC sessions after restart. Provider membership changes
take effect at the next sign-in; there is no retained refresh token. Application
logout does not terminate the identity provider's own session.

Remove retired `keycloak_*`, `duo_*`, `tls_enabled`, `reverse_proxy`, and the
previously unused `rate_limit_per_minute` settings. Loading them produces migration
guidance rather than silently accepting inactive configuration.

### Emergency administrator

`netinfra-ipman-init` is the sole provisioning path. It prompts for the username
and a password of at least 12 characters, writes private credentials atomically,
and requires password change on first login. Password hashing uses PBKDF2-SHA256
with 600,000 rounds; older hashes are upgraded on successful authentication.
Local lockout is configurable with `lockout_attempts` and `lockout_minutes`
(defaults 5 attempts and 15 minutes).

For recovery, run `IPMAN_CONFIG=/path/to/config.yml netinfra-ipman-init --replace`
on the server and complete the explicit replacement confirmation and password
prompts. Recovery and password changes invalidate all older local sessions.
Provisioning, recovery, authentication, and password-change outcomes are audited
without passwords or credential hashes. No web startup provisions credentials.

### Proxy and audit deployment

Keep SQLite, administrator credentials, settings, and audit files on protected
local storage; their parent directories must not be writable by untrusted users.
Configure `trusted_proxies` with only the actual proxy IPs/CIDRs (for example,
`["127.0.0.1/32"]` for a local proxy). Other peers' forwarding headers are ignored;
trusted forwarding chains are validated from right to left. OIDC redirects use
the fixed configured URI, never a forwarded host.

Use `--no-proxy-headers` so Uvicorn cannot rewrite the peer before application
trust checks. The CLI and Containerfile already disable Uvicorn proxy handling
and access logs. Keep `--no-access-log` when invoking Uvicorn directly: callback
queries contain authorization codes. Configure proxy logs to omit sensitive
queries, cookies, authorization headers, and request bodies; apply request limits
at the proxy.

Audit file rotation defaults to 10 MiB with five rotated files plus the active
file, independently of observations. Retention is configurable and bounded;
zero backup count is rejected. Logs redact secret fields and known secret values,
omit complete YAML snapshots, and use private permissions. `/audit` shows up to
100 recent entries from the active file, with historical redaction applied.
External syslog retention is the operator's responsibility.

## Verification

```bash
.venv/bin/python -m pytest -q
```

Tests use temporary files/databases and simulated probes/provider responses.
The suite passes **396 tests**, including session forgery/expiry/revocation,
CSRF, every role and both anonymous-view settings, OIDC signatures/claims/failure
paths, recovery, private configuration writes, proxy trust, audit redaction and
rotation, plus the earlier inventory/lifecycle coverage.

An isolated Uvicorn/browser smoke completed real signed OIDC exchanges against
a temporary local provider simulator for viewer/editor/administrator identities,
verified role restrictions, editor checks, protected settings/audit, anonymous
read-only access, CLI recovery, forced password change, and session revocation.
No external identity provider or live network scan was used. Production write
safety and complete v1 acceptance remain in phases 4–6.
