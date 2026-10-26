# NetInfra IP Manager

A Python/FastAPI application for managing host configuration in `NetInfra.yml`
and comparing intended configuration with network observations. The
[approved design](DESIGN.md) defines v1 behavior; the
[implementation plan](IMPLEMENTATION_PLAN.md) tracks delivery order.

## Implementation status

All six implementation phases are delivered. The phase-6 work adds search and
discrepancy filtering, sparse large-network queries, age-based freshness,
declared DHCP-pool context, scan progress polling, reviewed discovery proposals,
and a documented single-server TLS deployment. Deployment-specific OIDC,
trusted-proxy, network, and file/Git values remain operator configuration.

- `create_app()` constructs independent applications without creating configuration,
  credentials, logs, or database files at import time.
- FastAPI lifespan explicitly validates settings, initializes/version-checks SQLite,
  starts one scan manager and its schedule dispatcher, and closes probes, storage,
  schedules, and audit handlers on shutdown.
- SQLite on persistent local storage retains latest observations, compact discovery
  coverage, job summaries, and schedule definitions. Redis and process-memory fallback
  are removed. Database initialization errors fail startup; newer schema versions
  are rejected.
- Queued/running jobs found after restart become `interrupted` and incomplete.
  Graceful shutdown cancels active work and awaits outstanding probes.
- One scan job runs at a time. Targets are streamed through bounded workers;
  raw ping/DNS/MAC observations are stored separately from job summaries. Silent undocumented
  addresses do not create observation rows. Completed job retention defaults to 100.

- Scan requests support all declared subnets, one subnet, an inclusive IP range,
  or one IP with full, known-only, or discovery-only modes. The planner validates
  declared coverage, deduplicates overlap, streams large IPv4 ranges, and supports
  every prefix including `/31` and `/32`; there is no fixed `/16` cutoff.
- The runner defaults to 128 concurrent checks and 100 address-check starts per
  second. Manual scans above 4,096 targets require explicit confirmation enforced
  by the manager as well as the UI. Cancellation waits for synchronous probes;
  completed discovery coverage is stored compactly in SQLite schema 4.
- Administrators create, edit, enable/disable, and delete interval, daily, and
  weekly schedules from `/schedules`; new schedules start disabled. Schedules
  use explicit IANA timezones, skip nonexistent DST times, run repeated local
  times once, coalesce while busy, and resolve targets against current NetInfra
  at dispatch. Downtime does not trigger catch-up.
- Administrators are provisioned only through the CLI, never during web startup.
- Inventory includes IPv4 A/default-A and `no_dns` records with optional MACs.
  Shared addresses retain all definitions and prefer MAC-bearing records. Agreeing
  MACs retain their associated identities; conflicting/invalid definitions have
  no arbitrarily selected authority.
- DNS owners use `Source`, then `AltHostName`, then host `Name`. Absolute owners
  remain absolute; relative owners append `ZoneName`. `star` renders as `*` and
  `___` is removed. Original fields, comments, custom properties, and other
  record types remain intact and editable through host details and advanced YAML.
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
- Known refreshes and every manual scan scope use the same durable single runner.
  Concurrent scan requests are rejected as busy rather than starting independent
  workers. Address/outlier pages are bounded to 256 rows; large subnet pagination
  uses direct address arithmetic, not enumeration of earlier pages.

Host changes now use a shared reviewed transaction service:

- `/hosts` lists hosts with bounded pagination and read-only details. Editors can
  create, update, or delete hosts using common fields or the complete advanced
  YAML entry. Subnets and non-host sections remain read-only.
- Imports accept pasted or uploaded YAML as a host list or a `Hosts:` wrapper.
  Existing or repeated host names reject the whole batch; import never merges
  with or overwrites an existing host.
- Every mutation presents a full-file diff and validation findings. Apply posts
  only an opaque, one-use, actor-bound review token for the exact proposed bytes
  and source revision. Stale, altered, replayed, or direct apply requests fail.
- Complete proposal validation rejects malformed host structure, invalid known
  values, duplicate names, conflicting MACs, and eligible addresses outside
  declared subnets. Consistent shared-IP records and live network differences do
  not block a configuration save.
- Writes serialize within the application, recheck the source revision immediately
  before an atomic replacement, preserve file mode and round-trip YAML comments,
  preambles, quotes, ordering, custom fields, and unrelated sections. External
  writers that ignore app locks still require operational coordination.
- Backups default to `./ipman-backups` outside the source Git checkout, with 20
  retained copies. Configure `backup_dir` and `backup_retention` for deployment.
- Optional Git validates the configured checkout root, current branch and clean
  tree without switching branches. It commits only the saved NetInfra file, never
  pushes, reports commit failure separately from a successful file save, and
  provides a guarded retry. Remove retired `git_push` and `git_remote` settings.

**Phase 6 is implemented.** Inventory search/filtering, progressive job updates,
age-based freshness, DHCP-pool context, reviewed discovery creation, and a
single-server deployment package are delivered. Production readiness still
depends on validating the real identity provider, routing/resolver access,
file/Git permissions, storage, and operational recovery procedures. Start with
a disposable NetInfra copy.

For the Linux single-server TLS deployment, see [deploy/README.md](deploy/README.md).
The Compose and Caddy examples are operator templates; validate them against the
installed Docker, Caddy, proxy, and host networking configuration.

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

Replace retired `redis_url` with `sqlite_path` (default `./ipman.sqlite3`).
Redis state is not migrated. Select persistent **local disk** storage separate
from NetInfra, settings, credentials, and audit logs. SQLite is required; there is
no memory fallback. Parent directories are created at explicit startup.
`completed_job_retention` defaults to 100; zero keeps no terminal jobs. Latest
observations, compact discovery coverage, and schedule definitions persist across
restarts. Remove retired `large_subnet_prefix` and `max_subnet_prefix`; all IPv4
CIDR sizes are supported. Use `manual_scan_confirmation_threshold` (default
4,096) and `scan_start_rate` (default 100) to control workload rather than
restricting subnet sizes.

Host backups default to `./ipman-backups`, outside the detected source Git
checkout, with `backup_retention: 20`. Set `backup_dir` to protected persistent
storage outside the checkout; zero retention is rejected.

Optional local commits use `git_enabled`, `git_repo_path`, and `git_branch`.
The repository path must be the checkout root, the current branch must match,
and the tree must be clean before saving. Commits include only the NetInfra
source; there is no automatic push. A post-save commit failure is reported
separately and can be retried after resolving the Git failure. The app never
switches branches. Retired `git_push` and `git_remote` settings are rejected
and must be removed during configuration migration.

SQLite schema 4 adds compact discovery coverage to durable observations, jobs,
schedules, hashed sessions, and expiring one-use OIDC transactions. Earlier
observation migrations remain supported: migrated verdicts become raw evidence
without intended values. Historical observations without a semantic fingerprint
remain stale until checked again. Interrupted jobs remain incomplete after restart;
schedules resume without catch-up floods.

Scanner resolvers are separate from NetInfra DHCP options. `dns_servers` is the
global list; `subnet_dns_servers` maps canonical IPv4 CIDRs to resolver lists.
The most-specific matching override wins; an empty selected override falls back
to the global list. With neither configured, use the server resolver. DNS queries
are absolute and do not use resolver search suffixes. The Options page accepts
resolver overrides as a JSON object; the configuration file uses YAML mappings.

Administrator-only `/options`, `/audit`, and `/schedules` pages enforce permissions
server-side. Editors can launch and cancel manual scans. Secrets are omitted from
settings HTML and rejected on settings POSTs. Sensitive OIDC/session/proxy/path
fields are restart-only; edit the protected configuration file rather than trying
to switch them live. Redacted values in other fields are also read-only, so masks
cannot accidentally overwrite real configuration. Accepted settings are validated
and atomically saved with mode `0600`. `scan_concurrency` (128), `scan_start_rate`
(100 starts/second), and `manual_scan_confirmation_threshold` (4,096 targets)
are configurable.

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

Tests use temporary files/databases and simulated probes/provider responses. The
full suite passes **654 tests** with one Starlette/httpx TestClient deprecation
warning. Coverage includes target boundaries and large streamed ranges, rate and
concurrency limits, confirmation, cancellation/partial evidence, compact coverage,
interval/calendar scheduling and DST, freshness boundaries and schedule scope,
role/CSRF enforcement, plus earlier host, security, identity, inventory,
lifecycle, and persistence behavior. A temporary Uvicorn/browser smoke rendered
search results and freshness text; a separate temporary-app smoke rendered
discovery/DHCP context and editor proposal review without changing YAML. No live
probe or external identity provider was contacted. Docker was unavailable, so
Compose and container build execution remain unverified.
