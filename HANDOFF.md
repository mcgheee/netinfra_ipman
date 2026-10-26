# Implementation handoff

## Delivery state

Phases 1–4 are implemented. Phase 5 is next. This is **not production-ready v1**:
host writes now use full reviewed validation, revision-bound previews, external
backups, and atomic replacement; complete scan controls and scheduling remain
unfinished. Validate deployment against a disposable NetInfra copy.

Authoritative behavior and acceptance criteria:
- [DESIGN.md](DESIGN.md)
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), section 4
- [README.md](README.md), deployment, migration, OIDC, and recovery instructions

## What phase 3 delivered

| Area | Implementation |
| --- | --- |
| Sessions and roles | `netinfra_ipman/security.py`: opaque random cookies, hashed durable sessions, absolute expiry, revocation, CSRF, and viewer/editor/administrator dependencies. |
| Emergency access | CLI-only provisioning/recovery, atomic private credential writes, forced first-login password change, lockout, PBKDF2-SHA256 at 600,000 rounds, and credential-version invalidation. |
| OIDC | `netinfra_ipman/oidc.py`: discovery, code flow with PKCE S256, one-use browser-bound state, nonce, RS256/JWKS verification, issuer/audience/time checks, and explicit claim-to-role mappings. Uses maintained `joserfc` verification plus Authlib OIDC claims validation. |
| Persistence | `netinfra_ipman/persistence.py`: SQLite schema 3 adds expiring sessions and OIDC transactions while retaining previous runtime-state migrations. |
| Settings | `netinfra_ipman/config.py`: validated generic OIDC/proxy/security fields, secret-safe public settings, protected path checks, atomic mode-`0600` configuration writes. |
| Audit and proxies | `netinfra_ipman/audit.py`: private rotating audit files, redaction, bounded active-file history, and explicit trusted-peer forwarding-chain validation. |
| Web integration | `netinfra_ipman/main.py` and templates: server-side role gates, CSRF forms, OIDC/local login, logout/recovery behavior, administrator settings/audit pages, safe request outcomes and response headers. |
| Deployment | `Containerfile` and CLI disable Uvicorn proxy rewriting and access logs. Stylesheet URLs are path-only so disabling proxy rewriting does not produce HTTP asset URLs behind TLS. |

### Invariants to preserve

- `create_app()` has no provisioning or import-time file/network side effects.
  FastAPI lifespan owns storage, runner, OIDC client, and audit cleanup.
- `request.app.state.services` owns configuration, store, scanner, security, OIDC,
  and audit services. SQLite calls and `SecurityManager` methods remain on the
  event loop; local password/file APIs run through `asyncio.to_thread` in routes.
- Use `Principal.subject` for audited identity, not a submitted username or an
  unsigned cookie. Never accept the old `ipman_user` cookie.
- `require_viewer` permits anonymous access only when explicitly configured.
  `require_editor` protects host mutations and probes; `require_admin` protects
  settings/audit and must protect future schedule administration.
- `require_user` intentionally permits forced-password-change identities for
  password/logout operations only. Do not use it alone for ordinary application
  viewing or mutations.
- The router applies `verify_csrf` to unsafe methods. New forms need hidden
  `csrf_token` inputs; API callers can use `X-CSRF-Token`. The OIDC callback uses
  its bound one-use state instead. Preauth sessions grant no permissions.
- Session hashes, local credential versions, and OIDC policy fingerprints enforce
  revocation. Password changes/recovery invalidate older local sessions; relevant
  OIDC configuration changes invalidate existing OIDC sessions after restart.
- Do not persist provider access/ID tokens or log request bodies, cookies, codes,
  passwords, hashes, or full YAML snapshots. Host-change audit currently records
  content hashes instead of complete documents.
- Audit middleware captures the validated client address **before** dispatch:
  mounted ASGI applications can replace `scope['app']`. A regression test covers
  this; do not look up the parent services through `request.app` after dispatch.
- Live settings can replace the audit logger. Lifespan cleanup closes the current
  logger, not only the original instance.
- Preserve phase-2 grouping, exact DNS-answer sets, raw evidence, and semantic
  staleness. Unrelated comments/custom-field changes must not stale observations.

## Verification performed

```bash
.venv/bin/python -m pytest -q
```

Result: **396 passed**, with one Starlette/httpx TestClient deprecation warning.
The new authentication code does not use deprecated `authlib.jose` APIs.

Security coverage is in `tests/test_access.py`, `tests/test_security.py`,
`tests/test_security_persistence.py`, `tests/test_oidc.py`, `tests/test_audit.py`,
and the updated configuration/lifecycle tests. It covers roles, both anonymous
settings, direct-route authorization, CSRF, forged/expired/revoked sessions,
OIDC signature/claim/provider failures, state binding/replay, CLI recovery,
private configuration writes/failure preservation, proxy spoofing, redaction,
and rotation. Earlier inventory/runner/persistence coverage remains passing.

A running Uvicorn/browser smoke used a temporary local identity-provider simulator
with real RSA-signed tokens and actual discovery/token/JWKS exchanges. It verified:
- Viewer denial of scans/settings and editor checks without admin access.
- Administrator settings/audit pages and absence of the client secret in HTML.
- Anonymous viewing opt-in while anonymous probes remained unauthorized.
- Actual CLI replacement, mandatory password change, and revocation after another
  CLI recovery.
- Credential-free audit output, private settings roundtrip, and rendered stylesheet
  path behavior.

Probes were simulated against an explicitly designated `/32` fixture. No external
IdP or live network was scanned. Temporary provider scripts, credentials, data,
SQLite files, and verifier services were removed; no simulator ships in the app.

## Deployment and migration notes

- Anonymous viewing defaults off. Secure cookies default on: use HTTPS in real
  deployments. `session_cookie_secure: false` is only for loopback development.
- Configure the real OIDC issuer, client, exact callback URI, secret where needed,
  and group/role mappings. Unmapped identities are denied; highest mapped role
  wins. RS256 is the supported ID-token signing algorithm.
- Remove retired `keycloak_*`, `duo_*`, `tls_enabled`, `reverse_proxy`, and the
  previously inactive `rate_limit_per_minute`. They now produce migration errors.
- Configure only actual proxy peers in `trusted_proxies`; keep Uvicorn
  `--no-proxy-headers --no-access-log`. Proxy logs must omit authentication query
  values, cookies, authorization headers, and bodies. Apply request limits at the
  proxy; application local-account lockout is separate.
- Protect configuration/credential/database/log parent directories. Schema upgrades
  are automatic, transactional, and reject unsupported newer versions. One app
  worker and local persistent SQLite storage remain required.
- `netinfra-ipman-init --replace` is explicit emergency recovery. OIDC logout
  revokes the app session, not the provider session; provider membership changes
  take effect on the next login, with no retained refresh token.

## What phase 4 delivered

| Area | Implementation |
| --- | --- |
| Host workflows | `main.py` and templates provide paginated read details, editor-gated create/update/delete, common-field forms, complete advanced YAML, and pasted/uploaded list-or-`Hosts:` imports. Name collisions reject the entire batch. |
| Shared transactions | `hostwrites.py` binds opaque actor-specific tokens to immutable proposed bytes and source revision. Preview/apply validates the complete document; altered/direct apply and stale previews are rejected. Application writes serialize under one lock. |
| Validation and preservation | `netinfra.py` keeps round-trip comments, preamble, quotes, ordering, custom/nested fields, and unrelated sections. Structure, known field values, duplicate names, MAC conflicts, and out-of-subnet eligible assignments block saves; valid shared IPs and live discrepancies do not. |
| File durability | Backups default to `./ipman-backups` outside a discovered Git checkout and retain 20 files. The service rechecks the source immediately before same-directory atomic replacement, preserves file mode, fsyncs, and reports independent file/Git outcomes. |
| Git cutover | `gitops.py` validates checkout root, configured branch and cleanliness without switching branches, commits only the intended source, never pushes, and supports guarded commit retry. Retired `git_push`/`git_remote` configuration is rejected with migration guidance. |
| Coverage | `tests/test_hostwrites.py`, `tests/test_gitops.py`, `tests/test_host_routes.py`, configuration, NetInfra and access tests cover the phase contract. A rendered Uvicorn/browser smoke verified the host list; all host mutations used temporary-file integration tests. |

### Write coordination limit

The process-local lock serializes app writes only. External programs that ignore
the lock can still write concurrently; source revision checks detect changes up
to the atomic replace but cannot lock unrelated editors. Coordinate external
writers operationally. Backups are stored outside the checkout, default to
20 retained files, and can be configured with `backup_dir` and `backup_retention`.

### Verification performed

```bash
.venv/bin/python -m pytest -q
```

Result: **501 passed**, with one Starlette/httpx TestClient deprecation warning.
The host route tests covered create, update, delete, bulk import, whole-batch
collision rejection, stale/direct/replayed apply rejection, authorization, CSRF,
and external backups. A real Uvicorn/browser smoke rendered the paginated host
list against isolated temporary configuration and data. No network probes ran.

## Next: phase 5

Implement all section-5 scan and schedule requirements:

1. Explicit target scope (declared network, subnet, range, or IP) and mode (full,
   known-only, discovery-only), with declared-subnet enforcement and deduplication.
2. Stream all IPv4 CIDR sizes through bounded queues; remove the web `/16` cutoff,
   apply configurable 128-concurrency/100-starts-per-second defaults, and require
   manual confirmation above 4,096 targets.
3. Persist sparse undocumented observations and compact discovery coverage;
   implement progress, cancellation, partial/failure outcomes, and restart behavior.
4. Add disabled-by-default interval and timezone-aware daily/weekly schedules,
   separate known-IP/discovery schedules, administrator management, coalescing,
   no downtime catch-up, and DST skip/repeat-once semantics.
5. Keep scan scope resolution against current NetInfra at dispatch and enforce
   editor/admin permissions plus CSRF on new endpoints.

Retain simulated probes, bounded large-CIDR tests, controlled-clock rate and DST
tests, restart tests, and rendered scope/progress/cancellation checks.

## Remaining later-phase work

Phase 6 still includes search/filtering/progressive updates, age-based freshness,
DHCP context and discovery-to-host review, plus complete end-to-end deployment/UI
acceptance. Do not claim v1 production readiness until the full phase-6 acceptance
contract is complete.

