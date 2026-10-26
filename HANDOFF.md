# Implementation handoff

## Delivery state

Phases 1–3 are implemented. Phase 4 is next. This is **not production-ready v1**:
verified access controls now protect the existing routes, but host write-back
still has unsafe starter semantics. Use a disposable NetInfra copy until the
reviewed-write phase is complete.

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

## Next: phase 4

Implement the whole section-4 acceptance contract, not only a safer append route:

1. Host create/read/update/delete, common-field forms, and complete advanced YAML
   editing. Subnets and non-host sections remain read-only.
2. Bulk creation from pasted/uploaded YAML or a starter, accepting a host list or
   `Hosts:` wrapper. Reject the entire batch on existing or within-batch Name
   collisions; never merge/overwrite implicitly.
3. One shared preview/apply service. Bind the source content revision and exact
   proposed bytes/change to the reviewed preview. Present a full-file diff and
   validation findings; reject stale or altered/direct-apply attempts.
4. Validate the complete proposal against the inventory: structure, known field
   values, shared-IP MAC conflicts, out-of-subnet eligible targets, and cross-host
   consistency. No warning bypass. Consistent shared IPs and live network
   discrepancies alone must not block saves. Current viewing diagnostics are not
   yet a complete save-validation contract.
5. Serialize app writes, recheck the revision immediately before saving, create
   backups outside the Git checkout, then atomically replace the reviewed file.
   Preserve round-trip comments, explicit document preambles, quotes, ordering,
   custom/nested fields, and non-IP records. Document the limit of coordination
   with external writers that ignore app locks.
6. Validate configured Git branch/checkout without silently switching branches.
   Separate file-save and optional local-commit outcomes, with a commit retry path.
   No automatic push. Remove obsolete write paths and configuration on cutover.

### Existing hazards to replace

- `main.add_preview` builds a diff but binds nothing to a subsequent request.
- `main.add_commit` reloads the file and accepts submitted fields again; it has no
  stale-preview check, serialized write, or full semantic save validation.
- It backs up beside the source and calls `save_netinfra` directly; the serializer
  itself is not a safe host-write transaction.
- `gitops.ensure_clean_checkout` currently runs `git checkout` before checking
  cleanliness. `gitops.commit_changes` still supports the legacy `git_push` flag.
  Both are pending the phase-4 local-only Git cutover.

Useful starting points: `netinfra.py` for round-trip loading/serialization and
`build_inventory`/`load_inventory`; `main.py` for the append handlers; `gitops.py`
for legacy Git behavior; the form templates; and `tests/test_netinfra.py` for
preservation and upstream fixtures. Keep filesystem/probe/persistence operations
independently testable rather than moving all write logic into handlers.

Keep regression coverage for stale/tampered previews, whole-batch rejection,
concurrent app edits, external changes, backups, write/replace failures,
preservation, semantic conflicts, and file-saved/Git-failed outcomes. Keep the
phase-3 authorization/CSRF checks on every new endpoint. Run the changed paths
against temporary files and perform a rendered review/apply smoke before delivery.

## Remaining later-phase work

Phases 5–6 still include complete scan scope/mode controls, removal of the full-scan
web `/16` cutoff and prefix-based confirmation policy, start-rate bounds,
scheduling/DST/coalescing, compact discovery coverage, age-based freshness,
search/filtering/progressive updates, DHCP context, and complete deployment/UI
acceptance. Do not describe these as implemented because the foundational runner
or identity interfaces exist.
