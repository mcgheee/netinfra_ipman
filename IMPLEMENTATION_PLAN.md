# NetInfra IPAM v1 implementation plan

This plan implements [the approved design](DESIGN.md). Phases 1–3 are implemented;
phases 4–6 remain pending. Design policies and initial operational defaults are
approved; environment-specific values are supplied at deployment time.

## 1. Application and persistence foundation

- Separate application construction/lifecycle, configuration, NetInfra access,
  persistence, scanning, authentication, and routes. Remove import-time file
  creation and administrator provisioning.
- Keep Python/FastAPI, Jinja2, HTMX, and round-trip YAML handling.
- Introduce validated settings and SQLite schema initialization/versioning for
  schedules, jobs, and latest observations. Remove the Redis requirement and
  silent process-memory fallback.
- Run one application worker with one background runner. Persist job state and
  mark interrupted work incomplete on startup.
- Keep NetInfra authoritative; do not migrate intended network configuration
  into SQLite. Runtime storage remains separate and local.

Acceptance: startup has explicit, testable initialization; restart retains
schedules and latest observations; interrupted jobs are clearly identified.

Delivered: explicit `create_app()`/FastAPI lifespan, validated settings, SQLite
schema version 1, durable observations/schedule definitions/job summaries, and
interrupted-job recovery. Redis and web-startup administrator provisioning are
removed. One tracked runner streams bounded probes and awaits cleanup on shutdown.
Schedule execution and the complete scan contract remain phase 5; web routes and
inventory behavior not covered by this phase retain their documented starter gaps.

Phase-1 verification: 82 tests passed using temporary storage and simulated probes. A standalone
runner/reopen smoke retained observations and a disabled schedule and recovered a
running job as interrupted. An isolated Uvicorn/browser smoke rendered the page
without Redis or bootstrap-credential banners. No live network scan was used.

## 2. Inventory compatibility and reconciliation

- Include IPv4 A/default-A and `no_dns` assignments with or without MACs.
- Group records by IP; prefer MAC-bearing definitions, retain consistent names,
  and show conflicting MACs without selecting an arbitrary definition.
- Implement agreed DNS-owner precedence, absolute-name handling, and NetInfra
  tokens. Non-A records other than `no_dns` remain editable but are not scanned.
- Aggregate expected A addresses by DNS name using the authority rules and
  compare the full answer set exactly; missing or extra addresses are mismatches.
- Add visible structural/semantic diagnostics and an outliers view for IPs
  outside declared subnets. Preserve data rather than silently filtering it away.
- Represent observations separately from expected configuration and retain the
  file revision used to interpret a scan. Distinguish confirmed mismatch from
  unavailable evidence and mark affected observations stale after edits.

Acceptance: fixtures from the upstream example and focused cases cover optional
MACs, shared IPs, precedence, conflicts, aliases, `no_dns`, absolute DNS names,
custom fields, and out-of-subnet assignments.

Delivered: grouped optional-MAC inventory; deterministic shared-IP authority and
conflicts; agreed DNS precedence, absolute names, and tokens; complete expected
A-answer sets; structural/semantic diagnostics; outliers and full read-only host
details. Known-IP checks and full subnet scans use a single revision-bound
snapshot and central runner, persisting raw evidence independently from expected
configuration. Semantic fingerprints stale affected observations without
invalidating unrelated edits. Scanner resolver overrides use most-specific subnet,
global, then server precedence and never DHCP options. SQLite schema 2 migrates
phase-1 verdicts to historical raw evidence. Basic bounded address/outlier
pagination was brought forward to avoid unbounded rendering during this phase.

Verified: 191 tests pass. An attributed upstream fixture covers optional MAC,
shared addresses, custom/non-IP records, and outliers. An isolated running-app
browser smoke exercised the visible evidence states, complete retained host
properties, refresh/full checks, scope/authentication guards, selective staleness,
`/0` page boundaries, and restart/schema-upgrade persistence. All probes were
simulated; no live network was scanned. Security, reviewed writes, remaining
scan/schedule controls, and full web acceptance remain phases 3–6.

## 3. Secure access before exposing mutations

- Implement OIDC with configurable group/role mapping to viewer, editor, and
  administrator. Keep emergency local administrator provisioning in the CLI.
- Replace the unsigned username cookie with verified, expiring sessions. Add
  CSRF protection and server-side authorization to every mutation/probe route.
- Add `allow_anonymous_viewing`, default false. When enabled, grant viewer
  permissions only; authentication remains required for scans and edits.
- Restrict schedule/settings/audit access to administrators. Redact secrets and
  validate trusted proxy handling.
- Audit authentication, edits, scan actions, and settings changes, with bounded
  retention independent of observation history.

Acceptance: test both anonymous-view settings and every role, including forged
or expired sessions, direct requests to protected routes, CSRF, OIDC failure,
and emergency-admin recovery. Public pages never expose credentials.

Delivered: durable opaque sessions with absolute expiry, revocation, and
browser-bound CSRF; viewer/editor/administrator dependencies on every existing
route; anonymous viewing disabled by default and strictly read-only when enabled.
Generic OIDC uses discovery, authorization code with PKCE S256, one-use
browser-bound state, nonce, RS256/JWKS and identity/time/audience validation.
Explicit group/role mappings fail closed for unmapped users. Emergency local
provisioning/recovery remains CLI-only, forces password change, rotates credential
versions, and revokes older local sessions.

Settings and audit pages are administrator-only. Secrets are omitted/redacted,
protected settings require file edits/restart, and settings save atomically with
private permissions. SQLite schema 3 adds expiring security state. Trusted proxy
chains are validated against explicit peer networks; deployment commands disable
Uvicorn proxy rewriting and access logs. Audit files rotate independently with
private permissions and bounded retention; authentication, permission failures,
mutations, probes, and settings outcomes are audited without credential bodies.

Verified: 396 tests pass, including roles, both anonymous modes, direct-route
authorization, CSRF, forged/expired/revoked sessions, OIDC signature/claim/provider
failures, recovery, proxy spoofing, redaction/rotation, and private settings writes.
A running browser smoke completed signed OIDC flows against a temporary local
provider for all three roles, exercised editor checks and protected admin pages,
enabled read-only anonymous access, and verified CLI recovery, mandatory password
change, and revocation. Probes were simulated; no external IdP or live network
scan was used. Host-write safety and remaining scan/schedule/UI work remain
phases 4–6; full production readiness is not claimed.


## 4. Host editing, import, and safe file writes

- Add host create/read/update/delete interfaces, common-field forms, and an
  advanced YAML editor that exposes the complete host entry.
- Add bulk creation from pasted/uploaded YAML or an editable starter. Accept a
  list or `Hosts:` wrapper. Reject the complete batch if a host Name already
  exists or repeats within the batch. Existing hosts must be changed through the
  editor; do not implicitly merge or overwrite them.
- Provide shared preview/apply operations containing a source content revision
  and bound proposed change. Display the full-file diff and validation findings.
- Block saves with malformed YAML, invalid field values, conflicting MAC
  assignments, or eligible targets outside declared subnets. Validate against
  other hosts to catch cross-host conflicts; do not offer a warning override.
  Preserve legitimate shared-IP definitions and distinguish configuration
  validation from live network discrepancies.
- Serialize writes, recheck the revision immediately before saving, create a
  backup, and atomically replace the file. Reject stale previews and require a
  fresh review. Preserve comments, custom fields, and unrelated sections.
- Keep backups outside the Git checkout. Validate branch/checkout state before
  optional local commits. Report file-save and Git-commit outcomes separately
  and provide a commit retry path. Do not implement automatic push.

Acceptance: test single and bulk edits, deletions, malformed input, semantic
diagnostics, stale/tampered previews, concurrent app edits, external file changes,
preservation, backups, disk/write failures, and Git failures. A rejected batch
does not partially modify the file.
Verify that semantic conflicts block writes until resolved, including direct
apply requests that bypass the preview UI. Valid shared-IP definitions and live
network mismatches alone must not cause validation failures.

## 5. Scans, schedules, and runtime limits

- Introduce scan requests with explicit target scope and mode: all declared
  subnets, one subnet, an IP range, or one IP; full, known-only, or discovery-only.
- Require targets to be within declared subnets and deduplicate overlapping
  ranges. Resolve scheduled targets against the current file at dispatch time.
- Stream targets through bounded queues and probe concurrency/rate limits. Do
  not allocate one task per address. Remove the fixed `/16` rejection and support
  `/31` and `/32` semantics correctly.
- Default to 128 concurrent IP checks and at most 100 check starts per second.
  Require confirmation for manual scans above 4,096 target addresses; schedules
  are authorized when enabled. Make these defaults configurable without imposing
  a hard CIDR-size limit.
- Implement progress, cancellation, partial outcomes, and failure reporting with
  one active job. Store latest observations sparsely and track discovery coverage
  without creating a row for every silent, undocumented address.
- Check ping, forward DNS for applicable records, and MAC where observable.
  Require exact expected A-answer sets. Use per-subnet scanner resolver overrides,
  then global scanner resolvers, then the server's resolver. Keep this separate
  from DHCP DNS options. Never infer availability for allocation from silence
  alone or auto-add discovered hosts.
- Add disabled-by-default interval and timezone-aware daily/weekly schedules,
  including independent known-IP and discovery schedules.
- Coalesce duplicate schedule triggers, avoid downtime catch-up floods, and
  leave interrupted runs visibly incomplete. Skip nonexistent local DST times
  and run repeated local calendar times once.

Acceptance: simulated probes exercise timeout, resolver failure, mismatches,
unavailable MACs, undocumented responders, cancellation, overlapping targets,
scheduling, DST, and restart interruption. Tests demonstrate bounded generation
for very large CIDRs without actually scanning those networks.
DNS tests include multiple expected A addresses, missing and extra answers,
resolver failures, and all three levels of resolver selection. Import tests
verify that name collisions leave the entire file unchanged.
Use a controlled clock to verify concurrency and start-rate bounds. Confirm
that 4,096-target manual scans need no large-scan confirmation and 4,097-target
scans do, including enforcement on direct requests.

## 6. Web workflow and deployment

- Add paginated subnet/address views, search, discrepancy filters, host details,
  and an outliers view. Update scan progress and results with HTMX.
- Show expected/observed values, timestamps, textual reasons, and state colors.
  Expose undocumented responders and DHCP-pool context without claiming verified
  leases. Provide an explicit review flow to create a host from a discovery.
- Apply freshness defaults: twice the applicable schedule interval, otherwise
  24 hours for manual-only checks, with an administrator override.
- Default to latest observations, the last 100 completed job summaries, 20 file
  backups, and audit rotation at 10 MiB with five rotated files plus the active
  file. Keep retention settings configurable.
- Package a single-server deployment behind a TLS proxy with persistent local
  SQLite storage. Document network permissions, trusted proxies, OIDC setup,
  file/Git access, backup recovery, and coordination with external file editors.
- Update the README to distinguish supported behavior from future work. Remove
  misleading claims about unimplemented integrations.

Acceptance: a controlled end-to-end demonstration covers login/anonymous viewing,
role restrictions, host editing/import, reviewed saves, all scan scopes, split
schedules, visible mismatches, discovery, cancellation, and restart recovery.
The interface remains responsive during large streamed scans.

## Verification and rollout

The test dependencies are now installed in the development virtual environment,
and the phase-3 suite passes. The original inspection had no pytest baseline.
Add focused tests with each subsystem and use mocked network probes by default.
Use an isolated sample NetInfra file and controlled test networks for integration checks.

Deliver in the order above. Do not deploy the remaining direct-write paths as
the finished application or restore legacy unsigned-cookie authentication. Validate against a copy of a
representative NetInfra file before connecting the production file and enabling
schedules. Configure OIDC, DNS views, persistent storage, and scan rates for the
actual deployment; keep credentials out of source control.
