# Project guidance for coding agents

This file applies to the entire repository.

## Read first

- [DESIGN.md](DESIGN.md) contains the approved product behavior and defaults.
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) contains delivery order and
  acceptance checks. Follow it when implementing the application, within the
  scope of the current user request.
- [README.md](README.md) describes the starter. Verify its claims against code;
  some features are incomplete or placeholders.
- Inspect the working tree before editing. Preserve unrelated changes, including
  untracked design documents. Do not commit or push unless requested.

The user's current instructions take precedence over these project documents.
Do not ask the user to reconfirm already approved design choices. Surface genuine
contradictions or new scope decisions instead of silently changing the design.

## Project shape

The application uses Python 3.11+, FastAPI, Jinja2, HTMX, and `ruamel.yaml`.
The approved architecture uses one application worker, one central scan runner,
and SQLite on local persistent storage. Redis is still present in the starter
and is scheduled for replacement; it is not an approved runtime requirement.

Current code locations:

| Area | Location |
| --- | --- |
| Web routes and startup | `netinfra_ipman/main.py` |
| YAML interpretation and writing | `netinfra_ipman/netinfra.py` |
| Checks and scan jobs | `netinfra_ipman/checks.py`, `netinfra_ipman/scanner.py` |
| Models and settings | `netinfra_ipman/models.py`, `netinfra_ipman/config.py` |
| Authentication and audit | `netinfra_ipman/security.py`, `netinfra_ipman/audit.py` |
| Existing cache and Git support | `netinfra_ipman/cache.py`, `netinfra_ipman/gitops.py` |
| UI | `netinfra_ipman/templates/`, `netinfra_ipman/static/` |
| Tests and example input | `tests/`, `examples/NetInfra.yml` |

These are starting locations, not a requirement to preserve the current module
boundaries. Keep web handlers, file operations, probes, and persistence testable
independently. Avoid import-time file creation, network access, and provisioning.

## Behavior to preserve

- `NetInfra.yml` is authoritative for intended configuration. Observations,
  schedules, app settings, and secrets belong outside it.
- V1 edits hosts and all their properties. Subnets and other top-level sections
  are read-only. Preserve custom fields, non-IP records, comments, and ordering.
- Inventory includes valid IPv4 targets with A, omitted, or `no_dns` record type.
  MAC is optional. Other record types remain editable but are not scanned.
- Group by IP and prefer MAC-bearing definitions. Consistent shared-IP records
  are valid; conflicting MAC definitions must not be resolved arbitrarily.
- Use `Source` then `AltHostName` then host `Name` for DNS identity. Follow the
  absolute-name and token rules in the design. Skip DNS checks for `no_dns`.
- Compare complete expected A-answer sets exactly. Resolver precedence is
  per-subnet scanner override, global scanner setting, then server resolver.
  Do not infer scanner settings from DHCP DNS options.
- Keep intended configuration and live observations distinct. A timeout or
  unavailable MAC is not a confirmed mismatch; silence does not mean an IP is free.
- Scan only declared subnets or subsets of them. Support all valid IPv4 CIDR
  sizes with streamed targets, bounded queues, sparse storage, and pagination.
  Never allocate one task or UI row per address for an entire large network.
- Use the configurable defaults in `DESIGN.md`; do not retain the starter's
  fixed `/16` restriction or introduce another hard CIDR-size cutoff.

## Writes and access control

- All host changes require validation and a full-file diff preview bound to the
  source revision and exact proposed change. Reject stale or altered previews.
- Block invalid field values and semantic conflicts on save. Do not add a
  warning bypass. Live network discrepancies alone do not invalidate an edit.
- Reject a whole bulk import on host-name collisions; never silently merge,
  overwrite, or partially apply the batch.
- Serialize application writes, recheck revisions, back up, and replace files
  atomically. Keep backups outside the Git checkout. Report file-save and optional
  local Git-commit outcomes separately. Do not implement automatic Git push.
- Enforce viewer/editor/administrator permissions server-side. Optional anonymous
  access grants viewing only; probes and mutations always require authentication.
- Use verified sessions and CSRF protection. Never preserve the starter's unsigned
  username cookie as an authorization mechanism or expose bootstrap credentials.
- Keep secrets out of pages, logs, fixtures, and source control. Use temporary
  files and mocked identity-provider responses for tests.

## Development and verification

Use an existing suitable virtual environment, or create one:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

Run focused tests while developing, then the relevant broader suite before
delivery. Report unavailable dependencies or failing checks accurately; do not
claim the historical starter tests establish a passing baseline.

- Use pytest temporary directories for YAML, SQLite, backups, config, and logs.
  The starter initializes services and creates files when importing `main.py`;
  isolate its configuration before import until lifecycle refactoring removes
  those side effects. Never point test writes at a production NetInfra file.
- Mock ping, DNS, MAC lookup, OIDC, and Git failure paths. Live integration checks
  use explicitly designated test networks. Do not scan networks as part of routine
  tests or use arbitrary public/private ranges as real probe targets.
- Test shared-IP authority, DNS answer sets, preservation, validation, stale
  previews, concurrent edits, authorization, cancellation, scheduling, and restart
  behavior when changing those features.
- Exercise large CIDRs through bounded iteration and simulated probes, not full
  enumeration. Use controlled clocks for rate-limit and scheduler tests.
- For UI changes, check rendered behavior as well as backend responses. Present
  textual states and reasons alongside colors.
- Keep changes focused and use type annotations. Add dependencies or abstractions
  only when the implementation needs them. Do not impose new formatting tools
  solely for an unrelated change.

## Documentation and handoff

Keep the design, implementation plan, and README consistent with delivered work.
Clearly distinguish approved behavior from implemented behavior. Documentation-only
changes need document/link checks, not a network scan or new application tests.

In the final response, state what changed, what was verified, and any remaining
limitation. Reference the relevant files. Deployment-specific OIDC values, paths,
trusted proxies, and resolver addresses can be supplied at deployment time; they
do not block implementation against configurable interfaces.
