# NetInfra IP Manager

A Python/FastAPI application for managing host configuration in `NetInfra.yml`
and comparing intended configuration with network observations. The
[approved design](DESIGN.md) defines v1 behavior; the
[implementation plan](IMPLEMENTATION_PLAN.md) tracks delivery order.

## Implementation status

Phases 1–2 (foundation and inventory reconciliation) are implemented:

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

**This is not production-ready v1.** Existing unsigned-cookie authentication,
missing roles/CSRF/OIDC, direct file-write paths, and public settings remain
starter limitations. Keep this application isolated from untrusted users and use
only a disposable NetInfra copy until the security and reviewed-write phases land.

Full host editing/import, reviewed atomic writes, complete scan scope/mode controls,
start-rate limits, scheduling execution, age-based freshness, discovery coverage,
filters, and progressive updates remain pending. The starter full-scan web route
still uses prefix-based limits, including its default `/16` restriction; known-only
refresh and address browsing have no CIDR-size cutoff. Stored schedules have no
execution/UI yet and default to disabled. Latest undocumented ping responses are
visible, but DHCP-pool context and discovery-to-host review are not implemented.
Legacy SSO/Duo configuration fields are not integrations. Git behavior remains
starter code, not the approved safe local-commit flow.

## Development quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp ipman-config.example.yml ipman-config.yml
netinfra-ipman-init
uvicorn netinfra_ipman.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Open <http://127.0.0.1:8000>. The example configuration points at
`examples/NetInfra.yml`; copy it to a disposable location before exercising writes.
The initializer prompts for an emergency local administrator password. It honors
`IPMAN_CONFIG` just like the application. Web startup never generates credentials.

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

Schema version 2 upgrades phase-1 observations in a transaction: cached status
verdicts and ping results become latest raw evidence per IP, with intended values
and old verdicts removed. Historical evidence without a semantic fingerprint is
stale until checked again; it is not silently treated as a current match.

Scanner resolvers are separate from NetInfra DHCP options. `dns_servers` is the
global list; `subnet_dns_servers` maps canonical IPv4 CIDRs to resolver lists.
The most-specific matching override wins; an empty selected override falls back
to the global list. With neither configured, use the server resolver. DNS queries
are absolute and do not use resolver search suffixes. The Options page accepts
resolver overrides as a JSON object; the configuration file uses YAML mappings.

Changing `sqlite_path` or `config_path` requires editing the configuration file and
restarting; the Options route rejects live switches. Other accepted settings are
validated before being saved and activated. Do not expose the starter Options
page: secret redaction and administrator-only access are pending phase 3.

Run exactly one application worker against a runtime database. Multi-worker or
multi-server coordination is unsupported. SQLite contains runtime state only;
`NetInfra.yml` remains authoritative for intended configuration. Recovery marks
interrupted jobs incomplete rather than automatically replaying them.

## Verification

```bash
.venv/bin/python -m pytest -q
```

Tests use temporary files/databases and simulated probes. They cover lifecycle,
settings, SQLite upgrades/recovery, sparse and bounded scans, shared-IP authority,
upstream compatibility/preservation, exact DNS sets, resolver selection,
incomplete evidence, semantic staleness, and scan/refresh cancellation and busy
handling. The phase-2 suite passes 191 tests. An isolated Uvicorn/browser smoke
exercised refresh/full checks, retained records, conflict/incomplete/mismatch
states, outliers, relevant/unrelated file edits, `/0` pagination, and restart.
No live network was scanned. Production deployment guidance and full v1
acceptance remain in later phases.
