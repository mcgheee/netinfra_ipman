# NetInfra IP Manager

A Python/FastAPI application for managing host configuration in `NetInfra.yml`
and comparing intended configuration with network observations. The
[approved design](DESIGN.md) defines v1 behavior; the
[implementation plan](IMPLEMENTATION_PLAN.md) tracks delivery order.

## Implementation status

Phase 1 (application and persistence foundation) is implemented:

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
  ping observations are stored separately from job summaries. Silent undocumented
  addresses do not create observation rows. Completed job retention defaults to 100.
- Administrators are provisioned only through the CLI, never during web startup.

**This is not production-ready v1.** Existing unsigned-cookie authentication,
missing roles/CSRF/OIDC, direct file-write paths, and public settings remain
starter limitations. Keep this application isolated from untrusted users and use
only a disposable NetInfra copy until the security and reviewed-write phases land.

Inventory authority/DNS reconciliation, full host editing/import, scan modes and
rate limits, scheduling execution, freshness/coverage, and scalable paginated UI
are not implemented. The starter web scan route still uses prefix-based limits,
including its default `/16` restriction; the underlying runner is bounded, but
large address-table rendering is not. Stored schedules have no execution/UI yet
and default to disabled. Discovery observations are persisted but not yet merged
into the inventory table. Legacy SSO/Duo configuration fields are not integrations.
Git behavior also remains starter code, not the approved safe local-commit flow.

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

Tests use temporary files/databases and simulated probes. They cover settings
validation, side-effect-free import, isolated application lifecycles, persistence,
schema versioning, restart recovery, sparse observations, bounded target generation,
and scan failure/cancellation/shutdown. Do not run routine checks against a live
network or production NetInfra file. Production deployment guidance and full v1
acceptance remain in the later implementation phases.
