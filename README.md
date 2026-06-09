# NetInfra IP Manager

NetInfra IP Manager is a FastAPI web application for browsing, checking, scanning, and safely updating a local `NetInfra.yml` file that follows the structure used by the [NICS-UTK NetInfra monorepo](https://github.com/NICS-UTK/netinfra_monorepo).

## Features

- Reads a configurable local `NetInfra.yml` path, defaulting to `./NetInfra.yml`.
- Treats a managed server as a `Hosts[*].Records[*]` item with a valid IPv4 `Target` and a `MAC`.
- Builds expected FQDNs from `Record.Source`, `Record.HostName`, or `Host.Name` plus `Record.ZoneName`, with trailing-dot and case normalization.
- Shows one tab per `subnets[*].cidr` and one IP row per host address in that subnet.
- Displays hostname, FQDN, IP, MAC, comment, last check time, and a combined green/yellow/red status dot.
- Stores separate ping, DNS, MAC lookup, and MAC comparison results so tooltips can explain failures.
- Uses `ping3`, `dnspython`, and `getmac` for checks.
- Caches status in Redis, falling back to process memory if Redis is unavailable.
- Runs bounded-concurrency subnet scans as background jobs and marks unmanaged non-responding IPs as neutral.
- Allows authenticated users to preview diffs and append discovered hosts to `Hosts` using `ruamel.yaml` round-trip writing.
- Creates timestamped backups before write-back and supports optional git commit/push mode with a clean-checkout requirement.
- Provides local admin login, first-login password change, configurable Keycloak/Duo fields, and audit logging to file/syslog.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
cp ipman-config.example.yml ipman-config.yml
netinfra-ipman-init
uvicorn netinfra_ipman.main:app --reload
```

Open <http://localhost:8000>. Unauthenticated users can view; login is required for scans and write-back changes.

## Configuration

Configuration is stored in a local YAML file, defaulting to `./ipman-config.yml`, and is intentionally not intended to be tracked by git. Set `IPMAN_CONFIG=/path/to/ipman-config.yml` to choose a different file. Runtime options can also be edited from the Options tab after login.

## Deployment

Use the provided Containerfile for podman, or run behind Caddy/another reverse proxy. TLS termination can be handled by the proxy; set `reverse_proxy: true` to trust `X-Forwarded-For` for audit source IPs.
