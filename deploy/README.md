# Single-server TLS deployment

This package runs **one application process/worker** on a Linux server using
Docker Engine and the Compose v2 plugin, with Caddy installed as a host service.
The server must have the intended routing and DNS view of the managed networks.
Use persistent **local** disk: SQLite on NFS/SMB/network volumes, multiple workers,
replicas, Redis, and automatic Git push are not supported. This is not a
high-availability or multi-routing-view deployment.

The commands below are operator instructions, not recorded validation results.
Run repository-relative commands from the repository root. Prerequisites are
Docker/Compose, Caddy v2, sudo, tar, and (for the recovery check) the sqlite3 CLI.
Use a maintained Docker/Caddy release. Pin reviewed base-image versions/digests
and dependencies under your own release policy; the supplied build is not a
reproducible lockfile or a claim of vulnerability scanning.

## Files, ownership, and build

The supplied Compose file uses Linux **host networking**, not a published Docker
port. Uvicorn binds `127.0.0.1:8000`; only Caddy exposes HTTPS. Do not override the
command to bind all interfaces, add workers, or turn Uvicorn proxy/access logging
back on. The image command explicitly sets `--workers 1 --no-proxy-headers
--no-access-log`. Docker Desktop and rootless networking/capability mappings are
not the supported baseline; adapt and validate them separately.

| Host directory | Container directory | Contents |
| --- | --- | --- |
| `/srv/ipman/config` | `/etc/ipman` | Private, writable application YAML and OIDC secret |
| `/srv/ipman/runtime` | `/var/lib/ipman/runtime` | SQLite, administrator credentials/lock, rotating audit logs |
| `/srv/ipman/inventory` | `/srv/netinfra` | NetInfra.yml, optionally the entire Git checkout |
| `/srv/ipman/backups` | `/var/backups/ipman` | Bounded pre-write inventory backups, outside checkout |

These directories are separate bind mounts, not disposable container layers.
Mount **directories**, not individual YAML/SQLite files: atomic replacement,
Git, locks, and SQLite sidecars need writable parent directories. Host mount
sources must already exist; Compose refuses to silently create missing sources.
Configuration is writable to support atomic administrator settings saves. Protect
all parent directories against untrusted writes. Do not mount your home directory,
Docker socket, SSH agents/keys, or other unrelated host paths.

```sh
sudo install -d -m 0750 -o root -g root /srv/ipman
sudo install -d -m 0700 -o 10001 -g 10001 \
  /srv/ipman/config /srv/ipman/runtime /srv/ipman/inventory /srv/ipman/backups
sudo install -m 0600 -o 10001 -g 10001 deploy/ipman-config.example.yml \
  /srv/ipman/config/ipman-config.yml
# Use this disposable source first, before importing production inventory:
sudo install -m 0600 -o 10001 -g 10001 examples/NetInfra.yml \
  /srv/ipman/inventory/NetInfra.yml
docker compose -f deploy/compose.yml build
```

Replace the sample inventory with your reviewed source before production. UID/GID
10001 must be able to read/write the inventory file **and its directory**; for Git
it must own/access the whole checkout and `.git`. The host `/srv/ipman` root-only
parent does not prevent access to bind-mounted children inside the container.
On SELinux hosts, assign appropriate private container labels to these four data
directories using your distribution policy; do not disable SELinux globally or
relabel arbitrary system trees. Adjust ownership if user namespaces remap UID
10001; the numeric ownership above assumes standard rootful Docker.

`IPMAN_CONFIG=/etc/ipman/ipman-config.yml` selects the protected configuration.
All paths in `deploy/ipman-config.example.yml` are **container paths**. The config
contains no deployed secrets. Edit the installed copy with `sudoedit`; preserve
owner 10001:10001 and mode 0600 afterward. Never commit that copy or place secrets
in Compose environment variables, image layers, shell arguments, or this repo.
Keep `session_cookie_secure: true` and anonymous viewing disabled unless you
intentionally authorize read-only public inventory. Runtime defaults retain
100 completed jobs, 20 inventory backups, and 10 MiB audit rotation with five
rotated files plus the active log. Inventory backups are not disaster recovery.

## TLS proxy and first login

Give the server a real DNS name and replace `ipman.example.com` in
`deploy/Caddyfile.example`. Point the name to this server. Permit inbound TCP
80/443 for Caddy's normal automatic certificate issuance and HTTPS. Restrict
access to authorized client networks where possible. Port 8000 is loopback-only;
never expose it through a second forwarding service. If port 8000 is already
occupied, change both the Uvicorn command and Caddy upstream together.

The Caddy example intentionally has **no access log directive**, does not enable
debug logging, and bounds request bodies to 2 MB. Do not enable request logging
in Caddy, an upstream load balancer, APM, or Uvicorn without excluding/redacting
OIDC callback query strings, cookies, authorization headers, and request bodies.
Authorization codes and passwords must not enter logs. Caddy operational logs
are not an application audit log. The example is an edge proxy, not a design
for an additional untrusted forwarding chain; add any organizational rate limits
without requiring a nonstandard Caddy plugin in this baseline.

If Caddy already hosts other sites, merge this site block into its configuration
instead of replacing those sites. On a dedicated new Caddy installation:

```sh
sudo install -m 0644 deploy/Caddyfile.example /etc/caddy/Caddyfile
sudoedit /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# Prompts interactively; passwords are not command-line arguments.
docker compose -f deploy/compose.yml run --rm --no-deps ipman netinfra-ipman-init
docker compose -f deploy/compose.yml up -d --no-build
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

Visit `https://YOUR-DNS-NAME/`, sign in using the provisioned local administrator,
and complete the mandatory initial password change. Web startup never creates
credentials. To recover the local administrator, stop the application, then run:

```sh
docker compose -f deploy/compose.yml stop ipman
docker compose -f deploy/compose.yml run --rm --no-deps ipman netinfra-ipman-init --replace
docker compose -f deploy/compose.yml up -d --no-build
```

The CLI requires explicit replacement confirmation. Recovery revokes older local
sessions, not OIDC sessions. Never run a second web process against the same data.

`trusted_proxies: ["127.0.0.1/32"]` trusts only the Caddy connection to the explicit
IPv4 loopback upstream. Caddy supplies the forwarding headers; the application
validates trusted chains itself. Do not use `0.0.0.0/0`, trust a whole client
network, or enable Uvicorn's forwarding-header rewriting. Other local programs
can also connect from loopback, so this assumes trusted server users/services.
Caddy's certificate/account storage must persist with the host service; protect
and back it up according to your Caddy installation's policy.

## Probe permissions, reachability, and limits

The container runs as UID/GID 10001 with a read-only root filesystem and only
`NET_RAW` in its capability bounding set. The image's Python interpreter has
`cap_net_raw=ep` so ping3 can open ICMP sockets as the non-root application user.
No `--privileged`, `NET_ADMIN`, host PID namespace, or root web process is needed.
Do **not** add `no-new-privileges` to this particular file-capability design: it
prevents Python from obtaining the capability. Runtimes/filesystems that strip
file capabilities or enforce that flag need a separately reviewed probe setup;
do not work around them by granting full privilege. The capability applies to
Python code in this container, so protect its writable mounts and installed code.

Host networking provides the server's interfaces/routes and neighbor view, not
access to every managed network automatically. Allow only authorized probe
ranges, ICMP echo/replies, and UDP/TCP 53 to selected DNS resolvers. OIDC also needs
outbound HTTPS to the provider's discovery/token/JWKS endpoints and correct DNS,
CA trust, and time synchronization. Configure `dns_servers` and optional
`subnet_dns_servers` explicitly when the default host resolver view is unsuitable;
scanner resolvers are independent of inventory DHCP options.

MAC lookup uses getmac and available OS tools (`ip`/`ping` are installed), and is
best effort on directly attached L2 networks. Routed/VPN/overlay networks normally
cannot expose the remote endpoint's MAC; a router's MAC is not proof of that
endpoint. Firewalls, missing permissions, missing neighbors, and DNS failures
produce incomplete evidence, not guaranteed absence. Do not add broad privilege
to "fix" routed MAC discovery. Only one IPv4 routing view is supported, not
isolated networks reusing addresses or IPv6 scanning.

Start with conservative `scan_concurrency` and `scan_start_rate`, choose a small
authorized target, and inspect results before enabling schedules. The default
100 address-check starts/second is not a packet-rate limit: each check may issue
ICMP, MAC discovery, and several DNS requests. Manual scopes over 4096 addresses
require explicit confirmation. Schedules are disabled until configured; restrict
and review their ranges separately. No installation/validation command below
performs network probes.

## OIDC

Keep the emergency local administrator accessible until an actual OIDC sign-in
has been verified. Register a client with authorization-code flow, PKCE S256,
and **RS256** ID-token signatures. Register exactly
`https://YOUR-DNS-NAME/oidc/callback`; do not use a wildcard callback. In the
installed private config, replace these illustrative values with real ones:

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

Use the exact discovery issuer, including its path. HTTPS provider endpoints are
required in production. Public PKCE clients use an empty `oidc_client_secret`;
confidential clients use discovery-supported `client_secret_basic` or
`client_secret_post`. Enter any secret only through the protected config editor,
not command arguments. Explicit claim mappings grant viewer/editor/administrator;
unmapped users are denied and the highest explicitly mapped role wins. Dotted
claim paths are supported. Verify the provider actually includes these claims in
the ID token, not just the userinfo response.

Restart after changes to OIDC, paths, session, or proxy configuration:

```sh
docker compose -f deploy/compose.yml restart ipman
```

OIDC configuration changes invalidate affected OIDC sessions. Group changes take
effect at the next sign-in; provider logout and application logout are distinct,
and refresh tokens are not retained. Test at least one account per mapped role,
unmapped denial, callback rejection for invalid state, and secure cookies over
HTTPS with your real provider before depending on it. These are operator
acceptance steps, not evidence of a real-provider test here.

## Optional local Git and external writers

For Git, mount the **entire checkout** in `/srv/ipman/inventory`, so its in-container
root is `/srv/netinfra`. Avoid linked worktrees whose `.git` points outside that
mount. Set `git_enabled: true`, `git_repo_path: /srv/netinfra`, and the actual
`git_branch`. Keep `backup_dir` outside the checkout. Configure a local committer
identity (non-secret example), with the web app stopped:

```sh
docker compose -f deploy/compose.yml stop ipman
docker compose -f deploy/compose.yml run --rm --no-deps ipman \
  git -C /srv/netinfra config user.name 'IPAM Operator'
docker compose -f deploy/compose.yml run --rm --no-deps ipman \
  git -C /srv/netinfra config user.email 'ipam@example.com'
docker compose -f deploy/compose.yml run --rm --no-deps ipman \
  git -C /srv/netinfra status --short --branch
docker compose -f deploy/compose.yml up -d --no-build
```

Initialize/import the checkout and its clean initial commit before enabling Git.
It must be on the configured branch, not detached, and clean (including untracked
files). App writes commit only NetInfra.yml and never push or switch branches.
No SSH/network credentials are needed by the application. Treat checkout Git
hooks/configuration as trusted executable code; disable unexpected hooks and
signing requirements in this dedicated checkout. A commit failure after a file
save is reported separately; inspect the saved YAML and use guarded commit retry
rather than blindly repeating the edit.

App write locks are **in-process only**. Revision checks reject stale previews
but cannot make a final check-and-replace atomic against an unrelated writer.
The normal rule is exclusive application ownership. For external edits, pulls,
branch changes, generators, or restores:

1. Block user changes and stop `ipman` (not merely the browser or Caddy).
2. Pause every external writer/automation job and agree who owns the maintenance
   window; a host lock ignored by the app is not mutual exclusion.
3. Back up the coherent state, make/review the external change, and validate the
   full YAML. For Git, return to the configured branch and a clean checkout.
4. Finish/stop external tools, restore ownership, restart the single app, and
   discard old browser previews. Re-review from the current source revision.

Never run external writers concurrently and rely on backups to prevent lost
updates. Scans never automatically edit inventory or deploy DNS/DHCP.

## Consistent backup and recovery

Back up all four directories together, plus your deployed Compose/Caddy files,
image/release identity, and Caddy certificate state. These contain credentials,
session state, network inventory, audit history, and possibly OIDC secrets:
encrypt off-host copies, restrict access, and apply your own retention policy.
The app's 20 pre-write YAML copies omit SQLite/config/Git/audit and are not enough.
Copying just a live `ipman.sqlite3` is **not** a consistent SQLite backup; a WAL
or rollback journal may be required. Do not copy a live database's sidecars one
at a time either. The simple supported procedure below is an offline snapshot.

Pause all external writers first, and stop the application cleanly. `stop` waits
up to the Compose grace period for shutdown; inspect its result and do not back
up if the process remains active. A forced kill requires SQLite recovery/checking
before treating a snapshot as known good. Then, on the host:

```sh
docker compose -f deploy/compose.yml stop ipman
sudo install -d -m 0700 /var/backups/ipman-system
# Choose a new unique filename for each backup; do not overwrite the last good copy.
sudo tar --numeric-owner -C /srv/ipman -czpf \
  /var/backups/ipman-system/ipman-2026-10-26T120000Z.tar.gz \
  config runtime inventory backups
sudo chmod 0600 /var/backups/ipman-system/ipman-2026-10-26T120000Z.tar.gz
docker compose -f deploy/compose.yml up -d --no-build
```

Keep external writers paused until the snapshot is complete. This captures the
whole runtime directory, including any SQLite journal/WAL/SHM sidecars, and the
whole checkout including `.git`, not only tracked files. For an online SQLite
backup use SQLite's backup API or `.backup` from a permitted local connection,
not `cp`; that gives a consistent database but **not** an atomic snapshot of
inventory/config/audit. Cross-resource consistency still requires quiescing all
writers. Do not place an SQLite backup on a network filesystem while using it as
the live database.

For restore, stop the service and all external writers. Keep a separate protected
copy of the failed current directories for investigation. Restore into a new
empty directory so obsolete sidecars and files cannot survive, then swap it into
place while the application is stopped. Example (choose unused paths):

```sh
docker compose -f deploy/compose.yml stop ipman
sudo install -d -m 0700 /srv/ipman-restored
sudo tar --numeric-owner -xzpf \
  /var/backups/ipman-system/ipman-2026-10-26T120000Z.tar.gz -C /srv/ipman-restored
sudo sqlite3 /srv/ipman-restored/runtime/ipman.sqlite3 'PRAGMA integrity_check;'
# Continue only if the integrity check reports "ok"; inspect/review restored YAML too.
sudo mv /srv/ipman /srv/ipman-before-restore
sudo mv /srv/ipman-restored /srv/ipman
sudo chown -R 10001:10001 /srv/ipman/config /srv/ipman/runtime \
  /srv/ipman/inventory /srv/ipman/backups
sudo chmod 0700 /srv/ipman/config /srv/ipman/runtime /srv/ipman/inventory /srv/ipman/backups
sudo chmod 0600 /srv/ipman/config/ipman-config.yml
docker compose -f deploy/compose.yml up -d --no-build
```

Use the matching application release initially; do not try to downgrade a newer
SQLite schema. Startup marks interrupted jobs incomplete instead of replaying
scans. Restore brings back saved credentials and possibly unexpired sessions;
limit access during recovery, recover/rotate local credentials when needed, and
consider OIDC/session expiry and provider credentials before reopening access.
Do not selectively delete security tables or throw away runtime state to clear a
login problem. Re-enable schedules and external automation only after reviewing
restored inventory, settings, audit history, and a real HTTPS login.

## Validation commands and acceptance checklist

The following are available operator checks; none were claimed executed as part
of writing these assets. Config rendering/building is not a live-network scan.

```sh
docker compose -f deploy/compose.yml config --quiet
docker compose -f deploy/compose.yml build
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# After provisioning the persistent directories/config:
docker compose -f deploy/compose.yml run --rm --no-deps ipman python -c \
  'from netinfra_ipman.config import load_config; c = load_config(); assert c.session_cookie_secure; print(c.netinfra_path, c.sqlite_path, c.backup_dir)'
docker compose -f deploy/compose.yml run --rm --no-deps ipman python -c \
  'import importlib.resources as r; p = r.files("netinfra_ipman"); assert p.joinpath("templates", "base.html").is_file(); print("templates packaged")'
docker compose -f deploy/compose.yml run --rm --no-deps ipman \
  getcap /usr/local/bin/python3.12
docker compose -f deploy/compose.yml ps
```

Before production: verify HTTPS/certificate renewal, no externally reachable
8000 listener, private mount permissions, actual-provider role mapping, cookie
flags and emergency recovery, read-only viewer permissions, persistent state
across container recreation, a restore drill from an encrypted off-host backup,
and file/Git save/retry behavior against a disposable inventory. Inspect proxy
and application logging policy without recording credentials. Any deliberate
probe acceptance must use an explicitly authorized small target; permission and
reachability cannot be inferred from a successful image build. Do not enable
production schedules until those deployment-specific checks are complete.
