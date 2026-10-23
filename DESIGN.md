# NetInfra IPAM design

Status: approved v1 design. Deployment-specific values remain to be configured.
This describes the intended application; it does not claim that the starter
already implements these features. See [the implementation plan](IMPLEMENTATION_PLAN.md)
for delivery order and acceptance checks.

## Purpose and scope

NetInfra IPAM provides a web interface for inspecting and editing host data in
`NetInfra.yml`, and compares that intended configuration with live network
observations. The YAML file remains the source of truth. Scans never change it
automatically or deploy DNS/DHCP configuration.

V1 supports all valid IPv4 CIDR sizes, including `/31` and `/32`. Subnet
definitions are read-only in the app. Users can create, edit, and delete hosts
and any of their properties, including records that do not participate in scans.

V1 excludes IPv6, distributed scanners, independently isolated routing domains
that reuse the same IP space, network-device integrations, historical probe
storage, automatic Git pushes, and editing non-host NetInfra sections.

## Application architecture

- Python 3.11+ backend using FastAPI.
- Jinja2 pages with HTMX for forms, table updates, and scan progress.
- One application server and one central background scan runner, with one active
  scan job and bounded parallel probes. Web requests remain responsive during scans.
- SQLite on local persistent storage for schedules, jobs, and latest observations.
  No separate database service or Redis is required for v1.
- Configuration, secrets, schedules, and observations remain outside `NetInfra.yml`.
- A reverse proxy terminates TLS. Deployment documents required network access
  and probe permissions, persistent storage, and trusted proxy configuration.

SQLite is an embedded store rather than a separate server. Keeping only latest
observations reduces storage needs, but schedules and job state still need
durable storage. The SQLite file belongs on local disk, not a shared network
filesystem. The NetInfra file may be a file in a configured Git working tree.

## NetInfra compatibility and inventory

The reference is the upstream
[NetInfra example](https://github.com/NICS-UTK/netinfra_monorepo/blob/e673611cf76e1188c7bdab9064a0b56fa9be7f62/ansible/group_vars/NetInfra.yml).
That revision supplies examples and explanatory comments, not an executable
schema; the referenced Bind/Kea templates are absent from that repository tree.
The naming and precedence rules below were explicitly agreed during design review.

### Eligible records

- Read subnet definitions from `subnets` and host entries from `Hosts`.
- Include a record in inventory when `Target` is a valid IPv4 address and its
  `RRType` is `A`, omitted (defaults to A), or `no_dns`.
- MAC is optional. Records without one are still represented.
- Other record types are excluded from IP inventory and checks, but preserved
  and editable within their host entry.
- Show documented IPs outside declared subnets in a validation/outliers view;
  they are not eligible scan targets.
- Preserve unrelated sections, custom fields, comments, and ordering during edits.

### Shared addresses and authority

Group eligible records by IP address, with one address row per IP. When a group
has MAC-bearing definitions, prefer them over definitions without a MAC for the
displayed identity and expected checks. Preserve the other definitions in the
file and make them accessible through the host editor.

If preferred definitions agree on the normalized MAC, retain their associated
names. If their MACs disagree, show a configuration conflict without selecting an
arbitrary winner. If no definition has a MAC, retain the available definitions
and omit MAC comparison. Sharing an IP is not itself an error.

For A records, derive the DNS owner from the first populated field in this order:
`Source`, `AltHostName`, then host `Name`. Respect absolute names, resolve relative
names against `ZoneName`, and honor NetInfra's `star` and `___` token conventions.
Preserve the original field values when displaying or saving the file.

`no_dns` is an explicit exception to the A-only inventory rule: it receives ping
and applicable MAC checks, but no DNS check. Neither `no_dns` nor `Block_DHCP`
alone is treated as an instruction to exclude an IP from scanning.

### DNS comparison and resolver selection

Require exact agreement between observed A answers and the complete expected
address set for the DNS name, using the authority rules above. Both missing and
unexpected addresses are discrepancies; legitimately configured multiple A
addresses are compared together rather than against a single host record.
Resolver timeouts and failures remain incomplete evidence, not confirmed
address mismatches.

Use a global scanner DNS resolver setting with optional per-subnet overrides.
An override takes precedence over the global setting; when neither is set, use
the server's resolver. Keep these settings outside `NetInfra.yml`. Do not
automatically derive scanner resolvers from subnet DHCP `dns_servers` options.

## Host editing and write-back

Provide forms for common properties and an advanced YAML editor for the complete
host entry. All host properties, nested records, and custom fields are editable.
Non-host sections and subnet definitions remain read-only.

Bulk creation accepts pasted YAML, an uploaded YAML file, or an editable YAML
starter. Accept either a host list or a `Hosts:` wrapper. This is a YAML starter,
not a parameterized generation language. Preview and apply the batch together;
imports do not silently merge with or overwrite existing hosts.

If an imported host Name already exists, reject the entire batch until the
collision is resolved. Also reject repeated host names within the import batch.
Users modify existing hosts through the host editor rather than an import merge.
This name-collision rule is separate from legitimate shared-IP assignments.

Validate structure, known field values, and semantic consistency before saving.
Malformed YAML, invalid field values, conflicting MAC assignments for an IP,
and eligible IP targets outside declared subnets block saving until resolved.
Acknowledging a warning does not override these checks. Validate assignments
against the rest of the inventory so cross-host conflicts are detected. Multiple
names sharing an IP with consistent definitions are not inherently invalid.
Live network discrepancies are reported separately; they are not configuration
validation errors that prevent saving an otherwise valid intended configuration.

Every mutation follows the same workflow:

1. Load the file and record its content revision.
2. Build and validate the proposed single-host or bulk change.
3. Present a full-file diff for review.
4. Serialize application writes and recheck the source revision. If it changed,
   reject the stale preview and require refreshed review.
5. Create a backup and atomically replace the YAML file with the reviewed content.
6. Record the actor and outcome, then optionally commit the change locally in Git.

The preview must be bound to the exact change being applied. Backups are stored
outside the Git checkout. Git mode validates the configured branch and clean
checkout before writing. A Git failure after saving is reported as "file saved,
Git commit failed" with a retry path; it must not masquerade as a failed file save.
Automatic push is outside v1.

Revision checks detect changes made outside the app; application locking does
not by itself coordinate external programs that ignore that lock. Deployment
guidance must explain this limitation rather than promise exclusive ownership
of the file across unrelated tools.

## Scans and schedules

### Targets and modes

Both scheduled and on-demand work use the same runner. Support all declared
subnets, one subnet, an individual IP, or an inclusive IP range. Every target must
belong to a declared subnet. "Whole network" means the union of those subnets,
with overlapping targets deduplicated.

Support a full scan, known-IP checks only, or discovery of other addresses.
Users can run full subnet scans or configure separate known-IP and discovery
schedules. Discovery results can be used to prepare a host addition, but never
write to the file automatically.

Stream targets through a bounded queue rather than allocating a task or database
row for every address. Paginate address views. Do not retain the starter's fixed
`/16` cutoff. Supporting a CIDR size does not imply that scanning it is fast;
show the target count, progress, and cancellation controls for large scans.

Probe concurrency and scan rate are configurable. Run one job at a time and
coalesce repeated triggers for the same schedule instead of building an
unbounded backlog. Partial results remain identifiable as partial.

Default to at most 128 concurrent IP checks and 100 IP checks started per second.
The rate limits address-check starts, not the total packet count across ping,
DNS, and MAC checks. Require explicit confirmation before starting a manual scan
of more than 4,096 target addresses. These defaults are configurable and do not
limit supported CIDR sizes. Scheduled runs use their administrator-enabled
schedule rather than waiting for interactive confirmation at each execution.

### Scheduling and recovery

Support intervals and daily/weekly calendar schedules with an explicit timezone.
Schedules start disabled. Resolve their targets against the current NetInfra
file when each run starts and retain the file revision associated with the run.

After restart, mark interrupted work incomplete and allow a manual rerun. Future
schedules continue normally without replaying every missed run. Skip nonexistent
local times during daylight-saving transitions and execute repeated local times
once.

Administrators manage schedules. Editors can launch and cancel manual scans.

## Observations and discrepancy display

Check ping response, forward DNS for A records, and MAC where observable. A
central routed scanner may be unable to obtain a remote host's MAC; unavailable
evidence is not proof of a mismatch. Store observed evidence separately from the
expected values used for reconciliation.

| State | Meaning |
| --- | --- |
| Matches | Applicable checks completed and agree with the file. |
| Mismatch/conflict | Observed DNS or MAC disagrees, or authoritative definitions conflict. |
| No response / incomplete evidence | A probe timed out or a required observation could not be obtained. |
| Unchecked / stale | Evidence is absent, too old, or predates a relevant configuration change. |
| Undocumented responder | An address responded but has no eligible file assignment. |

Use text and explanations as well as color. Show expected and observed values,
timestamps, and per-check outcomes. Distinguish scanner/resolver failures from
confirmed discrepancies. Do not call a silent address "free". Identify whether
an undocumented responder lies in a declared DHCP pool without claiming that
a DHCP lease has been verified.

Keep latest observations only and bounded recent job summaries. Use sparse
observations plus compact completed-discovery coverage instead of one stored
result for every silent, undocumented IP. A relevant file edit marks affected
evidence stale until it is checked against the new expectations.

Freshness defaults to twice the applicable scheduled interval, or 24 hours for
manual-only checks, with an administrator override.

## Access and audit

Use OIDC SSO with configurable role/group mapping and an emergency local
administrator. Anonymous viewing is configurable through
`allow_anonymous_viewing`, defaulting to false. If enabled, anonymous users receive
viewer permissions only. This setting never authorizes mutations or probes.

| Role | Permissions |
| --- | --- |
| Viewer | Browse inventory and observation results. |
| Editor | Viewer permissions plus host changes and manual scan launch/cancellation. |
| Administrator | Editor permissions plus schedules, settings, and audit access. |

Enforce permissions server-side. Use verified, expiring sessions and CSRF
protection for mutations. Provision the emergency administrator through the CLI;
never display credentials in public pages. Keep secrets out of rendered settings
and audit records. Trust forwarded client addresses only from configured proxies.

Audit edits, scan actions, authentication events, and settings changes. Audit
and backup retention are independent of the decision to retain only latest
network observations.

## Defaults and deployment assumptions

| Setting | Default / assumption |
| --- | --- |
| Deployment | One server, one application worker, one central scan runner. |
| Routing | One routing view; isolated networks reusing IPs are outside v1. |
| Runtime storage | SQLite on persistent local disk. |
| Anonymous viewing | Disabled; configurable by administrators. |
| Schedule creation | Disabled until explicitly enabled. |
| Concurrent scan jobs | One, with bounded parallel probes. |
| Concurrent IP checks | Up to 128; configurable. |
| IP check start rate | At most 100 per second; configurable. |
| Large manual scan confirmation | Required above 4,096 target addresses; configurable. |
| Observation retention | Latest results only. |
| Completed job summaries | Most recent 100; configurable. |
| File backups | Most recent 20; configurable. |
| Audit retention | Rotate at 10 MiB; retain five rotated files plus the active file; configurable. |
| Freshness | Twice applicable scheduled interval, otherwise 24 hours; overridable. |
| Git | Optional local commits; no automatic push. |

## Implementation gaps

Phase 1 of the implementation plan is delivered. The table distinguishes the
remaining starter gaps from completed foundation work; these are implementation
differences, not undecided architecture choices.

| Area | Current behavior | Required change |
| --- | --- | --- |
| Inventory | Requires MAC; flags repeated IPs; reduces rows to one record. | Optional MAC, grouping, authority rules, conflict diagnostics, outliers. |
| DNS identity | Uses `Source`, `HostName`, then `Name`; strips trailing dots early. | Agreed `AltHostName` precedence, absolute-name and token handling. |
| Editing | Can append a host only. | Full host editing/deletion, advanced YAML, bulk import. |
| Validation | Skips some invalid data and has minimal field checks. | Visible diagnostics and safe validation without discarding data. |
| Saving | Direct file writes and unbound previews; backups in the file directory. | Revision-bound previews, serialized atomic saves, external backups, Git outcome handling. |
| Scanning | Single durable job runner with bounded streamed probes and restart recovery; web `/16` cutoff remains. | Full scan scopes/modes, rate limits, confirmation policy, and scheduling. |
| Scheduling | Durable disabled-by-default definitions; no dispatch/UI. | Interval/calendar schedules and overlap handling. |
| Results | Discovery results are not merged into the address table. | Reconciled latest observations and visible undocumented responders. |
| Status | Ping/DNS failures are combined as errors; no freshness policy. | Distinguish mismatch, inconclusive evidence, stale results, and scan failures. |
| Storage | SQLite retains latest observations, schedules, and bounded job summaries. | Complete reconciliation/coverage and scheduling integration in later phases. |
| UI scale | Renders every usable IP in a subnet. | Pagination, filtering, progressive scan updates. |
| Authentication | CLI-only provisioning; still trusts an unsigned username cookie. | Verified sessions, CLI recovery, authorization, CSRF protection. |
| SSO | Keycloak/Duo configuration fields without working integration. | Working OIDC; standalone Duo integration is not part of this design. |
| Access/settings | Anonymous viewing is fixed; refresh can trigger probes anonymously; settings expose configuration values. | Configurable viewing, authenticated probes, protected and redacted settings. |
| Lifecycle | Explicit factory/lifespan initialization and awaited scan/storage/audit cleanup. | Foundation delivered; one worker required. |
| Tests | 82 passing tests, including foundation lifecycle, persistence, cancellation, and recovery. | Remaining inventory, authorization, write safety, scheduling, and UI acceptance coverage. |

## Deployment configuration still required

The design policies and initial operational defaults above are approved. Supply
the real OIDC issuer and role/group mapping, trusted proxy addresses, scanner
DNS settings, file/Git paths, and persistent runtime location at deployment
time. Credentials are supplied through protected configuration, not committed
to the repository. These environment-specific values do not block implementation.

## Acceptance

The application must demonstrate host editing and bulk creation with reviewed,
conflict-aware YAML saves; on-demand IP/range/subnet/network scans; independent
known-IP/discovery schedules; and actionable discrepancy displays. It must
preserve unrelated NetInfra content, enforce all roles in both anonymous-view
modes, and remain responsive with large target ranges using bounded resources.

Tests use simulated probes and controlled networks. Initial inspection lacked
pytest; phase-1 verification now passes 82 tests. This does not establish full v1
acceptance or make the remaining starter authentication/write paths safe to deploy.
