# Alloy setup and application logs

`ansible/roles/monitoring_alloy` deploys official Grafana Alloy **1.21.2** to
systemd Debian-family amd64/arm64 guests (including Ubuntu, Pop!_OS and Parrot)
and Windows amd64 guests. It adopts an
existing matching installation by default. It refuses a different version,
automatic repair, and unapproved installation. No operating system upgrade or
apt repository is added. Appliances and Xen dom0 receive no agent.

The unified Terraform root in [`infra/monitoring`](../../infra/monitoring/) owns
monitoring orchestration: Grafana resources plus an explicit selected-fleet
deployment that invokes the monitoring controller and Ansible. The controller
and fleet manifest select the hosts and enforce the account prerequisites.
Use the Terraform workflow in the [monitoring guide](../README.md) for deployment
and redeployment. The Ansible role is its implementation layer. The role fails
before fact gathering or mutation unless `monitoring_access_verified`,
`monitoring_deployment_approved` and `monitoring_grafana_zero_cost_mode_verified`
are actual YAML booleans set to `true`.
`"true"`, `1`, or a missing flag are rejected. Installing on a fresh host further
requires `monitoring_alloy_install_approved: true`.

The observed stack is in Cloud Trial. Grafana states trial use is never billed,
then automatically moves the account to the always-free plan. A live API check
confirms the Trial edition before each plan and apply; this $0 path permits Alloy
collectors only. The collector rate/series settings below bound per-host ingestion.
The Free plan has service usage limits; exceeding them does not authorize paid use.

## Private input contract

Supply these variables through the controller's private input file or an
owner-only inventory/Vault outside the checkout. Never commit variable files,
credentials, rendered files, saved plans, or Terraform state.

| Variable | Meaning / default |
| --- | --- |
| `monitoring_grafana_metrics_url` | Existing Grafana Cloud Prometheus HTTPS write URL, generally `/api/prom/push` |
| `monitoring_grafana_metrics_username` | Existing metrics instance username, represented as a string |
| `monitoring_grafana_logs_url` | Existing Loki HTTPS write URL, generally `/loki/api/v1/push` |
| `monitoring_grafana_logs_username` | Existing logs instance username, represented as a string |
| `monitoring_grafana_write_token` | Write-only token restricted to the selected metrics/logs endpoints |
| `monitoring_role` | Reviewed manifest role, required; letters, numbers, `_` and `-` |
| `monitoring_environment` | `homelab` (default) or `lab` |
| `monitoring_access_verified` | `false`; must become boolean `true` after access verification |
| `monitoring_deployment_approved` | `false`; controller sets boolean `true` only for approved selected hosts |
| `monitoring_grafana_zero_cost_mode_verified` | `false`; set true after reviewing the existing $0 Free/Trial mode; the controller checks live Trial edition |
| `monitoring_alloy_install_approved` | `false`; boolean `true` permits a fresh installation, never an upgrade |
| `monitoring_alloy_version` | Reviewed pin `1.21.2`; other values deliberately fail |
| `monitoring_alloy_sample_limit` | `450`; integer range `1..450`, per host scrape |
| `monitoring_alloy_log_rate` | `0.2`; positive lines/second, at most `0.2`, per host |
| `monitoring_alloy_log_burst` | `10`; integer range `1..10` |
| `monitoring_alloy_linux_log_files` | `[/var/log/dpkg.log]`; select only `/var/log/dpkg.log`, `/var/log/kern.log`, `/var/log/nginx/error.log`; `[]` disables file reads |
| `monitoring_alloy_windows_event_channels` | `[System, Application]`; select only those channels; `[]` disables event reads |
| `monitoring_alloy_container_syslog_enabled` | `false`; explicit boolean `true` enables the Linux-only native Docker syslog input on `127.0.0.1:1515` |
| `monitoring_alloy_container_syslog_apps` | `[maps, openwebui, portainer]`; exact allowed app-name subset; at least one app when the receiver is enabled |

URLs must use HTTPS, a DNS hostname, and the default TLS port or port 443.
Embedded credentials, query strings, fragments, whitespace, insecure TLS, and
unbounded exporter/log overrides are rejected. Token validation excludes
newlines, so the file contains the exact token with no trailing newline.

Example private values (placeholders only; these do not authorize deployment):

```yaml
monitoring_grafana_metrics_url: https://prometheus-prod-REGION.grafana.net/api/prom/push
monitoring_grafana_metrics_username: 'REPLACE_METRICS_INSTANCE'
monitoring_grafana_logs_url: https://logs-prod-REGION.grafana.net/loki/api/v1/push
monitoring_grafana_logs_username: 'REPLACE_LOGS_INSTANCE'
monitoring_grafana_write_token: REPLACE_WITH_RESTRICTED_WRITE_TOKEN
monitoring_alloy_install_approved: false
```

For a first setup, obtain the existing Prometheus/Loki write URLs and instance
usernames from the stack's connection details. Create a write-only token scoped
to those services and the existing stack; the collector needs no billing, stack
administration, Docker or Grafana dashboard permission. Keep the separate
Terraform Grafana administration token in its supported external environment,
and keep the collector write token in the private Ansible inputs. Nothing in
the example Compose fragment needs either token.

Add verified SSH/WinRM connection details to the owner-only private inventory.
Use the actual guest accounts; captured Xen credentials do not authenticate to
Windows guests. Retain SSH host-key verification and HTTPS WinRM certificate
verification. The controller's selection must name only reachable reviewed
inventory members. Do not boot a stopped VM or target dom0 to make deployment
pass. Set the role access/approval/Free flags only after those prerequisites are
actually met. A fresh Alloy installation additionally needs the installation
flag; adopting a matching existing version does not.

Terraform receives reviewed public host selections and existing data-source
identifiers. Private inventory/variable-file paths are supplied to its runner
through the controller environment; token contents are not Terraform variables
and must not enter a plan or state. Changing private host options does not make
Terraform inspect private file contents for drift. Follow the guide's explicit
fleet redeployment procedure after such changes so the same gated role runs
again. Keep `expected_linux_hosts`/`expected_windows_hosts` aligned with collectors
that are deployed and actually expected online, not every archived inventory
entry.

## Setup sequence

1. Review the stack's $0 Trial status, then prepare private inventory/write
   credentials and the exact first host selection. The controller confirms the
   live Trial edition immediately before planning and applying.
2. Select file/event sources and optional app syslog input below. On Linux,
   arrange exact file read permissions before including non-world-readable logs.
3. Review the unified Terraform plan and selected hosts. Apply it through the
   monitoring controller after the host credentials and endpoint are verified. Terraform calls
   Ansible; the role verifies package/version policy and validates the candidate
   Alloy configuration before restarting its service.
4. Verify the collector service, cloud `up` series, selected log sources and
   observed usage for that small first selection. Native syntax validation alone
   does not prove authentication, reachability, a healthy collector or ingestion.
5. For container logs, deploy the optional receiver first, then review the
   logging-only Compose changes in the existing application deployment workflow.
   Recreating an application is separate from collector deployment and may cause
   application downtime; this repository does not do it automatically.
6. After confirming the 7,000-series / 500-MB-per-day fleet planning targets,
   expand the exact selected set and update expected-host alerts. Reduce sources
   or log rate if usage rises; never use a paid fallback.

## Maps, OpenWebUI and Portainer container logs

Container stdout/stderr reaches Alloy through Docker's built-in `syslog`
logging driver. This is an opt-in path for **application logs**, independent of
the bounded host metrics and Linux package log. Alloy never queries Docker's
API, opens `docker.sock`, reads Docker environment variables, joins the Docker
group, or installs Docker. The monitoring role does not recreate containers,
change the daemon-wide logging driver or overwrite existing application files.

Enable it only on reviewed Linux Docker hosts. These example optional values
belong under the matching hosts in the **private inventory** (outside Git):

```yaml
all:
  hosts:
    maps:
      monitoring_alloy_container_syslog_enabled: true
      monitoring_alloy_container_syslog_apps: [maps, openwebui]
    portainer:
      monitoring_alloy_container_syslog_enabled: true
      monitoring_alloy_container_syslog_apps: [portainer]
```

The host called `maps` is an inventory identity, not proof that OpenWebUI runs
there. Put each option on the host that actually runs that app. The examples do
not supply access details or override the default-false deployment gates. When
deploying more than one host, avoid a global extra variable that enables the
receiver everywhere. A Windows target with this option enabled fails closed.

The receiver accepts only RFC5424 syslog over TCP at **`127.0.0.1:1515`**. Port
1515 is unprivileged, so the existing unprivileged Alloy service needs no new
capabilities. The address/port are fixed intentionally; no LAN listener, firewall
opening or remote-device forwarding is added. Docker resolves this loopback
address from the **Docker daemon's network context**, not from inside the app's
container. This matches an existing Docker Engine on the same Linux host as
Alloy. A remote Docker daemon, Docker Desktop VM, containerized daemon or
rootless daemon with a separate network namespace needs a separately reviewed
design; replacing loopback with `0.0.0.0` is not a supported shortcut.

Use [`examples/compose.logging.yaml`](examples/compose.logging.yaml) as a
logging-only fragment. Merge only the entries matching existing services into
the owner's existing Compose project, or copy their `logging:` sections into
the existing services. The example has no images, volumes, credentials, ports,
application command or container lifecycle operations. It is not a standalone
application deployment. Adjust service keys to the real Compose service names;
keep the literal syslog tags shown below. Delete irrelevant service entries
from an overlay so Compose cannot interpret them as new service definitions.

| Application | Example Compose service | Required literal `tag` | Cloud log label |
| --- | --- | --- | --- |
| Maps | `maps` | `homelab.maps` | `app="maps"` |
| OpenWebUI | `open-webui` | `homelab.openwebui` | `app="openwebui"` |
| Portainer | `portainer` | `homelab.portainer` | `app="portainer"` |

Each service uses `syslog-address: tcp://127.0.0.1:1515`,
`syslog-format: rfc5424`, `mode: non-blocking` and `max-buffer-size: 1m`.
Nonblocking delivery buffers a small amount per container and drops new entries
when full, protecting running application stdout/stderr from logging
backpressure. **It does not guarantee container startup during a receiver
outage:** Docker may fail to initialize the TCP syslog logging driver when
creating/recreating a container if Alloy is unavailable. Start and verify Alloy
before applying an approved application recreation, and preserve the previous
logging configuration for rollback. Logging options only take effect when the
container is recreated; restarting an old container does not change its logging
driver. No such recreation was performed here.

The fragment also limits Docker's optional local dual-logging cache to two
5-MB files before compression, with compression enabled, so a local `docker
logs` view need not use Docker's larger defaults. This cache belongs to Docker;
Alloy does not read it or replay it. Cache writes can fail alongside remote
driver writes, and this is not a durable queue or guaranteed recovery of logs
lost while Alloy is down. Check host disk usage and the installed Docker
version's support for the documented options before changing the application.

Only a configured exact tag is accepted. A Docker-generated container ID,
arbitrary image/tag, hostname, process ID or structured-data field cannot become
a cloud label. The app label contains only `maps`, `openwebui` or `portainer`;
`host`, `role`, `environment` and `job` remain the reviewed collector's static
labels. Loopback restricts access to the local machine, but tag matching is not
authentication: another local process can send an allowed tag. Keep this input
off on hosts where untrusted local users/containers should not supply logs.

The driver forwards stdout/stderr that the app actually emits after its logging
configuration takes effect. It does not scrape an app's internal database,
historical files, arbitrary mounted log folders, conversations or Docker
metadata. If an application logs only to an internal file, configure its
supported stdout/stderr output in the existing app configuration first, or add
a separately reviewed file source. Do not enable debug dumps to manufacture
logs. OpenWebUI prompts/chat payloads, Maps URL query strings/location data and
Portainer endpoint/registry details can be private; review each app's logging
settings and prefer operational warnings/errors.

All app records feed the **same** `loki.process.bounded` pipeline as selected
file logs, with one host-wide line limiter shared across apps. Syslog messages
have an 8,192-byte parser limit; records above 4 KB are dropped downstream.
Records older than one hour are dropped. Common credential and sensitive-content
markers cause the **entire line** to become `[REDACTED sensitive log entry]`
before forwarding. Examples include authorization/cookies/API keys/passwords,
access/refresh tokens and explicit prompt/messages/coordinate fields. This is
conservative, lossy filtering, not proof that every personal datum or secret is
removed. Prevent sensitive content at the application source; leave a source
disabled when that cannot be established. Never add `env`, `env-regex` or dynamic
ID-based tag options to this fragment.

To inspect expected cloud results after an authorized deployment, Grafana
Explore queries use the real inventory name:

```promql
up{job="homelab",host="maps"}
```

```logql
{job="homelab",host="maps",app="maps"}
{job="homelab",host="maps",app="openwebui"}
{job="homelab",host="portainer",app="portainer"}
```

An absent app stream can mean the receiver is disabled, the app has not been
recreated with the new driver, its literal tag is not allowlisted, no new
stdout/stderr has occurred, or the shared limiter dropped a burst. Check those
in order before changing the service's privileges or opening a network port.

## Collected data and privileges

Every metric, including scrape `up`, carries `job=homelab`,
`host=<inventory_hostname>`, `instance=<inventory_hostname>`,
`environment=<monitoring_environment>` and `role=<monitoring_role>`. Logs carry
the same required job/host/environment/role labels. Labels are fixed from the
reviewed inventory, not extracted from arbitrary log fields.

Linux enables only CPU, memory, filesystem, network, boot-time and time
collectors. Windows enables only CPU, memory, logical disk, network and system
collectors. A second metric-name allowlist forwards essential measurements and
scrape `up`. Windows memory uses `windows_memory_available_bytes` and
`windows_memory_physical_total_bytes`; the removed `cs` collector is not used.
Filesystem collection excludes virtual filesystems and container mounts; no
container metrics, Kubernetes, textfile, process, Docker environment or Docker
socket collection is enabled. Optional container application logs use only the
native syslog path described above. The management/metrics interface listens on loopback
`127.0.0.1:12345`; profiling, support bundles and Alloy usage reporting are
disabled.

The default scrape interval is 60 seconds. `sample_limit` fails an entire scrape
above its limit; it does not trim samples. Fourteen stable exporters at the
default limit account for at most 6,300 exporter samples per scrape plus scrape
health samples. Hardware/label churn and other collectors can increase active
series across the cloud's accounting window. Monitor the **7,000 total active
series** fleet planning target and refine the allowlist before enabling any
additional source.

Linux runs as the dedicated `alloy` user with no supplementary groups, no Linux
capabilities, restricted filesystem access and no Docker socket. The token is
`/etc/alloy/grafana-write-token`, owned by root:alloy with mode `0640`, inside a
`0750` directory. The active configuration contains only a `local.file` secret
reference. Secret/config tasks disable diffs and logs. `/var/lib/alloy` remains
owned by alloy with mode `0700` and is never cleared on redeployment.

### Linux system/application file logs

The exact file allowlist is deliberately small:

| Path | Intended signal | Enabled by default |
| --- | --- | --- |
| `/var/log/dpkg.log` | Package installation/removal activity | Yes |
| `/var/log/kern.log` | Kernel/device/memory/disk warnings, where rsyslog writes this file | No |
| `/var/log/nginx/error.log` | Selected reverse-proxy/application errors | No |

For example, a reviewed reverse-proxy host may select
`monitoring_alloy_linux_log_files: [/var/log/dpkg.log, /var/log/nginx/error.log]`.
`[]` disables file reads. Paths are literal, not glob patterns. Rotated archives,
`/var/log/auth.log`, `/var/log/secure`, the whole journal and arbitrary container
folders are not allowed. Additions require a repository allowlist/test change
and a privacy/volume review, rather than passing an unrestricted path override.

The role does not grant broad `adm` access or change application/logrotate
configuration. Selected existing files must be regular nonsymlink files readable
by `alloy` before deployment. `/var/log/dpkg.log` is normally world-readable.
For a private extra file, grant a **named-user `alloy` read ACL on that exact
file** and only the required directory traverse access, or use an application
log dedicated to the primary `alloy` group. The role deliberately removes
supplementary groups, so a separate reader-group membership is not preserved.
Arrange the corresponding application's rotation policy to recreate that exact
access; do not add a directory default ACL that makes every unrelated security
log readable. Permission and rotation changes belong to the existing host/app
management workflow and are not automatically performed by this collector role.
Check readability as the service user after rotation. Missing selected files
are permitted; they produce no logs until created and readable.

### Windows System/Application events

Windows uses the official Alloy service wrapper as LocalSystem. Its configuration,
write token, staging files, component state and bookmarks are under
`C:\ProgramData\HomeLabMonitoring\Alloy`, restricted to SYSTEM and local
Administrators with inheritance from broader directories disabled. Existing
explicit ACLs in this owned directory are tightened before writing secrets.
Reparse points are rejected. No token appears on a process command line, in
registry environment variables, or in the rendered Alloy config.

`monitoring_alloy_windows_event_channels: [System, Application]` is the default.
Choose either/both, or `[]` to disable these reads. **Security** and arbitrary
application-specific channels are rejected. Only critical/error/warning levels
1, 2 and 3 are subscribed; informational/debug events are not. System includes
OS/service failures; Application includes applications that actually publish to
the Windows Event Log. This does not collect Windows container stdout or an
application's private files. Event/user data payload fields are omitted, while
the rendered message still passes through the common sensitive-line redaction.
Use the Wazuh policy for its separately managed security signals.

Linux tails new lines only and resumes saved positions. Corrupt file positions
restart at the end instead of replaying history. Windows creates a bookmark at
the latest existing event for each newly enabled channel, then preserves it
across redeployments. Only critical/error/warning events are selected; user/event
data fields are excluded. An empty channel has no historical events to replay.
Logs older than one hour and lines above 4 KB are dropped; common sensitive
markers replace the entire line with a redaction marker.
The shared per-host line limiter drops excess lines rather than accumulating
them. These checks intentionally lose verbose data and do not guarantee removal
of every secret. Review selected application logs before enabling them.

The fleet **500 MB/day total logs** target is an operational target, not an
enforced byte quota. A line token bucket, overhead, bursts, restarts and all other
sources affect real ingestion. Observe cloud usage after a small initial host
selection, and reduce collection before enabling more hosts. No paid fallback,
trial credits, or subscription upgrade is part of this deployment.

## Validation and recovery

Linux uses `alloy validate` as Ansible's candidate-file validator, then atomically
replaces the active config. Windows renders a protected candidate, validates it
with the installed native binary, and only then copies it to the active path.
Staging files are removed even when validation fails. Validation does not start
collectors or write to Grafana. Service restarts happen only after valid config
activation. Existing Linux systemd drop-ins require review; the role refuses to
adopt a service whose overrides could defeat confinement.

Fresh Linux package installation suppresses maintainer-script service starts.
The Windows installer starts a service with an inert bootstrap config containing
no receivers/exporters or credentials, reporting disabled; the role immediately
stops it until the rendered candidate validates. The active service thereafter
uses the role-owned config and persistent data path. Native deployment still
requires live Linux/Windows readback before claiming the fleet is healthy.

When adopting a collector managed elsewhere, privately back up its configuration,
token, service settings, WAL/positions and bookmarks. This role takes ownership
of the Alloy service and the paths above. It does not migrate positions from an
unrelated prior data directory; new file/event sources start at the current end.
Once deployed by this role, repeated deployments preserve the same paths and
component names. To recover, stop only Alloy, restore the last validated private
configuration/service settings and matching data backup, validate locally, then
start Alloy. Do not delete the data directory to fix a configuration error.
Version upgrades require a separate reviewed pin/digest change and backup; the
fresh-install flag never authorizes replacement of an installed version.

Run local tests in the Ansible Python environment:

```sh
ALLOY_BINARY=/absolute/path/to/verified/alloy \
  python -m unittest discover -s ansible/tests -p test_monitoring_alloy.py -v
```

The optional `ALLOY_BINARY` test validates rendered Linux with the app receiver
disabled and enabled, plus Windows configs, and
checks an invalid component is rejected. Other tests execute only the four local
preflight assertion tasks, inspect secret/service/package boundaries and test the
metric allowlist. They never start Alloy or contact a guest/cloud write endpoint.

## Reviewed official sources

- [Immutable v1.21.2 release and SHA256 asset digests](https://github.com/grafana/alloy/releases/tag/v1.21.2), checked 2026-10-25; release API `https://api.github.com/repos/grafana/alloy/releases/tags/v1.21.2`.
- [Linux setup](https://grafana.com/docs/alloy/latest/set-up/install/linux/) and [Windows installer/service registry](https://grafana.com/docs/alloy/latest/set-up/install/windows/).
- [Unix collector allowlist](https://grafana.com/docs/alloy/latest/reference/components/prometheus/prometheus.exporter.unix/), [Windows collector allowlist](https://grafana.com/docs/alloy/latest/reference/components/prometheus/prometheus.exporter.windows/) and [current Windows memory metrics](https://github.com/prometheus-community/windows_exporter/blob/v0.31.3/docs/collector.memory.md).
- [Secret file references](https://grafana.com/docs/alloy/latest/reference/components/local/local.file/), [file tail positions](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/), [Windows bookmarks](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.windowsevent/) and [line limiter behavior](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.process/#stagelimit).
- [Alloy syslog listener, internal labels and relabel rules](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.syslog/), [Docker native syslog format/tags](https://docs.docker.com/engine/logging/drivers/syslog/), [nonblocking delivery and container recreation](https://docs.docker.com/engine/logging/configure/) and [bounded local dual-logging cache](https://docs.docker.com/engine/logging/dual-logging/).

Pinned package SHA256 values are stored in role defaults and checked against the
reviewed constants before any download. Merely changing an inventory version or
checksum cannot authorize a different artifact.
