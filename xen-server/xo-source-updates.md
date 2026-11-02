# Xen Orchestra source and OS updates

The management VM runs the official Xen Orchestra GitHub source with Node 24 LTS.
This workflow requires no XOA registration, Enterprise license or paid trial.
Ansible declares the build dependencies, updater, timers, service recovery policy,
daily Debian security updates and bounded journal storage.

## Updates

```sh
make xo-update-status  # Deployed Git commit, Node version and activation health
make xo-update        # Fetch/build a candidate and activate it if healthy
make xo-update-syntax
```

These commands use the existing owner-only management-guest inventory and dedicated
SSH key. The ordinary account has only two additional exact sudo commands: invoking
the root-owned updater with `--apply` or `--status`. It receives no general sudo.
The guest UUID is verified before the command executes.

`home-lab-xo-update.timer` runs Sunday at 03:00 America/Los_Angeles, with up to 30
minutes of jitter. It follows official `master` and current Node 24 LTS patch
releases. The deployed commit/runtime are recorded in the guest's private status
file. Native daily apt timers apply Debian bookworm security updates; automatic
reboots are disabled. Kernel activation therefore needs a controlled reboot.

## Activation and rollback

1. Resolve the official GitHub commit and verify upstream Node/Yarn archive hashes.
2. Build into a separate release as the dedicated unprivileged build account. Its
   build units have restricted filesystem writes and cannot reach loopback or
   private management networks. The working XO service stays available.
3. Require the server and both web builds, freeze deployed file ownership and
   permissions, and check XAPI tasks, XO tasks and running jobs before cutover.
4. Stop XO and preserve Redis RDB, configuration and application data. Transient
   sockets/pipes are excluded. Redis AOF requires a separately reviewed procedure.
5. Activate the new release, then require authenticated VM/host/pool identity
   agreement, the task API, both web interfaces and an active service.
6. On failed activation, stop the candidate and restore the database, data,
   configuration and previous service definition before restarting it. A failed
   rollback step stops for recovery rather than starting against unverified data.

Retain current/previous source releases and their runtimes, seven application
backups and seven build logs. Each build log is capped at 16 MiB. Build caches are
cleared and builds stop when the filesystem reserve is low. These local copies do
not replace independent VM/application backups.

The initial legacy-appliance migration may use `xo_source_initial_migration=true`
only when no jobs are configured and the legacy task API is unavailable. Future
scheduled cutovers require the application task API and cannot reuse that exception.

## Provisioning

Use [xo-source.yml](../ansible/playbooks/xo-source.yml) with existing authenticated
root access, the private guest inventory, and owner-only extra vars containing
`xo_source_health_login.email` and `xo_source_health_login.password`. The health
account needs administrator visibility. Never commit or pass credentials as literal
command arguments. Run `xo_source_stage=prepare`, then `build` or `deploy`, and
`verify`. Deployment enables the timer only after health checks pass and disables
the vendor updater. Remove temporary root authorization after permanent access is
verified.

The runtime retains the existing service execution account; build code and update
policy are root-owned. The allowed update entrypoint cannot change its repository,
guest identity or credentials through caller-supplied arguments/environment.

## Debugging and recovery

```sh
make xo-update-status
ssh xoa-management 'systemctl status xo-server home-lab-xo-update.timer'
ssh xoa-management 'systemctl list-timers home-lab-xo-update.timer apt-daily-upgrade.timer'
```

With an authenticated root recovery shell, inspect:

```sh
journalctl -u xo-server -u home-lab-xo-update --since today
cat /var/lib/home-lab-xo/status.json
df -h /
```

Private backup metadata is under `/var/lib/home-lab-xo/backups`; the current release
is `/opt/home-lab/xo/current`. Never publish backup contents, Redis data or private
health credentials. Inspect the last failure before retrying a cutover. A VM-level
rollback uses the separately preserved disk and attachment definition; do not delete
the active or preservation disks while investigating.

This timer maintains the management guest's XO/Node installation. Hypervisor and
other guests have separate maintenance and backup requirements. After a host update,
verify its native approved VM autostart set, storage, network recovery, Tailscale,
guest services and actual reboot behavior.

## Hypervisor maintenance

[host-updates.yml](../ansible/playbooks/host-updates.yml) stages or installs official
XCP-ng maintenance RPMs during an explicit update window. It requires private host
identity, the exact expected release and a mounted download directory. Third-party
repositories are disabled for the transaction and RPM signature checking is forced.
Its defaults are read-only; an explicit apply defaults to download-only.

Use the existing pinned host transport and a private extra-vars file containing
`host_update_expected_version`, `host_update_download_directory`,
`host_update_apply` and `host_update_download_only`. Actual installation additionally
requires the host disabled, one pool with HA disabled, no pending XAPI tasks and all
ordinary guests halted. The controller does not evacuate or force-stop guests.

An apply launches a transient systemd job; successful launch is not installation
success. Its owner-only log is `/var/log/home-lab-host-update-<release>-<phase>.log`,
where release dots become hyphens and phase is `download` or `apply`. Require the
matching `.status` JSON to contain `returncode: 0`, inspect the transaction log and
installed packages, then perform and verify the required controlled reboot. A
missing marker or nonzero result requires investigation. Existing completion markers
prevent accidental retry without review. Never kill a live RPM transaction casually.

This maintains packages within a release. A major upgrade uses the
[supported installer procedure](https://docs.xcp-ng.org/installation/upgrade/),
followed by current maintenance patches and the complete host recovery checks.
