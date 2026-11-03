# Local Wazuh storage policy

`monitoring_wazuh_storage` manages the existing Ubuntu 24.04 central installation
with `wazuh-manager`, `wazuh-indexer`, and `wazuh-dashboard` exactly `4.7.5-1`.
It creates no cloud resources, changes no packages, and uses Python and systemd
already present on that host. This role is separate from the alert-index ISM
policy in `retention.py` / `retention.json`.

## Rotation

Only these overrides in `/var/ossec/etc/local_internal_options.conf` are managed:

| Setting | Value |
| --- | --- |
| `monitord.rotate_log` | `1` |
| `monitord.keep_log_days` | `7` |
| `monitord.size_rotate` | `64` MiB |
| `monitord.daily_rotations` | `4` |
| `monitord.compress` | `1` |

Unrelated lines and settings remain intact; duplicate managed keys collapse to
one value. The role preserves existing file ownership and permissions, keeps
one root-only original backup named
`local_internal_options.conf.pre-home-lab-storage`, validates with
`wazuh-monitord -t`, and restarts the manager only when configuration changes.
The backup is deliberately never overwritten; subsequent runs retain that first
original. Review it privately before a manual rollback. Configuration contents
are suppressed from Ansible output and diffs.
If native validation or activation fails, the role restores the options captured
at the beginning of that run and restarts the restored manager before stopping.

In the official [4.7.5 internal defaults](https://github.com/wazuh/wazuh/blob/v4.7.5/etc/internal_options.conf),
these options govern internal logs. The
[4.7.5 rotation implementation](https://github.com/wazuh/wazuh/blob/v4.7.5/src/monitord/rotate_log.c)
rotates `ossec.log` and `ossec.json` into `logs/wazuh` and prunes that tree;
`keep_log_days` does **not** remove generated alert archives. Wazuh's own internal
retention threshold includes an additional day, so do not interpret it as exactly
168 hours. The size setting triggers rotation; it is not a filesystem quota.

## Conservative generated-alert cleanup

The helper's CLI is pinned to `/var/ossec/logs/alerts`; it accepts no path
argument. It does not access indexer data, agent databases, credentials, logs
outside that tree, or log contents. It walks exactly `YYYY/Mon`, with English
month names, and recognizes only these Wazuh-generated names:

- `ossec-alerts-DD.json.gz` and `ossec-alerts-DD.log.gz`;
- the same names with a positive, minimum-three-digit rotation suffix such as
  `-001` before `.json.gz` or `.log.gz`;
- unnumbered `ossec-alerts-DD.json.sum` and `ossec-alerts-DD.log.sum`.

The exact paths and suffixes follow the official
[4.7.5 archive management](https://github.com/wazuh/wazuh/blob/v4.7.5/src/monitord/manage_files.c)
and [checksum generation](https://github.com/wazuh/wazuh/blob/v4.7.5/src/monitord/sign_log.c).
The helper keeps the current local calendar day and the previous seven days.
Only artifacts with an earlier valid filename date **and** a modification time
before the cutoff's local midnight qualify. Thus a file dated October 26 is kept
on November 2, while an untouched October 25 file qualifies. This deliberately
retains more than seven days at the boundary.

Active `alerts.json` / `alerts.log`, all uncompressed alert logs, arbitrary names,
invalid dates, symlinks, and multiply linked files remain untouched. Directory
traversal uses pinned directory descriptors and refuses symlink ancestors.
Apply rechecks the name, date, regular-file status, link count, device, inode,
size, modification time, and change time against the plan. Replaced or modified
candidates are skipped. No directories are removed. Trusted root ownership and
normal Wazuh rotation behavior remain assumptions; this is not protection
against a hostile root process concurrently mutating directories.

Removing old checksum files discards the old full integrity chain along with
retired alerts. Remaining checksum files still contain hashes of their previous
checksum, but the deleted source cannot later be reverified.

## Role interface and operation

Run this role only against the intended existing central host with verified
access. The three inputs accept actual YAML booleans:

```yaml
monitoring_access_verified: true
monitoring_deployment_approved: true
monitoring_wazuh_storage_cleanup_approved: false
```

Both access and deployment gates default to false. Cleanup approval defaults to
false: rotation is configured and a cleanup plan is calculated, with no archive
deletion. The registered `monitoring_wazuh_storage_plan.stdout` is JSON with a
`plan` list and `changed: false`. It contains filenames/metadata, never event
contents; treat it as private operational data. The task suppresses its output.

Review the dry-run directly on the host, as root:

```sh
/usr/bin/python3 /usr/local/sbin/home-lab-wazuh-storage.py cleanup
```

For a separately reviewed one-time cleanup, feed JSON on stdin to
`cleanup --apply-reviewed-plan`, in the shape
`{"apply_approved": true, "plan": [...]}` using the exact plan list. Omitted,
false, numeric, or string approval is rejected. The role itself performs this
plan/apply sequence only when
`monitoring_wazuh_storage_cleanup_approved: true`. That approval also installs
a root-owned `home-lab-wazuh-storage.timer` for 03:35 local time daily, with a
persistent missed-run catch-up. Each scheduled run generates a fresh plan before
applying the approved policy. The root-only helper is installed at
`/usr/local/sbin/home-lab-wazuh-storage.py`; the systemd service has write access
only to the alert tree and does not retain success output in journald.

Setting cleanup approval back to false disables and removes this timer and
service. Already deleted data cannot be restored by changing that boolean.
Ansible `--check` previews role file/config changes; first-install cleanup
planning is skipped in check mode because the remote helper may not exist yet.
No script or live host is run during offline tests:

```sh
/Users/umarfaruq/.config/home-lab/monitoring/venv/bin/python -m unittest discover -s ansible/tests -p test_wazuh_storage.py
```

## Limits

Time-based retention is **not a hard disk cap**. Ingestion can fill a filesystem
within a day; internal rotation can overshoot its trigger; compressed alerts,
active/uncompressed files, Filebeat state/logs, system logs, indexer translogs,
other index families, and unrelated data consume additional space. Uncompressed
historical alerts intentionally require separate investigation if compression
was disabled or rotation failed. Index deletion remains asynchronous under the
separate seven-day ISM policy. Keep filesystem-usage monitoring and investigate
failed timer/rotation runs; no paid disk, snapshot, or cloud fallback is added.
