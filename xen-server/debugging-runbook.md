# Debugging runbook

Start with read-only evidence and a precise failing layer. Keep output local and private: inventories, logs, command results and screenshots can reveal identities, addresses and secrets.

## Controller and access

```sh
make check
make readiness
ssh -o BatchMode=yes <configured-host-alias> true
```

Verify the selected private inventory/policy, executable paths, pinned host key and authentication mode. Separate host SSH reachability from management API authentication. Do not solve authentication failures by disabling host-key checks, exposing a public listener or resetting unrelated accounts.

## Host, network and management

Through already authorized host access, read the relevant state:

```sh
xe host-list
xe pool-list
xe vm-list is-control-domain=false
xe sr-list
xe task-list
ip -brief address
ip route
systemctl --failed
journalctl -b -p warning
```

Store results in ignored private evidence. Confirm physical links, VLAN ownership, route/DNS selection and duplicate addresses before a network change. Keep an independent recovery path. Service state alone does not prove API authentication or guest health.

## Storage and boot

Read kernel/storage logs and filesystem space/inode usage before repair. A reassuring health summary does not invalidate observed I/O timeouts. Avoid stress tests or aggressive retries on a failing path; preserve data on known-good storage first.

For a supported guest-disk inspection, verify its live VBD/VDI identity and power state. Use a native read-only presentation and an isolated inspection appliance. Never mount an untrusted guest filesystem in the control domain or activate guest volume groups there. Unsupported/encrypted filesystems are blockers to record, not evidence that a disk is empty.

Filesystem repair requires a separate authorization, an unmounted target and a verified independent backup. Rehearse on a disposable clone first. A successful repair check proves a limited filesystem-consistency result, not intact application semantics. Remove temporary presentations before starting a guest.

## Convergence failures

Inspect the exact saved plan and guard refusal. Do not weaken identity, disk, firmware or recovery guards to make a plan pass. Compare declared ownership, current private state and live identities. Preserve failed-operation evidence and check native tasks before retrying.

After a change, repeat the relevant read-only check and document its limits privately. Do not publish raw logs, screenshots, tokens, password material or private application configuration.
