# Invented offline examples

Every record here was authored from scratch for tests. This is not a redacted or pseudonymized copy of an installation. The seven small guest definitions, fake users/packages, artificial UUIDs and hashes, locally administered MACs, and TEST-NET addresses contain no captured host or guest data.

`inventory.json` exercises an automatic management appliance, Linux with cloud-config media, a diskless definition, legacy absent firmware, explicit UEFI, raw passthrough storage, and observed-only BSD. Networks include physical, isolated, host-internal and tagged examples. Tiny `guest-inventory/` manifests test structured observation and provenance; they are not backups or deployable images.

`ansible/` is generated from these fixtures. Live operators must provide their own ignored local inventory, policy, guest observations, native recovery hashes and connection settings. Do not use fixture policies against a real host.
