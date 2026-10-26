# Home lab platform and configuration guide

Comparison notes consolidated from our discussion, checked against the linked upstream documentation on October 25, 2026. This is a reference and decision guide, not an inventory of a verified installation or an executed migration plan.

## Read in this order

1. [XCP-ng versus Proxmox: architecture and practical tradeoffs](virtualization-comparison.md)
2. [VM disks, storage backends, and snapshots explained](storage-comparison.md)
3. [Making the lab reproducible before an upgrade or migration](reproducible-home-lab.md)

The observed installation is now documented under [Xen server inventory and recovery notes](../xen-server/README.md), including hardware, VM definitions, network and storage metadata, and the incomplete-boot investigation. Those observations are separate from the comparison and design guidance below.

## Recommendation in plain language

For a fresh homelab, Proxmox VE is an attractive default when you want integrated VM, container, networking, and storage management with a Debian foundation. This is a usability recommendation, not a claim that KVM is intrinsically faster or safer than Xen.

Keeping XCP-ng and using Xen Orchestra is also reasonable, particularly when avoiding migration and centrally managing VMs are the main priorities. Both platforms support multiple hosts. Adding hosts does not automatically decide the choice; shared management, storage, availability requirements, and hardware compatibility matter more.

For either platform, a useful division of responsibilities is:

- Terraform/OpenTofu: supported VM and infrastructure resources.
- Cloud-init: initial machine identity and access.
- Ansible: applications, services, and operating-system configuration.
- Backups or reproducible images: any remaining state that configuration code cannot reconstruct.

Inventory applications and their configuration before investing heavily in a hypervisor-specific Terraform provider. Configuration-management work can often survive a platform change; provider-specific VM definitions usually need adaptation.

## Important distinctions

- XCP-ng, Xen, and commercial XenServer are related but are not interchangeable product names.
- Proxmox VE is a management platform; KVM is its full-VM virtualization engine, and QEMU constructs and supplies the virtual machine environment.
- A VDI is an XCP-ng managed virtual-disk object, not a disk-image format.
- ext4, ZFS, LVM, and VHD are not four equivalent filesystems. They operate at different layers.
- An infrastructure repository is not automatically a backup of VM disks, credentials, application databases, or undocumented configuration.
- Instructions and examples here do not imply that any host has been upgraded or reconfigured.
