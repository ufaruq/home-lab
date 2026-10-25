# VM disks, filesystems, volumes, and snapshots

## Start with the layers

These names do not all describe competing filesystems:

| Name | What it describes |
| --- | --- |
| ext4 | A filesystem that organizes files and directories |
| LVM | A volume manager that allocates logical block devices |
| LVM-thin | LVM thin-pool allocation and snapshot machinery |
| ZFS | Integrated storage-pool, filesystem, and block-volume facilities |
| VHD or QCOW2 | Virtual-disk image formats |
| VDI | An XCP-ng managed virtual-disk object, not a file format |
| SR | An XCP-ng storage repository holding VM disks or other designated content |
| VBD | The virtual block-device attachment linking a disk to a VM |

A filesystem can sit on a logical volume, and an image file can sit in that filesystem. A VM disk can instead be backed directly by a logical block volume. This is why ext4 and LVM are not necessarily mutually exclusive choices.

Source: [XCP-ng storage concepts and backends](https://docs.xcp-ng.org/storage/).

## From a guest write to a physical drive

~~~text
Application in guest
  Guest filesystem, such as ext4 or NTFS
    Guest storage driver and virtual controller
      Virtual disk backed by an image file OR block volume
        Host storage backend or remote storage service
          Physical drives and controller
~~~

The guest sees a disk interface, not necessarily the host's actual drive. A 100 GB guest disk does not imply a dedicated 100 GB physical partition. Its contents can be stored in a file, a logical volume, or another supported backend.

The filesystem inside the VM is independent of the host backend. For example, a Windows VM can use NTFS internally while its virtual disk is a file stored on the host's ext4 filesystem.

Sources: [XCP-ng architecture](https://docs.xcp-ng.org/project/architecture/), [Proxmox storage](https://github.com/proxmox/pve-docs/blob/master/pvesm.adoc).

## Thin versus thick allocation

Suppose a VM is given a 100 GB disk but has written only 10 GB:

- A thick-provisioned backend generally reserves the configured capacity up front.
- A thin-provisioned backend allocates physical space as writes require it. Actual usage also depends on metadata, snapshots, compression, discard handling, and other details.

Thin provisioning lets advertised VM capacity exceed currently allocated physical space. It does not create more physical capacity. Exhausting the backing pool can disrupt VMs, so monitor available space and leave appropriate headroom.

Deleting files inside the guest does not necessarily release their host-side allocation immediately. Discard/TRIM support must work through the layers, and snapshots may still retain the old blocks.

**Platform correction:** XCP-ng's standard Local LVM backend is thick-provisioned. It should not be casually described as the LVM-thin backend commonly offered by Proxmox. XCP-ng Local EXT is file-based and thin-provisioned.

Source: [XCP-ng storage types](https://docs.xcp-ng.org/storage/).

## What a VDI actually represents

A VDI is the disk XCP-ng tracks: its identity, virtual capacity, repository location, and associated metadata. The storage backend determines how its contents are represented.

A VBD is the attachment through which a VM uses that disk. An SR identifies the storage repository containing it. The VHD image file or underlying logical volume is the representation of the data; it is not interchangeable with the inventory object.

Distinguishing these explains why deleting a disk object, unplugging an attachment, and removing an underlying file are different operations. Manipulating backend files manually can break the management layer's view or a disk's parent relationships.

Sources: [XCP-ng glossary](https://docs.xcp-ng.org/appendix/glossary/), [SR and VDI management](https://docs.xcp-ng.org/storage/manage-srs/).

## Snapshot example: preserve the old block, write a new one

Consider a thin-provisioned VM disk containing about 20 GB of allocated data. Take a snapshot, then overwrite 1 GB of existing data with new contents.

The system must preserve the old contents for the snapshot while making the new contents visible to the running VM. It can share unchanged blocks rather than copying the entire virtual disk immediately. Ignoring metadata, compression, and allocation granularity, keeping both versions could require roughly 21 GB instead of 20 GB.

That example explains the space-saving principle. It is not a storage-capacity estimate for an actual deployment; backends differ, particularly thick-provisioned ones.

### VHD image chains in traditional XCP-ng storage

A simplified VHD-chain arrangement preserves a parent image and redirects new writes to a writable child. Reading a block may require checking the child, then a parent if the child has no newer version. Actual snapshot implementations can involve hidden base disks and multiple related objects; the essential property is shared parent data.

Removing a snapshot from the interface does not mean every underlying parent can immediately be deleted. A running disk may still depend on its contents. Coalescing merges necessary data and adjusts the relationships so the surviving disk remains complete. This can consume I/O, time, and working space.

Long chains and interrupted or constrained coalescing are therefore operational concerns. They are properties of that storage implementation, not proof that the Xen CPU hypervisor is slow.

Traditional VHD disks have a maximum size of 2040 GiB, just under 2 TiB. This is a format limit, not a fundamental Xen limit. Newer XCP-ng releases offer additional formats on supported backends; consult the release-specific documentation rather than assuming all XCP-ng storage has the old limit.

Source: [XCP-ng disk formats and coalescing operations](https://docs.xcp-ng.org/storage/manage-srs/).

### Proxmox with image files

Proxmox can store VM disks as files, including QCOW2. File-backed configurations can also involve copy-on-write and backing-image relationships. Choosing Proxmox does not inherently eliminate all image-chain behavior.

Raw image files do not supply the same built-in image-format snapshot facilities as QCOW2. What the platform can do also depends on the storage backend. Always identify both the backend and disk format before comparing features.

Source: [Proxmox storage documentation](https://github.com/proxmox/pve-docs/blob/master/pvesm.adoc).

### Proxmox with ZFS volumes

A VM disk can instead be a ZFS block volume. ZFS manages snapshots by preserving block references. When the live disk changes, new blocks can be written while snapshots retain references to the old ones.

Deleting a snapshot releases its references; blocks become reclaimable when nothing still references them. Other snapshots or clones can keep them allocated. There is no equivalent requirement to merge an external VHD image-file chain for that native ZFS snapshot, although metadata processing and space reclamation still require work.

ZFS also checksums data. It can detect corruption, and when an appropriate redundant good copy is available, it can repair certain corruption. Checksums alone do not supply a second copy. A single-drive pool does not acquire drive-failure resilience merely by using ZFS.

### Proxmox with LVM-thin

A VM disk can be a thin logical volume. Thin-pool metadata maps logical blocks to physical storage, and snapshots can share existing blocks while changes receive new allocations.

This avoids requiring a VHD/QCOW2 file chain for the native block-volume snapshot. It does not make LVM-thin equivalent to ZFS: LVM-thin does not by itself add ZFS-style end-to-end data checksumming, compression, or an integrated self-healing storage design. Pool data and metadata capacity both need monitoring.

Sources: [Proxmox LVM-thin implementation documentation](https://github.com/proxmox/pve-docs/blob/master/pve-storage-lvmthin.adoc), [Proxmox storage overview](https://github.com/proxmox/pve-docs/blob/master/pvesm.adoc).

## Pros and cons

| Choice | Advantages | Tradeoffs |
| --- | --- | --- |
| ext4 plus VM image files | Mature, straightforward file storage; generally modest additional resource requirements; practical thin provisioning with XCP-ng Local EXT | ext4 itself does not provide native filesystem snapshots or checksums of file contents; VM snapshot behavior belongs to the image/backend layer |
| Traditional LVM | Direct logical volumes and predictable reserved capacity | Thick allocation can reserve much more than a VM currently uses; XCP-ng warns about snapshot capacity costs on thick storage |
| LVM-thin | Efficient allocation, block-level snapshots, and standard Proxmox integration | Must monitor pool data and metadata; integrity and redundancy require other mechanisms |
| ZFS | Integrated pooling, snapshots, compression, checksums, and repair with appropriate redundant copies | More resource and layout considerations; prefers direct visibility of physical drives rather than a hardware RAID virtual disk |

ZFS cache consumes memory but is not the same thing as an unreclaimable memory leak. Size and tune the deployment for its workload rather than assuming that every installation needs a fixed, universal amount of RAM per terabyte.

A critical platform difference: Proxmox integrates ZFS and LVM-thin as standard storage options. XCP-ng officially supports Local EXT and Local LVM; its ZFS storage integration is provided without official support. Do not assume selecting a similarly named backend gives identical support or snapshot behavior across platforms.

Sources: [XCP-ng storage support matrix](https://docs.xcp-ng.org/storage/), [Proxmox ZFS documentation](https://github.com/proxmox/pve-docs/blob/master/local-zfs.adoc).

## Pooling, redundancy, snapshots, and backups are separate

- A pool supplies capacity from storage resources. Combining drives does not automatically add redundancy.
- Mirroring/RAID can help tolerate specified drive failures, depending on the layout.
- A snapshot retains an earlier state within the storage system. It may rely on the same devices and metadata as the live data.
- A separate backup supports recovery when the source storage or its metadata is lost.

For a configuration-focused lab, application databases and user files may be expendable. Still identify which state actually matters: SSH keys, certificates, application settings, boot parameters, and VM definitions are not necessarily recreated just because Terraform contains VM resource sizes.

## Choosing for a lab

- Keeping a healthy XCP-ng Local EXT setup is reasonable. Changing it is not automatically a performance improvement.
- On a fresh Proxmox installation, LVM-thin is a practical choice when you want straightforward local VM allocation and snapshots.
- ZFS is attractive when its integrity, compression, snapshot, or drive-management features are explicit goals. The drive/controller layout must fit it.
- A mirrored ZFS arrangement can be useful with suitable drives, but it is not the universal answer for every single-drive or hardware-RAID system.
- Shared storage and distributed storage introduce network, failure-domain, and operational requirements beyond this local-storage comparison.

Before selecting a layout, establish the actual drive count, usable capacities, controller mode, RAM, workload, and recovery requirements. Do not infer the host backend from the filesystem reported inside a guest VM.
