# XCP-ng versus Proxmox VE

## What the names mean

**Xen** is a hypervisor: software that partitions and controls access to a machine's CPU and memory so multiple guest operating systems can run in isolation.

**XCP-ng** is a virtualization platform built around Xen, the XAPI management toolstack, and a privileged Linux control domain. **XenServer** is a related commercial product. They share history and technologies, but release, support, and management details must be checked for the actual product.

**Xen Orchestra (XO)** is a management and backup system for XCP-ng and XenServer. It can manage multiple hosts and pools. Its source is open; running it from source and using a packaged, supported appliance have different maintenance implications.

**Proxmox VE** is a Debian-based virtualization management platform. It integrates QEMU/KVM for full virtual machines and LXC for Linux containers, with web-based management of hosts, networking, storage, and related operations.

Both ecosystems have substantial open-source projects behind them. Familiarity or popularity in a particular community does not establish technical superiority.

Sources: [XCP-ng overview](https://docs.xcp-ng.org/), [Xen Orchestra overview](https://docs.xen-orchestra.com/), [XO from source](https://docs.xen-orchestra.com/category/getting-started), [Proxmox overview](https://proxmox.com/en/products/proxmox-virtual-environment/overview).

## CPU virtualization: both use the real processor

For a typical modern hardware-assisted VM, ordinary guest instructions execute on the physical processor. Intel VT-x or AMD-V provides controlled guest execution; the hypervisor handles events requiring intervention. This is different from interpreting every guest instruction in software.

Hardware support also accelerates translation between guest memory addresses and physical memory. The guest sees its own memory layout while the host controls the backing memory and isolation boundaries.

Neither platform dedicates a physical core to each virtual CPU by default. Virtual CPUs are scheduled onto physical processors. Contention, configuration, and workload matter when allocating more virtual CPUs than the host can run simultaneously.

Sources: [Xen virtualization concepts](https://handbook.xenproject.org/users/concepts.html), [Linux KVM API](https://docs.kernel.org/virt/kvm/api.html).

## How Xen organizes the machine

A simplified XCP-ng arrangement is:

~~~text
Physical hardware
  Xen hypervisor
    Privileged Linux control domain: drivers, toolstack, storage backends
    Guest VM 1
    Guest VM 2
~~~

Xen boots below the control domain and guests. Its core handles important CPU scheduling, memory, and isolation responsibilities. The privileged control domain, often called dom0, runs management services and supplies much of the physical device access.

The small Xen hypervisor does not eliminate Linux or supporting software. Hardware-virtualized Xen guests can also use QEMU for device emulation; Xen-aware guest drivers provide efficient device paths. Device passthrough changes the path for the assigned device.

A small, separately structured hypervisor is a real architectural property. It does not mean the complete privileged system is equally small: control-domain drivers and services still affect operation and security.

Sources: [Xen architecture](https://handbook.xenproject.org/users/introduction.html), [XCP-ng architecture](https://docs.xcp-ng.org/project/architecture/).

## Exactly what QEMU and KVM do

A simplified Proxmox full-VM arrangement is:

~~~text
Physical hardware
  Linux kernel, including KVM
    QEMU process for VM 1
    QEMU process for VM 2
    Host management services
~~~

Consider a VM configured with two virtual CPUs, 4 GB of RAM, and a virtual disk:

1. Proxmox starts and manages QEMU with that VM's configuration.
2. QEMU constructs the machine environment: firmware, virtual motherboard, device models, disk backends, and memory arrangements.
3. QEMU uses the Linux KVM interface to create the VM execution environment, register guest memory, and create virtual CPUs.
4. Virtual CPUs normally have corresponding host threads. Linux schedules those threads on physical cores.
5. QEMU asks KVM to run a virtual CPU. KVM configures the processor's virtualization state and enters guest execution.
6. Guest instructions execute on the CPU. Events requiring intervention return control to KVM.
7. KVM handles many events inside the kernel. Events requiring a userspace device implementation return to QEMU; after handling them, execution can resume.

**KVM is not a separate desktop application.** It is virtualization machinery inside the Linux kernel. **QEMU is not merely a launcher that exits after startup.** It remains involved in the machine's lifecycle, devices, storage backends, and other functionality.

QEMU can also emulate CPUs in software without KVM, including some cross-architecture scenarios. That is a different execution mode from the normal hardware-accelerated QEMU/KVM setup being compared here.

Sources: [KVM API](https://docs.kernel.org/virt/kvm/api.html), [QEMU architecture and accelerators](https://www.qemu.org/docs/master/system/introduction.html).

## Device access and the two sets of drivers

A guest operating system has drivers for the devices presented to it. The host has drivers for the actual hardware. Those are different responsibilities.

For example, a guest VirtIO storage driver can place a request in a shared-memory queue. The host-side backend processes it and submits I/O to a host filesystem or block device. The host Linux storage driver ultimately communicates with the physical controller. Completion is reported back to the guest.

VirtIO avoids the need to imitate every behavior of a historical physical device. Xen has analogous frontend/backend driver arrangements. Some accelerated paths use kernel or separate-process backends, so not every I/O operation must traverse the main QEMU event loop.

This is why correct guest drivers and storage configuration can matter more than the hypervisor label.

Sources: [QEMU virtual devices](https://www.qemu.org/docs/master/system/device-emulation.html), [XCP-ng device architecture](https://docs.xcp-ng.org/project/architecture/).

## Is Xen lighter, faster, or safer?

| Question | Useful answer |
| --- | --- |
| Is Xen's core smaller than a general-purpose Linux kernel? | Yes, but compare complete systems, including control domains, drivers, and management tools. |
| Does KVM introduce a software interpreter for every instruction? | No. Guest CPU instructions normally execute using hardware virtualization. |
| Does a smaller core guarantee lower overall overhead? | No. Host memory allocations, device paths, storage, scheduling, and workloads determine practical overhead. |
| Does either architecture guarantee better security? | No. Architectural boundaries matter, but so do privileged supporting components, configuration, vulnerabilities, and patching. |
| Which will be faster for this lab? | That requires representative workload measurements on the actual hardware and intended storage layout. |

KVM benefits from Linux's scheduler, memory management, drivers, and development ecosystem. Xen offers a separate hypervisor with explicit domain boundaries. These are meaningful design choices, not a simple good-versus-bad ranking.

## Practical platform tradeoffs

| Topic | Proxmox VE | XCP-ng with Xen Orchestra |
| --- | --- | --- |
| Initial management experience | Integrated web interface for VMs, LXC, storage, and networking | XCP-ng host management plus XO for a fuller centralized management and backup experience |
| Containers | Integrated LXC alongside VMs | Commonly run application/container workloads inside VMs |
| Host foundation | Debian-based | Specialized Xen platform with a privileged Linux control domain |
| Infrastructure automation | Community providers, including bpg/proxmox | Official Xen Orchestra Terraform provider |
| Multiple hosts | Clusters and shared management | XO manages multiple hosts and pools |
| Reasons to stay | Familiar interface and integrated storage choices if already adopted | Avoids migration and preserves existing Xen-based workflows |
| Migration cost | Existing XCP-ng VMs and hardware assignments require migration or rebuilding | Staying still requires maintenance and supported-release upgrades |

The Proxmox recommendation for a fresh homelab is a judgment about convenience and integrated features. It is not evidence of a universal performance advantage or a quantified popularity claim.

Sources: [Proxmox features](https://proxmox.com/en/products/proxmox-virtual-environment/features), [bpg/proxmox](https://registry.terraform.io/providers/bpg/proxmox/latest/docs), [XO Terraform provider](https://docs.xen-orchestra.com/automation/terraform-provider).

## Multiple hosts: management is not automatic failover

Managing several servers from one interface is distinct from restarting VMs automatically after a host fails. The latter needs an appropriate availability design, including quorum/fencing behavior, accessible storage or replication, networking, and spare capacity.

Do not select either platform solely because more hosts may be added. Decide whether the goal is a shared interface, live migration, planned maintenance with less downtime, or failure recovery. These are different requirements.

## GPU and controller passthrough

Both ecosystems support forms of PCI device passthrough. The CPU/chipset's IOMMU support, device grouping, firmware, and reset behavior affect whether a particular GPU or controller works reliably.

Passing a GPU to a guest generally gives that guest ownership of it while assigned. It does not imply that the host and other guests can all use it simultaneously. Passthrough can also restrict migration and recovery options. A working arrangement on one platform is not proof that migration will preserve every detail automatically.

For storage-controller passthrough, the guest can manage physical disks more directly, but the host may no longer have normal access to those disks. Plan which system owns them before changing the layout.
