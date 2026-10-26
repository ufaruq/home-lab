output "fleet_coverage" {
  description = "Every VM, its resource address or explicit XenAPI ownership, and exact captured configuration."
  value = {
    for id, vm in local.fleet : id => {
      name  = vm.name_label
      owner = length(vm.disks) == 0 ? "ansible_xenapi" : "terraform"
      resource_address = length(vm.disks) == 0 ? null : (
        contains(keys(local.protected_vms), id) ? "xenorchestra_vm.protected[\"${id}\"]" : "xenorchestra_vm.existing[\"${id}\"]"
      )
      reason = length(vm.disks) == 0 ? "Provider 0.41.2 requires at least one disk block; preserve this diskless VM through Ansible/XenAPI without adding a disk." : (
        contains(keys(local.protected_vms), id) ? "Imported VM; all nested disk changes ignored to protect existing raw-device passthrough." : "Converge captured configuration and declared overrides; missing VM requires verified recovery."
      )
      configuration          = vm
      observed_configuration = local.observed_fleet[id]
      xenapi_configuration   = local.snapshot.vms[id]
    }
  }
}

output "adoption_targets" {
  description = "Contract for the plan gate: stable resource address -> original logical UUID; runtime import identities are separate."
  value = merge(
    { for id in keys(local.existing_vms) : "xenorchestra_vm.existing[\"${id}\"]" => id },
    { for id in keys(local.protected_vms) : "xenorchestra_vm.protected[\"${id}\"]" => id },
    { for id in keys(local.existing_networks) : "xenorchestra_network.existing[\"${id}\"]" => id }
  )
}

output "network_coverage" {
  description = "All supplied networks; host-internal management remains under XenAPI ownership."
  value = {
    for id, network in local.networks : id => merge(network, {
      owner            = network.host_internal ? "xenapi" : "terraform"
      resource_address = network.host_internal ? null : "xenorchestra_network.existing[\"${id}\"]"
    })
  }
}

output "storage_repositories" {
  description = "All existing SRs referenced by UUID. No SR, filesystem, image upload, or raw disk is created."
  value       = local.snapshot.storage_repositories
}

output "preservation_notes" {
  value = {
    snapshot    = var.inventory_file
    captured_at = local.snapshot.captured_at
    template    = "Current template selected by exact base_template_name match; ignore_changes preserves imported provenance. Original template UUID is unknown."
    provider_limits = [
      "No separate static RAM bounds or CPU maximum management. Any provider VM update sends static RAM maximum equal to dynamic maximum.",
      "CPU cap/weight and host schema attributes are unused by provider implementation.",
      "Platform flags, boot order, PCI/USB/vGPU, disk mode/bootable flags, VIF locking/QoS, snapshots and host configuration remain in the source snapshot under XenAPI ownership.",
      "XO CloudConfigDrive is omitted from VM disk blocks because provider read always filters that exact name; it remains in configuration.externally_preserved.original_disks.",
      "Empty CD drives remain in source inventory; provider cdrom blocks describe inserted media only.",
      "Attachment differences are suppressed by provider unless the VM is stably Running.",
      "Network NBD is mapped from captured purpose; host/PIF addressing remains under XenAPI ownership."
    ]
  }
}

output "xenapi_infrastructure" {
  description = "Captured infrastructure outside this provider root's ownership; source values are retained for Ansible/XenAPI reconciliation, not recreated."
  value = {
    hosts     = local.snapshot.hosts
    pools     = local.snapshot.pools
    pifs      = local.snapshot.pifs
    pbds      = local.snapshot.pbds
    pcis      = local.snapshot.pcis
    bonds     = local.snapshot.bonds
    snapshots = local.snapshot.snapshots
    templates = local.snapshot.templates
  }
}

output "ownership_targets" {
  description = "Stable logical ownership contract; original UUIDs persist after verified recovery."
  value = merge(
    { for id in keys(local.existing_vms) : "xenorchestra_vm.existing[\"${id}\"]" => id },
    { for id in keys(local.protected_vms) : "xenorchestra_vm.protected[\"${id}\"]" => id },
    { for id in keys(local.existing_networks) : "xenorchestra_network.existing[\"${id}\"]" => id }
  )
}

output "discovered_import_targets" {
  description = "Current discovered remote UUIDs for objects being imported; missing objects are absent."
  value = merge(
    { for id in keys(local.existing_vms) : "xenorchestra_vm.existing[\"${id}\"]" => local.current_vm_ids[id] if contains(keys(local.current_vm_ids), id) },
    { for id in keys(local.protected_vms) : "xenorchestra_vm.protected[\"${id}\"]" => local.current_vm_ids[id] if contains(keys(local.current_vm_ids), id) },
    { for id in keys(local.existing_networks) : "xenorchestra_network.existing[\"${id}\"]" => local.current_network_ids[id] if contains(keys(local.current_network_ids), id) }
  )
}
