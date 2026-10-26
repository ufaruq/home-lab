# Runtime discovery adopts existing objects; missing VMs require verified recovery.
# ignore_changes(template) preserves imported provenance; creation uses the recovery template.
resource "xenorchestra_vm" "existing" {
  for_each = local.existing_vms

  name_label         = each.value.name_label
  name_description   = each.value.name_description
  cpus               = each.value.cpus
  memory_min         = each.value.memory_min
  memory_max         = each.value.memory_max
  power_state        = each.value.power_state
  auto_poweron       = each.value.auto_poweron
  hvm_boot_firmware  = each.value.hvm_boot_firmware
  secure_boot        = each.value.secure_boot
  exp_nested_hvm     = each.value.exp_nested_hvm
  cores_per_socket   = each.value.cores_per_socket
  high_availability  = each.value.high_availability
  affinity_host      = each.value.affinity_host
  start_delay        = each.value.start_delay
  vga                = each.value.vga
  videoram           = each.value.videoram
  tags               = each.value.tags
  blocked_operations = each.value.blocked_operations
  template           = each.value.template_uuid

  dynamic "network" {
    for_each = each.value.networks
    content {
      network_id  = try(xenorchestra_network.existing[network.value.network_id].id, local.current_network_ids[network.value.network_id], network.value.network_id)
      mac_address = network.value.mac_address
      attached    = network.value.attached
    }
  }
  dynamic "disk" {
    for_each = each.value.disks
    content {
      sr_id            = disk.value.sr_id
      name_label       = disk.value.name_label
      name_description = disk.value.name_description
      size             = disk.value.size
      attached         = disk.value.attached
    }
  }
  dynamic "cdrom" {
    for_each = each.value.cdroms
    content {
      id = cdrom.value
    }
  }
  lifecycle {
    prevent_destroy = true
    # These five defaults are not populated by provider Read on import. They
    # describe creation, unused CPU fields or resource-set sharing, none of
    # which is managed by this root. Legacy absent firmware reads as "", which
    # the provider cannot accept in config (only bios/uefi), so preserve it too.
    ignore_changes = [template, clone_type, core_os, cpu_cap, cpu_weight, share, hvm_boot_firmware]
    precondition {
      condition = contains(keys(local.current_vm_ids), each.key) || (
        each.value.recovery_verified && can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", each.value.recovery_template_id))
      )
      error_message = "Missing VM requires an operator-verified recovery template in desired-state.json. An OS-template candidate is insufficient."
    }
  }
}

resource "xenorchestra_vm" "protected" {
  for_each = local.protected_vms

  name_label         = each.value.name_label
  name_description   = each.value.name_description
  cpus               = each.value.cpus
  memory_min         = each.value.memory_min
  memory_max         = each.value.memory_max
  power_state        = each.value.power_state
  auto_poweron       = each.value.auto_poweron
  hvm_boot_firmware  = each.value.hvm_boot_firmware
  secure_boot        = each.value.secure_boot
  exp_nested_hvm     = each.value.exp_nested_hvm
  cores_per_socket   = each.value.cores_per_socket
  high_availability  = each.value.high_availability
  affinity_host      = each.value.affinity_host
  start_delay        = each.value.start_delay
  vga                = each.value.vga
  videoram           = each.value.videoram
  tags               = each.value.tags
  blocked_operations = each.value.blocked_operations
  template           = each.value.template_uuid

  dynamic "network" {
    for_each = each.value.networks
    content {
      network_id  = try(xenorchestra_network.existing[network.value.network_id].id, local.current_network_ids[network.value.network_id], network.value.network_id)
      mac_address = network.value.mac_address
      attached    = network.value.attached
    }
  }
  dynamic "disk" {
    for_each = each.value.disks
    content {
      sr_id            = disk.value.sr_id
      name_label       = disk.value.name_label
      name_description = disk.value.name_description
      size             = disk.value.size
      attached         = disk.value.attached
    }
  }
  dynamic "cdrom" {
    for_each = each.value.cdroms
    content {
      id = cdrom.value
    }
  }
  lifecycle {
    prevent_destroy = true
    # Read omits the same creation-only/unused defaults as for ordinary VMs.
    # Preserve legacy firmware representation and protect nested raw storage.
    ignore_changes = [template, disk, clone_type, core_os, cpu_cap, cpu_weight, share, hvm_boot_firmware]
    precondition {
      condition     = contains(keys(local.current_vm_ids), each.key)
      error_message = "Raw-device storage forbids automated VM recreation; recover its original VM and disk mapping explicitly."
    }
  }
}
