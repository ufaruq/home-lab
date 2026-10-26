locals {
  snapshot = jsondecode(file(var.inventory_file))
  pool_id  = one(keys(local.snapshot.pools))

  # UUID keys survive VM renames. Use numeric device order, not snapshot array order.
  observed_fleet = {
    for id, vm in local.snapshot.vms : id => {
      uuid              = id
      name_label        = vm.name_label
      name_description  = vm.name_description
      cpus              = tonumber(vm.VCPUs_at_startup)
      cpus_max_observed = tonumber(vm.VCPUs_max)
      memory_min        = tonumber(vm.memory_dynamic_min)
      memory_max        = tonumber(vm.memory_dynamic_max)
      memory_static_min = tonumber(vm.memory_static_min)
      memory_static_max = tonumber(vm.memory_static_max)
      power_state       = vm.power_state
      auto_poweron      = lower(try(vm.other_config.auto_poweron, "false")) == "true"
      # XO preserves an absent legacy HVM firmware key as an empty read value.
      # Retain that absence separately; bios is only the provider-valid creation fallback.
      hvm_boot_firmware          = try(vm.HVM_boot_params.firmware, "bios")
      hvm_boot_firmware_observed = try(vm.HVM_boot_params.firmware, null)
      secure_boot                = lower(try(vm.platform.secureboot, "false")) == "true"
      exp_nested_hvm             = lower(try(vm.platform["exp-nested-hvm"], "false")) == "true"
      cores_per_socket           = try(tonumber(vm.platform["cores-per-socket"]), null)
      high_availability          = vm.ha_restart_priority
      affinity_host              = vm.affinity_host_uuid
      start_delay                = tonumber(vm.start_delay)
      # Provider projection defaults for absent display platform keys.
      vga                 = try(vm.platform.vga, "cirrus")
      videoram            = try(tonumber(vm.platform.videoram), 4)
      tags                = vm.tags
      blocked_operations  = vm.blocked_operations
      base_template_name  = vm.other_config.base_template_name
      template_uuid       = one([for template in values(local.snapshot.templates) : template.uuid if template.name_label == vm.other_config.base_template_name])
      template_provenance = "Current template matched by observed base_template_name; original template UUID is not recorded. Adoption/rebuild candidate only."
      networks = values({
        for vif in vm.vifs : format("%08d", tonumber(vif.device)) => {
          network_id  = vif.network_uuid
          mac_address = lower(vif.MAC)
          attached    = vif.currently_attached
          device      = vif.device
          vif_uuid    = vif.uuid
        }
      })
      disks = values({
        for disk in vm.disks : format("%08d", tonumber(disk.userdevice)) => {
          sr_id            = disk.vdi.sr_uuid
          name_label       = disk.vdi.name_label
          name_description = disk.vdi.name_description
          size             = tonumber(disk.vdi.virtual_size)
          attached         = disk.currently_attached
          position         = disk.userdevice
          vbd_uuid         = disk.uuid
          vdi_uuid         = disk.vdi.uuid
        } if disk.vdi.name_label != "XO CloudConfigDrive"
      })
      cdroms = [for cd in vm.cdroms : cd.vdi.uuid if !cd.empty]
      externally_preserved = {
        platform          = vm.platform
        boot_parameters   = vm.HVM_boot_params
        static_memory     = [tonumber(vm.memory_static_min), tonumber(vm.memory_static_max)]
        cpu_maximum       = tonumber(vm.VCPUs_max)
        pci_uuids         = vm.attached_pci_uuids
        pci_configuration = try(vm.other_config.pci, null)
        vgpu_uuids        = vm.vgpu_uuids
        vusb_uuids        = vm.vusb_uuids
        original_disks    = vm.disks
        original_vifs     = vm.vifs
        original_cdroms   = vm.cdroms
      }
    }
  }
  desired_state_path  = var.desired_state_file
  desired_state       = jsondecode(file(local.desired_state_path))
  current_vm_ids      = var.existing_vm_ids == null ? { for id in keys(local.snapshot.vms) : id => id } : var.existing_vm_ids
  current_network_ids = var.existing_network_ids == null ? { for id in keys(local.snapshot.networks) : id => id } : var.existing_network_ids

  # Overrides change desired behavior, never the historical capture or logical keys.
  fleet = {
    for id, vm in local.observed_fleet : id => merge(vm, {
      cpus         = try(local.desired_state.vms[id].cpus, vm.cpus)
      memory_min   = try(local.desired_state.vms[id].memory_min, vm.memory_min)
      memory_max   = try(local.desired_state.vms[id].memory_max, vm.memory_max)
      power_state  = try(local.desired_state.vms[id].power_state, vm.power_state)
      auto_poweron = try(local.desired_state.vms[id].auto_poweron, vm.auto_poweron)
      blocked_operations = [
        for operation in vm.blocked_operations : operation
        if !(try(local.desired_state.vms[id].allow_graceful_shutdown, false) && contains(["clean_shutdown", "clean_reboot"], operation))
      ]
      recovery_verified    = try(local.desired_state.vms[id].recovery.verified == true, false)
      recovery_template_id = try(local.desired_state.vms[id].recovery.template_id, null)
      template_uuid        = try(local.desired_state.vms[id].recovery.verified == true, false) ? try(local.desired_state.vms[id].recovery.template_id, vm.template_uuid) : vm.template_uuid
      template_provenance  = try(local.desired_state.vms[id].recovery.verified == true, false) ? "Operator-declared verified recovery template; original template UUID remains unknown. Runner must verify template exists live before creation." : vm.template_provenance
      # Halted runtime attachments are false even when disks/NICs should attach at start.
      # Preserve intentional detachments captured on a Running VM.
      networks = [for network in vm.networks : merge(network, {
        attached = try(local.desired_state.vms[id].power_state, vm.power_state) == "Running" && vm.power_state != "Running" ? true : network.attached
      })]
      disks = [for disk in vm.disks : merge(disk, {
        attached = try(local.desired_state.vms[id].power_state, vm.power_state) == "Running" && vm.power_state != "Running" ? true : disk.attached
      })]
    })
  }

  diskless = { for id, vm in local.fleet : id => vm if length(vm.disks) == 0 }
  # Raw/passthrough protection follows storage type, never a private VM name.
  protected_vms = { for id, vm in local.fleet : id => vm if anytrue([
    for disk in vm.disks : contains(["udev", "raw"], local.snapshot.storage_repositories[disk.sr_id].type)
  ]) }
  existing_vms = { for id, vm in local.fleet : id => vm if length(vm.disks) > 0 && !contains(keys(local.protected_vms), id) }

  networks = {
    for id, network in local.snapshot.networks : id => {
      uuid              = id
      name_label        = network.name_label
      name_description  = network.name_description
      mtu               = tonumber(network.MTU)
      automatic         = lower(try(network.other_config.automatic, "false")) == "true"
      default_is_locked = network.default_locking_mode == "locked"
      nbd               = contains(network.purpose, "nbd") || contains(network.purpose, "insecure_nbd")
      host_internal     = lower(try(network.other_config.is_host_internal_management_network, "false")) == "true"
      pifs              = [for pif in values(local.snapshot.pifs) : pif if pif.network_uuid == id]
      vlan              = coalesce(try(tonumber(one([for pif in values(local.snapshot.pifs) : pif.VLAN if pif.network_uuid == id])), null), 0)
      source_pif_device = join("", [for pif in values(local.snapshot.pifs) : pif.device if pif.network_uuid == id])
    }
  }
  existing_networks = { for id, network in local.networks : id => network if !network.host_internal }
}
