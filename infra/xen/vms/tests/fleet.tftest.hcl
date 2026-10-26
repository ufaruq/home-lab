# Entirely synthetic source; mocked provider makes no live API calls.
mock_provider "xenorchestra" {}
override_resource { target = xenorchestra_vm.existing }
override_resource { target = xenorchestra_vm.protected }
override_resource { target = xenorchestra_network.existing }

variables {
  inventory_file     = "../../../tests/fixtures/xen/inventory.json"
  desired_state_file = "../../../tests/fixtures/xen/policy.json"
}

run "synthetic_fleet_coverage" {
  command = plan
  override_resource {
    target = xenorchestra_vm.existing["00000000-0000-4000-8000-000000000004"]
    values = { clone_type = null, core_os = null, cpu_cap = null, cpu_weight = null, share = null, hvm_boot_firmware = "" }
  }
  assert {
    condition     = length(output.fleet_coverage) == 7 && length(output.adoption_targets) == 10
    error_message = "Seven invented guests: six Terraform VMs, one native diskless definition, four managed networks."
  }
  assert {
    condition     = output.fleet_coverage["00000000-0000-4000-8000-000000000003"].owner == "ansible_xenapi" && output.fleet_coverage["00000000-0000-4000-8000-000000000003"].resource_address == null
    error_message = "Diskless fixture must not gain an invented provider disk."
  }
  assert {
    condition     = length(xenorchestra_vm.existing["00000000-0000-4000-8000-000000000002"].disk) == 1 && length(output.fleet_coverage["00000000-0000-4000-8000-000000000002"].configuration.externally_preserved.original_disks) == 2
    error_message = "Provider-filtered cloud-config media stays in evidence but not managed disk blocks."
  }
  assert {
    condition     = output.fleet_coverage["00000000-0000-4000-8000-000000000004"].observed_configuration.hvm_boot_firmware_observed == null && output.fleet_coverage["00000000-0000-4000-8000-000000000005"].observed_configuration.hvm_boot_firmware_observed == "uefi" && xenorchestra_vm.existing["00000000-0000-4000-8000-000000000005"].secure_boot
    error_message = "Absent legacy firmware must remain distinguishable from explicit UEFI."
  }
  assert {
    condition     = output.fleet_coverage["00000000-0000-4000-8000-000000000006"].configuration.disks[1].size == 17179873280 && startswith(output.fleet_coverage["00000000-0000-4000-8000-000000000006"].resource_address, "xenorchestra_vm.protected")
    error_message = "Raw storage type, not a guest name, determines provider protection and preserves exact bytes."
  }
  assert {
    condition     = output.network_coverage["10000000-0000-4000-8000-000000000001"].vlan == -1 && xenorchestra_network.existing["10000000-0000-4000-8000-000000000002"].source_pif_device == "" && output.network_coverage["10000000-0000-4000-8000-000000000003"].owner == "xenapi"
    error_message = "Preserve physical untagged, isolated and host-internal topology."
  }
  assert {
    condition     = xenorchestra_vm.existing["00000000-0000-4000-8000-000000000001"].network[0].mac_address == "02:00:00:00:01:00" && xenorchestra_vm.existing["00000000-0000-4000-8000-000000000005"].cdrom[0].id == "80000000-0000-4000-8000-000000000001"
    error_message = "Synthetic MAC and inserted media identities must reach provider arguments."
  }
}

run "missing_unverified_vms_are_blocked" {
  command = plan
  variables { existing_vm_ids = {} }
  expect_failures = [xenorchestra_vm.existing, xenorchestra_vm.protected]
}

run "verified_recovery_and_discovered_identity" {
  command = plan
  variables {
    desired_state_file = "tests/fixtures/recovery.json"
    existing_vm_ids = {
      "00000000-0000-4000-8000-000000000001" = "00000000-0000-4000-8000-000000000001"
      "00000000-0000-4000-8000-000000000004" = "00000000-0000-4000-8000-000000000004"
      "00000000-0000-4000-8000-000000000005" = "00000000-0000-4000-8000-000000000005"
      "00000000-0000-4000-8000-000000000006" = "00000000-0000-4000-8000-000000000006"
      "00000000-0000-4000-8000-000000000007" = "00000000-0000-4000-8000-000000000007"
    }
    existing_network_ids = {
      "10000000-0000-4000-8000-000000000001" = "10000000-0000-4000-8000-000000000001"
      "10000000-0000-4000-8000-000000000002" = "10000000-0000-4000-8000-000000000002"
      "10000000-0000-4000-8000-000000000004" = "10000000-0000-4000-8000-000000000099"
    }
  }
  assert {
    condition     = xenorchestra_vm.existing["00000000-0000-4000-8000-000000000002"].cpus == 3 && xenorchestra_vm.existing["00000000-0000-4000-8000-000000000002"].memory_max == 3221225472 && xenorchestra_vm.existing["00000000-0000-4000-8000-000000000002"].template == "40000000-0000-4000-8000-000000000004"
    error_message = "Only verified recovery policy may choose a replacement template and hardware."
  }
  assert {
    condition     = !contains(keys(output.discovered_import_targets), "xenorchestra_vm.existing[\"00000000-0000-4000-8000-000000000002\"]") && output.discovered_import_targets["xenorchestra_network.existing[\"10000000-0000-4000-8000-000000000004\"]"] == "10000000-0000-4000-8000-000000000099"
    error_message = "Missing objects skip import; replacement identities do not rewrite logical ownership."
  }
  assert {
    condition     = alltrue([for disk in xenorchestra_vm.existing["00000000-0000-4000-8000-000000000002"].disk : disk.attached]) && alltrue([for network in xenorchestra_vm.existing["00000000-0000-4000-8000-000000000002"].network : network.attached])
    error_message = "Declared starts must attach previously halted fixture disks and NICs."
  }
}

run "only_declared_appliance_is_automatic" {
  command = plan
  variables { desired_state_file = "tests/fixtures/xoa-only-auto-poweron.json" }
  assert {
    condition     = alltrue([for id, vm in output.fleet_coverage : vm.configuration.auto_poweron == (id == "00000000-0000-4000-8000-000000000001")])
    error_message = "Only the explicitly selected synthetic appliance may be automatic."
  }
}
