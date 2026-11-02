mock_provider "oci" {
  mock_data "oci_core_image" {
    defaults = {
      operating_system         = "Canonical Ubuntu"
      operating_system_version = "22.04"
      display_name             = "Canonical-Ubuntu-22.04-aarch64-test"
      state                    = "AVAILABLE"
    }
  }
}

variables {
  tenancy_ocid        = "ocid1.tenancy.oc1..test"
  compartment_ocid    = "ocid1.compartment.oc1..test"
  availability_domain = "TEST:US-SANJOSE-1-AD-1"
  image_ocid          = "ocid1.image.oc1.us-sanjose-1.test"
  ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleForOfflineTestsOnly fixture"
  audit = {
    free_account_verified = true
    capacity_available    = true
    existing_storage_gb   = 60
    other_a1_cores        = 0
    other_a1_memory_gb    = 0
    audited_at            = timestamp()
  }
}

run "fixed_free_size_and_no_public_application_access" {
  command = plan
  assert {
    condition     = oci_core_instance.wazuh.shape == "VM.Standard.A1.Flex" && oci_core_instance.wazuh.shape_config[0].ocpus == 2 && oci_core_instance.wazuh.shape_config[0].memory_in_gbs == 12 && tonumber(oci_core_instance.wazuh.source_details[0].boot_volume_size_in_gbs) == 100 && tonumber(oci_core_instance.wazuh.source_details[0].boot_volume_vpus_per_gb) == 10
    error_message = "Fixed compute and storage bounds must not grow."
  }
  assert {
    condition     = length(oci_core_network_security_group_security_rule.bootstrap_ssh) == 0 && length(oci_core_security_list.closed.ingress_security_rules) == 0 && length(oci_core_security_list.closed.egress_security_rules) == 0 && oci_core_vcn.wazuh.is_ipv6enabled == false
    error_message = "Default network must allow no public ingress, including IPv6."
  }
  assert {
    condition     = length(oci_limits_quota.free_bounds.statements) == 4 && contains(oci_limits_quota.free_bounds.statements, "set compute-core quota standard-a1-core-count to 2 in tenancy where request.region = 'us-sanjose-1'") && contains(oci_limits_quota.free_bounds.statements, "set block-storage quota total-storage-gb to 200 in tenancy where request.region = 'us-sanjose-1'")
    error_message = "Enforce resource-specific free bounds before creating the VM."
  }
}
run "unverified_or_unavailable_stops_before_creation" {
  command = plan
  variables {
    audit = { free_account_verified = false, capacity_available = false, existing_storage_gb = 60, other_a1_cores = 0, other_a1_memory_gb = 0, audited_at = timestamp() }
  }
  expect_failures = [oci_limits_quota.free_bounds]
}
run "existing_disks_cannot_be_ignored" {
  command = plan
  variables {
    audit = { free_account_verified = true, capacity_available = true, existing_storage_gb = 101, other_a1_cores = 0, other_a1_memory_gb = 0, audited_at = timestamp() }
  }
  expect_failures = [oci_limits_quota.free_bounds]
}
run "other_a1_usage_blocks_extra_allocation" {
  command = plan
  variables {
    audit = { free_account_verified = true, capacity_available = true, existing_storage_gb = 60, other_a1_cores = 1, other_a1_memory_gb = 6, audited_at = timestamp() }
  }
  expect_failures = [oci_limits_quota.free_bounds]
}
run "stale_audit_is_rejected" {
  command = plan
  variables {
    audit = { free_account_verified = true, capacity_available = true, existing_storage_gb = 60, other_a1_cores = 0, other_a1_memory_gb = 0, audited_at = "2000-01-01T00:00:00Z" }
  }
  expect_failures = [oci_limits_quota.free_bounds]
}
run "another_region_is_forbidden" {
  command = plan
  variables { availability_domain = "TEST:US-PHOENIX-1-AD-1" }
  expect_failures = [var.availability_domain]
}
run "world_open_ssh_is_forbidden" {
  command = plan
  variables { bootstrap_ssh_cidr = "0.0.0.0/0" }
  expect_failures = [var.bootstrap_ssh_cidr]
}
run "narrow_bootstrap_ssh_is_explicit" {
  command = plan
  variables { bootstrap_ssh_cidr = "203.0.113.2/32" }
  assert {
    condition     = length(oci_core_network_security_group_security_rule.bootstrap_ssh) == 1 && oci_core_network_security_group_security_rule.bootstrap_ssh[0].tcp_options[0].destination_port_range[0].min == 22
    error_message = "Bootstrap exception must be exactly one SSH rule."
  }
}
