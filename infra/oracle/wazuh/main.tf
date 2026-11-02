data "oci_core_image" "ubuntu" {
  image_id = var.image_ocid
}

# These are resource-specific caps, not a universal spending cap. The operator
# remains read-only; only the existing temporary administrator can apply this root.
resource "oci_limits_quota" "free_bounds" {
  compartment_id = var.tenancy_ocid
  name           = "home-lab-wazuh-free-bounds"
  description    = "A1 and combined disk bounds for the owner-approved zero-cost deployment."
  statements = [
    "set compute-core quota standard-a1-core-count to 2 in tenancy where request.region = 'us-sanjose-1'",
    "set compute-memory quota standard-a1-memory-count to 12 in tenancy where request.region = 'us-sanjose-1'",
    "set block-storage quota total-storage-gb to 200 in tenancy where request.region = 'us-sanjose-1'",
    "zero block-storage quota backup-count in compartment home-lab",
  ]
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.audit.free_account_verified && var.audit.capacity_available
      error_message = "Actual Free account eligibility and current free host capacity must both be verified."
    }
    precondition {
      condition     = var.audit.existing_storage_gb >= 0 && var.audit.existing_storage_gb + 100 <= 200 && var.audit.other_a1_cores == 0 && var.audit.other_a1_memory_gb == 0
      error_message = "Combined tenancy usage would exceed the conservative free deployment allowance."
    }
    precondition {
      condition     = timecmp(plantimestamp(), var.audit.audited_at) >= 0 && timecmp(plantimestamp(), timeadd(var.audit.audited_at, "15m")) <= 0
      error_message = "Audit is stale or future-dated; run the guarded controller again."
    }
    precondition {
      condition     = data.oci_core_image.ubuntu.operating_system == "Canonical Ubuntu" && data.oci_core_image.ubuntu.operating_system_version == "22.04" && strcontains(data.oci_core_image.ubuntu.display_name, "aarch64") && data.oci_core_image.ubuntu.state == "AVAILABLE"
      error_message = "The image must be the reviewed available Ubuntu 22.04 ARM platform image."
    }
  }
}

resource "oci_core_vcn" "wazuh" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.86.0.0/24"]
  display_name   = "home-lab-wazuh"
  dns_label      = "hlwazuh"
  is_ipv6enabled = false
  depends_on     = [oci_limits_quota.free_bounds]
}
resource "oci_core_internet_gateway" "wazuh" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.wazuh.id
  display_name   = "home-lab-wazuh-egress"
  enabled        = true
}
resource "oci_core_route_table" "wazuh" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.wazuh.id
  display_name   = "home-lab-wazuh"
  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.wazuh.id
  }
}
resource "oci_core_security_list" "closed" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.wazuh.id
  display_name   = "home-lab-wazuh-closed"
  # No rule blocks: custom lists start empty; the VCN's permissive default list
  # is deliberately never associated with this subnet.
  lifecycle {
    postcondition {
      condition     = length(self.ingress_security_rules) == 0 && length(self.egress_security_rules) == 0
      error_message = "The subnet security list must remain empty."
    }
  }
}
resource "oci_core_subnet" "wazuh" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.wazuh.id
  cidr_block                 = "10.86.0.0/28"
  display_name               = "home-lab-wazuh"
  dns_label                  = "security"
  route_table_id             = oci_core_route_table.wazuh.id
  security_list_ids          = [oci_core_security_list.closed.id]
  prohibit_public_ip_on_vnic = false
}
resource "oci_core_network_security_group" "wazuh" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.wazuh.id
  display_name   = "home-lab-wazuh"
}
resource "oci_core_network_security_group_security_rule" "bootstrap_ssh" {
  count                     = var.bootstrap_ssh_cidr == null ? 0 : 1
  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.bootstrap_ssh_cidr
  source_type               = "CIDR_BLOCK"
  stateless                 = false
  description               = "Temporary SSH from the verified operator address only."
  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}
resource "oci_core_network_security_group_security_rule" "outbound_tcp" {
  for_each                  = toset(["80", "443"])
  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "EGRESS"
  protocol                  = "6"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false
  description               = "Package repositories, updates and HTTPS VPN relays; no inbound application access."
  tcp_options {
    destination_port_range {
      min = tonumber(each.value)
      max = tonumber(each.value)
    }
  }
}
resource "oci_core_network_security_group_security_rule" "outbound_udp" {
  for_each                  = toset(["123", "3478"])
  network_security_group_id = oci_core_network_security_group.wazuh.id
  direction                 = "EGRESS"
  protocol                  = "17"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false
  description               = "Time synchronization and VPN discovery; direct UDP peers may fall back to HTTPS relays."
  udp_options {
    destination_port_range {
      min = tonumber(each.value)
      max = tonumber(each.value)
    }
  }
}

resource "oci_core_instance" "wazuh" {
  compartment_id       = var.compartment_ocid
  availability_domain  = var.availability_domain
  display_name         = "home-lab-wazuh"
  shape                = "VM.Standard.A1.Flex"
  preserve_boot_volume = true
  shape_config {
    ocpus         = 2
    memory_in_gbs = 12
  }
  create_vnic_details {
    subnet_id        = oci_core_subnet.wazuh.id
    nsg_ids          = [oci_core_network_security_group.wazuh.id]
    assign_public_ip = "true"
    assign_ipv6ip    = false
    hostname_label   = "wazuh"
  }
  source_details {
    source_type                     = "image"
    source_id                       = var.image_ocid
    boot_volume_size_in_gbs         = "100"
    boot_volume_vpus_per_gb         = "10"
    is_preserve_boot_volume_enabled = true
  }
  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }
  agent_config {
    is_monitoring_disabled   = true
    is_management_disabled   = true
    are_all_plugins_disabled = true
  }
  metadata = {
    ssh_authorized_keys = trimspace(var.ssh_public_key)
    user_data           = filebase64("${path.module}/cloud-init.yaml")
  }
  freeform_tags = {
    managed_by = "terraform"
    purpose    = "wazuh"
    budget     = "always-free-only"
  }
  depends_on = [oci_core_network_security_group_security_rule.outbound_tcp, oci_core_network_security_group_security_rule.outbound_udp]
  lifecycle {
    prevent_destroy = true
  }
}

# Authentication, enrollment and management credentials are inherited by the
# controller from owner-only files; no private input is read into Terraform.
resource "terraform_data" "manager" {
  count = var.deploy_manager ? 1 : 0
  triggers_replace = {
    instance_id = oci_core_instance.wazuh.id
    sources = sha256(join("", [for name in sort(tolist(setunion(
      fileset("${path.module}/../../..", "ansible/roles/monitoring_wazuh_manager/**"),
      fileset("${path.module}/../../..", "monitoring/wazuh/**"),
      toset(["scripts/monitoring/manage.py", "monitoring/fleet.json", "monitoring/inventory/oracle.yml", "ansible/playbooks/monitoring-wazuh.yml", "ansible/playbooks/monitoring-preflight.yml"])
    ))) : filesha256("${path.module}/../../../${name}") if !strcontains(name, "__pycache__/") && !endswith(name, ".pyc")]))
  }
  provisioner "local-exec" {
    command = <<-EOT
      set -eu
      exec python3 "$MONITORING_CONTROLLER" deploy --component manager --targets oracle_wazuh --private-inventory "$MONITORING_PRIVATE_INVENTORY" --private-vars "$MONITORING_PRIVATE_VARS"
    EOT
    environment = {
      MONITORING_CONTROLLER = abspath("${path.module}/../../../scripts/monitoring/manage.py")
    }
    quiet = true
  }
}
