# Existing switches and VLANs only. No host/PIF address, bond, or storage creation.
# Names are labels, not proof of physical topology.
resource "xenorchestra_network" "existing" {
  for_each = local.existing_networks

  name_label        = each.value.name_label
  name_description  = each.value.name_description
  pool_id           = local.pool_id
  mtu               = each.value.mtu
  automatic         = each.value.automatic
  default_is_locked = each.value.default_is_locked
  nbd               = each.value.nbd
  source_pif_device = each.value.source_pif_device
  vlan              = each.value.vlan

  lifecycle {
    prevent_destroy = true
  }
}
