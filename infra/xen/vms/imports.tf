# Discovery omits missing objects and maps replacements back to stable logical keys.
import {
  for_each = { for id in keys(local.existing_vms) : id => local.current_vm_ids[id] if contains(keys(local.current_vm_ids), id) }
  to       = xenorchestra_vm.existing[each.key]
  id       = each.value
}
import {
  for_each = { for id in keys(local.protected_vms) : id => local.current_vm_ids[id] if contains(keys(local.current_vm_ids), id) }
  to       = xenorchestra_vm.protected[each.key]
  id       = each.value
}
import {
  for_each = { for id in keys(local.existing_networks) : id => local.current_network_ids[id] if contains(keys(local.current_network_ids), id) }
  to       = xenorchestra_network.existing[each.key]
  id       = each.value
}
