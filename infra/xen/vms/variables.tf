variable "inventory_file" {
  description = "Explicit local inventory JSON path. Real inventories remain private; offline tests supply synthetic fixtures."
  type        = string
}

variable "existing_vm_ids" {
  description = "Private runtime discovery: original logical VM UUID -> current remote UUID. Null uses snapshot identities; an explicit empty map means no existing VMs were found."
  type        = map(string)
  default     = null
  validation {
    condition = var.existing_vm_ids == null ? true : alltrue([
      for logical_id, remote_id in var.existing_vm_ids :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", logical_id)) &&
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", remote_id))
    ])
    error_message = "VM discovery must map valid logical UUIDs to valid existing remote UUIDs."
  }
}

variable "existing_network_ids" {
  description = "Private runtime discovery: original logical network UUID -> current remote UUID. Null uses snapshot identities; an explicit empty map means no existing networks were found."
  type        = map(string)
  default     = null
  validation {
    condition = var.existing_network_ids == null ? true : alltrue([
      for logical_id, remote_id in var.existing_network_ids :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", logical_id)) &&
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", remote_id))
    ])
    error_message = "Network discovery must map valid logical UUIDs to valid existing remote UUIDs."
  }
}

variable "desired_state_file" {
  description = "Explicit local desired-state JSON path; tests use a synthetic fixture."
  type        = string
}
