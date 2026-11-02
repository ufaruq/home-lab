variable "tenancy_ocid" {
  description = "Existing tenancy OCID; identifiers are metadata, not credentials."
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.tenancy\\.", var.tenancy_ocid))
    error_message = "Provide an OCI tenancy OCID."
  }
}

variable "identity_domain_ocid" {
  description = "Existing Default identity domain OCID; this module never creates a domain."
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.domain\\.", var.identity_domain_ocid))
    error_message = "Provide the existing identity domain OCID."
  }
}

variable "operator_email" {
  description = "Owner's email for Oracle-managed account activation and recovery."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.operator_email))
    error_message = "Provide a valid operator email address."
  }
}

variable "oci_profile" {
  description = "Temporary administrator profile in ~/.oci/config, used only for bootstrap."
  type        = string
  default     = "home-lab-bootstrap"
}

variable "region" {
  description = "Tenancy home region, used for identity administration."
  type        = string
  default     = "us-sanjose-1"
}
