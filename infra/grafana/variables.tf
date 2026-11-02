variable "free_plan_verified" {
  description = "Explicit owner confirmation that the stack has exited trial and its current plan is Free, with no paid subscription. A trial does not qualify."
  type        = bool
  default     = false
}

variable "unbilled_trial_dashboard_only_verified" {
  description = "Explicit unbilled Cloud Trial verification for free folders/dashboards only; no hosts, alert rules, ingestion or billing changes. The controller verifies live edition before plan/apply."
  type        = bool
  default     = false
}

variable "prometheus_datasource_uid" {
  description = "UID of an existing Prometheus data source in the existing stack."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,40}$", var.prometheus_datasource_uid))
    error_message = "Supply an existing Prometheus data source UID, not a URL or credential."
  }
}

variable "loki_datasource_uid" {
  description = "UID of an existing Loki data source in the existing stack."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,40}$", var.loki_datasource_uid))
    error_message = "Supply an existing Loki data source UID, not a URL or credential."
  }
}

variable "usage_datasource_uid" {
  description = "Optional existing grafanacloud-usage Prometheus UID; null omits the usage dashboard."
  type        = string
  default     = null
  validation {
    condition     = var.usage_datasource_uid == null ? true : can(regex("^[A-Za-z0-9_-]{1,40}$", var.usage_datasource_uid))
    error_message = "Supply an existing usage data source UID, or null."
  }
}

variable "expected_linux_hosts" {
  description = "Inventory names of deployed Linux collectors expected online now. Exclude halted, disabled, diskless and appliance hosts."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for host in var.expected_linux_hosts : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$", host))])
    error_message = "Expected hosts must be inventory names containing letters, numbers, underscores or hyphens."
  }
}

variable "expected_windows_hosts" {
  description = "Inventory names of deployed Windows collectors expected online now. Exclude halted or disabled hosts."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for host in var.expected_windows_hosts : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$", host))])
    error_message = "Expected hosts must be inventory names containing letters, numbers, underscores or hyphens."
  }
}

variable "alerts_enabled" {
  description = "Activate provisioned alerts only after collectors, host expectations and the existing contact point have been verified."
  type        = bool
  default     = false
}

variable "existing_contact_point_name" {
  description = "Owner-selected existing contact point name. Required to activate alerts; no recipients, credentials or global routes are managed here."
  type        = string
  default     = null
  validation {
    condition     = var.existing_contact_point_name == null ? true : length(trimspace(var.existing_contact_point_name)) > 0
    error_message = "An existing contact point name must be nonempty, or null."
  }
}

variable "enable_security_dashboard" {
  description = "Show optional Wazuh/security log views when those bounded logs are shipped to existing Loki."
  type        = bool
  default     = false
}
