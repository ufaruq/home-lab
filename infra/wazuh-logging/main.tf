terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  backend "local" {}
}

variable "deployment_reviewed" {
  type    = bool
  default = false
}
variable "agents" {
  type    = list(string)
  default = []
  validation {
    condition = alltrue([for name in var.agents : contains([
      "debian_server", "maps", "popos", "portainer", "ubuntu_malware_lab", "xoa",
      "deb_node_db", "deb_node_slim"
    ], name)]) && length(var.agents) == length(distinct(var.agents))
    error_message = "Only explicitly selected guest aliases may receive agents; Parrot and appliances are excluded."
  }
}
variable "phase" {
  type    = string
  default = "all"
  validation {
    condition     = contains(["logging", "tailnet", "all", "truenas"], var.phase)
    error_message = "Select logging, tailnet, all, or the separate manager-only truenas phase."
  }
}
variable "truenas_template_fix" {
  type    = bool
  default = false
}
locals {
  repository = abspath("${path.module}/../..")
  sources = setunion(
    fileset(local.repository, "monitoring/wazuh/**"),
    fileset(local.repository, "monitoring/truenas/**/*.py"),
    fileset(local.repository, "ansible/roles/monitoring_wazuh_*/**/*.yml"),
    fileset(local.repository, "ansible/roles/monitoring_wazuh_*/files/*.py"),
    fileset(local.repository, "ansible/roles/monitoring_wazuh_*/templates/*.j2"),
    fileset(local.repository, "ansible/playbooks/wazuh-logging*.yml"),
    toset(["scripts/monitoring/wazuh_logging.py"])
  )
}
resource "terraform_data" "logging" {
  input = merge({
    manager        = "wazuh"
    agents         = var.agents
    phase          = var.phase
    retention_days = 7
  }, var.truenas_template_fix ? { native_template_fix = true } : {})
  triggers_replace = {
    selection = sha256(jsonencode([var.agents, var.phase, var.truenas_template_fix]))
    source    = sha256(jsonencode({ for name in local.sources : name => filesha256("${local.repository}/${name}") if !strcontains(name, "__pycache__") && !endswith(name, ".md") }))
  }
  lifecycle {
    precondition {
      condition     = !var.truenas_template_fix || var.phase == "truenas"
      error_message = "Native syslog template repair is allowed only in the separately reviewed TrueNAS phase."
    }
    precondition {
      condition     = var.phase != "truenas" || length(var.agents) == 0
      error_message = "The TrueNAS phase configures only the existing manager receiver and native appliance; agents must be empty."
    }
    precondition {
      condition     = var.deployment_reviewed
      error_message = "Use the guarded controller to inspect the exact local-only saved plan before applying."
    }
  }
  provisioner "local-exec" {
    command = "exec \"$WAZUH_LOGGING_PYTHON\" \"$WAZUH_LOGGING_CONTROLLER\" deploy --phase \"$WAZUH_LOGGING_PHASE\""
    environment = {
      WAZUH_LOGGING_CONTROLLER = "${local.repository}/scripts/monitoring/wazuh_logging.py"
      WAZUH_LOGGING_PHASE      = var.phase
    }
    quiet = true
  }
}
