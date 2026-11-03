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
    condition     = contains(["logging", "tailnet", "all"], var.phase)
    error_message = "Select logging, tailnet, or all."
  }
}
locals {
  repository = abspath("${path.module}/../..")
  sources = setunion(
    fileset(local.repository, "monitoring/wazuh/**"),
    fileset(local.repository, "ansible/roles/monitoring_wazuh_*/**/*.yml"),
    fileset(local.repository, "ansible/roles/monitoring_wazuh_*/files/*.py"),
    fileset(local.repository, "ansible/playbooks/wazuh-logging*.yml"),
    toset(["scripts/monitoring/wazuh_logging.py"])
  )
}
resource "terraform_data" "logging" {
  input = {
    manager        = "wazuh"
    agents         = var.agents
    phase          = var.phase
    retention_days = 7
  }
  triggers_replace = {
    selection = sha256(jsonencode([var.agents, var.phase]))
    source    = sha256(jsonencode({ for name in local.sources : name => filesha256("${local.repository}/${name}") if !strcontains(name, "__pycache__") && !endswith(name, ".md") }))
  }
  lifecycle {
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
