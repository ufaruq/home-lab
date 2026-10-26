data "oci_identity_domain" "default" {
  domain_id = var.identity_domain_ocid
}

data "oci_identity_domains_policy" "console" {
  idcs_endpoint = data.oci_identity_domain.default.url
  policy_id     = "OciConsolePolicy"
  # Rules are returned only when explicitly requested by this API.
  attributes = "id,active,rules"
}

data "oci_identity_domains_rule" "non_admin_mfa" {
  idcs_endpoint = data.oci_identity_domain.default.url
  rule_id       = "OciConsoleMFANonAdminRule"
}

data "oci_identity_domains_rule" "admin_mfa" {
  idcs_endpoint = data.oci_identity_domain.default.url
  rule_id       = "OciConsoleAdminMFARule"
}

data "oci_identity_domains_condition" "console_login" {
  idcs_endpoint = data.oci_identity_domain.default.url
  condition_id  = "OciConsoleDefaultSignOnCondition"
}

locals {
  console_mfa_actions = {
    for action in data.oci_identity_domains_rule.non_admin_mfa.return : action.name => action.value
  }
  admin_mfa_actions = {
    for action in data.oci_identity_domains_rule.admin_mfa.return : action.name => action.value
  }
}

resource "oci_identity_compartment" "home_lab" {
  compartment_id = var.tenancy_ocid
  name           = "home-lab"
  description    = "Always Free home lab; absolute cloud cost limit is zero."
  enable_delete  = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_domains_user" "operator" {
  idcs_endpoint = data.oci_identity_domain.default.url
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:OCITags",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User",
  ]
  user_name    = "home-lab-operator"
  display_name = "Home lab operator"
  active       = true

  name {
    given_name  = "Home Lab"
    family_name = "Operator"
  }

  emails {
    value   = var.operator_email
    type    = "work"
    primary = true
  }

  # Oracle adds this automatically if omitted; declare it to preserve convergence.
  emails {
    value   = var.operator_email
    type    = "recovery"
    primary = false
  }

  # Oracle emails the owner an activation link. Passwords and MFA are enrolled
  # directly with Oracle, never generated or stored by this configuration.
  urnietfparamsscimschemasoracleidcsextensionuser_user {
    bypass_notification = false
  }

  lifecycle {
    prevent_destroy = true
    # Oracle owns extension namespace discovery, including enrollment metadata.
    # Email, active state, and all access controls remain managed.
    ignore_changes = [schemas]

    precondition {
      condition     = data.oci_identity_domain.default.type == "DEFAULT"
      error_message = "Use the existing Free (DEFAULT) identity domain; do not create or upgrade a paid domain."
    }

    precondition {
      condition = (
        data.oci_identity_domains_policy.console.active == true &&
        toset([for rule in data.oci_identity_domains_policy.console.rules : rule.value]) == toset(["OciConsoleAdminMFARule", "OciConsoleMFANonAdminRule"]) &&
        length(data.oci_identity_domains_policy.console.rules) == 2 &&
        alltrue([
          for rule in data.oci_identity_domains_policy.console.rules :
          (rule.value == "OciConsoleAdminMFARule" && rule.sequence == 1) ||
          (rule.value == "OciConsoleMFANonAdminRule" && rule.sequence == 2)
        ]) &&
        try(one(data.oci_identity_domains_rule.non_admin_mfa.condition_group).value, "") == "OciConsoleDefaultSignOnCondition" &&
        try(one(data.oci_identity_domains_rule.non_admin_mfa.condition_group).type, "") == "Condition" &&
        data.oci_identity_domains_condition.console_login.attribute_name == "target.action" &&
        data.oci_identity_domains_condition.console_login.operator == "eq" &&
        data.oci_identity_domains_condition.console_login.attribute_value == "\"Login\"" &&
        try(length(data.oci_identity_domains_condition.console_login.evaluate_condition_if), 0) == 0 &&
        try(length(data.oci_identity_domains_rule.non_admin_mfa.rule_groovy), 0) == 0 &&
        lookup(local.console_mfa_actions, "authenticationFactor", "") == "IDP+2FA" &&
        lookup(local.console_mfa_actions, "allowUserToSkip2FAEnrolment", "") == "false" &&
        lookup(local.console_mfa_actions, "2FAFrequency", "") == "ALWAYS" &&
        lookup(local.admin_mfa_actions, "authenticationFactor", "") == "IDP+2FA" &&
        lookup(local.admin_mfa_actions, "allowUserToSkip2FAEnrolment", "") == "false" &&
        lookup(local.admin_mfa_actions, "2FAFrequency", "") == "ALWAYS"
      )
      error_message = "The existing console policy must require MFA for non-administrators on every login and prohibit skipping enrollment."
    }
  }
}

resource "oci_identity_domains_group" "operators" {
  idcs_endpoint = data.oci_identity_domain.default.url
  display_name  = "HomeLabOperators"
  # Without this explicit request, Oracle omits members from GET responses.
  attributes = "id,ocid,displayName,schemas,members"
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:Group",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:OCITags",
  ]

  members {
    type  = "User"
    value = oci_identity_domains_user.operator.id
    ocid  = oci_identity_domains_user.operator.ocid
  }

  lifecycle {
    prevent_destroy = true
    # Returned namespaces vary as Oracle populates extensions. Keep actual
    # membership authoritative; never ignore changes to the members block.
    ignore_changes = [schemas]
  }
}

resource "oci_identity_policy" "workload" {
  compartment_id = oci_identity_compartment.home_lab.id
  name           = "home-lab-operator-read"
  description    = "Read-only lab access; resource creation waits for verified Always Free safeguards."
  statements = [
    for family in ["instance-family", "volume-family", "virtual-network-family"] :
    "Allow group id ${oci_identity_domains_group.operators.ocid} to read ${family} in compartment id ${oci_identity_compartment.home_lab.id}"
  ]

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_policy" "discovery" {
  compartment_id = var.tenancy_ocid
  name           = "home-lab-operator-discovery"
  description    = "Read-only metadata for console compartment navigation and platform images."
  statements = [
    "Allow group id ${oci_identity_domains_group.operators.ocid} to inspect compartments in tenancy",
    "Allow group id ${oci_identity_domains_group.operators.ocid} to read instance-images in tenancy",
  ]

  lifecycle {
    prevent_destroy = true
  }
}
