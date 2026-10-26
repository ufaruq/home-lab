mock_provider "oci" {
  override_during = plan

  mock_data "oci_identity_domain" {
    defaults = {
      url          = "https://example.identity.oraclecloud.com"
      display_name = "Default"
      type         = "DEFAULT"
    }
  }

  mock_resource "oci_identity_compartment" {
    defaults = {
      id = "ocid1.compartment.oc1..testhomelab"
    }
  }

  mock_resource "oci_identity_domains_user" {
    defaults = {
      id       = "operator-scim-id"
      ocid     = "ocid1.user.oc1..testoperator"
      password = ""
    }
  }

  mock_data "oci_identity_domains_policy" {
    defaults = {
      active = true
      rules = [
        { value = "OciConsoleAdminMFARule", sequence = 1 },
        { value = "OciConsoleMFANonAdminRule", sequence = 2 },
      ]
    }
  }

  mock_data "oci_identity_domains_rule" {
    defaults = {
      return = [
        { name = "authenticationFactor", value = "IDP+2FA" },
        { name = "allowUserToSkip2FAEnrolment", value = "false" },
        { name = "2FAFrequency", value = "ALWAYS" },
      ]
      condition_group = [{ type = "Condition", value = "OciConsoleDefaultSignOnCondition" }]
      rule_groovy     = ""
    }
  }

  mock_data "oci_identity_domains_condition" {
    defaults = {
      attribute_name        = "target.action"
      operator              = "eq"
      attribute_value       = "\"Login\""
      evaluate_condition_if = ""
    }
  }

  mock_resource "oci_identity_domains_group" {
    defaults = {
      id   = "operator-group-scim-id"
      ocid = "ocid1.group.oc1..testoperators"
    }
  }
}

variables {
  tenancy_ocid         = "ocid1.tenancy.oc1..testtenancy"
  identity_domain_ocid = "ocid1.domain.oc1..testdomain"
  operator_email       = "owner@example.com"
}

run "restricted_access" {
  command = plan

  assert {
    condition = (
      oci_identity_policy.workload.compartment_id == oci_identity_compartment.home_lab.id &&
      length(oci_identity_policy.workload.statements) == 3 &&
      alltrue([
        for statement in oci_identity_policy.workload.statements :
        can(regex("^Allow group id ocid1\\.group\\.oc1\\.\\.testoperators to read (instance-family|volume-family|virtual-network-family) in compartment id ocid1\\.compartment\\.oc1\\.\\.testhomelab$", statement))
      ])
    )
    error_message = "The operator must have read-only access to the three workload families in the dedicated compartment, using the group's OCI OCID. Provisioning waits for enforceable free-tier safeguards."
  }

  assert {
    condition = (
      oci_identity_policy.discovery.compartment_id == var.tenancy_ocid &&
      length(oci_identity_policy.discovery.statements) == 2 &&
      alltrue([
        for statement in oci_identity_policy.discovery.statements : contains([
          "Allow group id ocid1.group.oc1..testoperators to inspect compartments in tenancy",
          "Allow group id ocid1.group.oc1..testoperators to read instance-images in tenancy"
        ], statement)
      ])
    )
    error_message = "Root grants must remain limited to compartment discovery and image reading; no IAM administration or tenancy-wide writes."
  }

  assert {
    condition = (
      length(oci_identity_domains_group.operators.members) == 1 &&
      one(oci_identity_domains_group.operators.members).value == oci_identity_domains_user.operator.id &&
      one(oci_identity_domains_group.operators.members).ocid == oci_identity_domains_user.operator.ocid &&
      one(oci_identity_domains_group.operators.members).type == "User" &&
      oci_identity_domains_user.operator.user_name == "home-lab-operator"
    )
    error_message = "The dedicated group must contain exactly the new operator using its SCIM ID, not the administrator or an OCI OCID."
  }

  assert {
    # password is Optional+Computed: use an empty mock response to model Oracle's
    # write-only password field. An explicitly configured password still fails.
    condition     = oci_identity_domains_user.operator.password == null || oci_identity_domains_user.operator.password == ""
    error_message = "Password enrollment must happen with Oracle; Terraform must not manage the password."
  }

  assert {
    condition     = anytrue([for email in oci_identity_domains_user.operator.emails : email.type == "recovery" && email.value == var.operator_email])
    error_message = "Declare Oracle's recovery email explicitly to avoid post-creation drift."
  }
}

run "reject_extra_signon_rule" {
  command = plan

  override_data {
    target = data.oci_identity_domains_policy.console
    values = {
      active = true
      rules = [
        { value = "PermissiveRule", sequence = 1 },
        { value = "OciConsoleAdminMFARule", sequence = 2 },
        { value = "OciConsoleMFANonAdminRule", sequence = 3 },
      ]
    }
  }

  expect_failures = [oci_identity_domains_user.operator]
}

run "reject_unrelated_mfa_condition" {
  command = plan

  override_data {
    target = data.oci_identity_domains_rule.non_admin_mfa
    values = {
      return = [
        { name = "authenticationFactor", value = "IDP+2FA" },
        { name = "allowUserToSkip2FAEnrolment", value = "false" },
        { name = "2FAFrequency", value = "ALWAYS" },
      ]
      condition_group = [{ type = "Condition", value = "UnrelatedCondition" }]
    }
  }

  expect_failures = [oci_identity_domains_user.operator]
}

run "reject_missing_mfa" {
  command = plan

  override_data {
    target = data.oci_identity_domains_rule.non_admin_mfa
    values = {
      return = [{ name = "authenticationFactor", value = "IDP" }]
    }
  }

  expect_failures = [oci_identity_domains_user.operator]
}

run "reject_paid_identity_domain" {
  command = plan

  override_data {
    target = data.oci_identity_domain.default
    values = {
      type = "PREMIUM"
      url  = "https://example.identity.oraclecloud.com"
    }
  }

  expect_failures = [oci_identity_domains_user.operator]
}
