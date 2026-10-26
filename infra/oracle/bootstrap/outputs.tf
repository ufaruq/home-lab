output "compartment_ocid" {
  description = "Dedicated compartment for future Always Free workloads."
  value       = oci_identity_compartment.home_lab.id
}

output "operator_username" {
  description = "Sign in to the existing identity domain with this username."
  value       = oci_identity_domains_user.operator.user_name
}

output "operator_user_ocid" {
  description = "Operator's OCI identifier; distinct from its SCIM ID."
  value       = oci_identity_domains_user.operator.ocid
}

output "operator_group_ocid" {
  description = "OCI group identifier used by the IAM policies."
  value       = oci_identity_domains_group.operators.ocid
}

output "identity_domain_url" {
  description = "Existing identity domain for account enrollment."
  value       = data.oci_identity_domain.default.url
}

output "region" {
  description = "Verified tenancy home region."
  value       = var.region
}
