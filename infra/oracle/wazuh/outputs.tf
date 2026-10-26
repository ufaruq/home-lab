output "instance_id" {
  value = oci_core_instance.wazuh.id
}
output "public_ip" {
  description = "Transport/bootstrap address only; Wazuh application ports remain closed publicly."
  value       = oci_core_instance.wazuh.public_ip
}
output "private_ip" {
  value = oci_core_instance.wazuh.private_ip
}
output "planned_resources" {
  value = { shape = "VM.Standard.A1.Flex", ocpus = 2, memory_gb = 12, boot_gb = 100, boot_vpus_per_gb = 10 }
}
