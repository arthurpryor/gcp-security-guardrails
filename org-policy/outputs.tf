output "custom_constraint_name" {
  description = "Name of the custom WIF attribute condition constraint."
  value       = google_org_policy_custom_constraint.wif_attribute_condition.name
}

output "enforced_policies" {
  description = "Org policies enforced by this module. Empty while dry_run is true."
  value = concat(
    var.dry_run ? [] : [for p in google_org_policy_policy.managed : p.name],
    [for p in google_org_policy_policy.boolean : p.name],
    [for p in google_org_policy_policy.list : p.name],
    var.dry_run ? [] : [google_org_policy_policy.wif_attribute_condition.name],
  )
}

output "dry_run_policies" {
  description = "Org policies deployed in dry-run mode."
  value = var.dry_run ? concat(
    [for p in google_org_policy_policy.managed : p.name],
    [google_org_policy_policy.wif_attribute_condition.name],
  ) : []
}
