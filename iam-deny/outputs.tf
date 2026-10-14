output "deny_policy_id" {
  description = "ID of the deny policy."
  value       = google_iam_deny_policy.guardrails.id
}
