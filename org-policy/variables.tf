variable "organization_id" {
  description = "Numeric organization ID, for example 123456789012."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "organization_id must be the numeric organization ID."
  }
}

variable "dry_run" {
  description = "When true, managed and custom constraints are deployed in dry-run mode. Legacy constraints do not support dry-run and are not created until this is false."
  type        = bool
  default     = true
}

variable "allowed_customer_ids" {
  description = "Cloud Identity / Workspace customer IDs allowed in IAM policies, for example [\"C0abc123d\"]."
  type        = list(string)

  validation {
    condition     = length(var.allowed_customer_ids) > 0 && alltrue([for id in var.allowed_customer_ids : can(regex("^C[0-9A-Za-z]+$", id))])
    error_message = "Provide at least one customer ID in the form C0abc123d."
  }
}

variable "allowed_contact_domains" {
  description = "Domains allowed for Essential Contacts, in the form @example.com."
  type        = list(string)

  validation {
    condition     = length(var.allowed_contact_domains) > 0 && alltrue([for d in var.allowed_contact_domains : startswith(d, "@")])
    error_message = "Provide at least one domain in the form @example.com."
  }
}

variable "allowed_wif_issuers" {
  description = "OIDC issuer URIs allowed for workload identity pool providers. Empty denies all."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for u in var.allowed_wif_issuers : startswith(u, "https://")])
    error_message = "Issuer URIs must start with https://."
  }
}

variable "allowed_wif_aws_accounts" {
  description = "AWS account IDs allowed for workload identity federation. Empty denies all."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.allowed_wif_aws_accounts : can(regex("^[0-9]{12}$", a))])
    error_message = "AWS account IDs must be 12 digits."
  }
}

variable "service_account_key_expiry_hours" {
  description = "Lifetime of newly created service account keys. Only applies where key creation is still allowed."
  type        = string
  default     = "24h"

  validation {
    condition     = contains(["1h", "8h", "24h", "168h", "336h", "720h", "1440h", "2160h"], var.service_account_key_expiry_hours)
    error_message = "Must be one of 1h, 8h, 24h, 168h, 336h, 720h, 1440h, 2160h."
  }
}
