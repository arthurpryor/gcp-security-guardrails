variable "organization_id" {
  description = "Numeric organization ID, for example 123456789012."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "organization_id must be the numeric organization ID."
  }
}

variable "break_glass_group" {
  description = "Email of the Google group exempt from these deny rules, for example break-glass@example.com."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.break_glass_group))
    error_message = "break_glass_group must be a group email address."
  }
}

variable "policy_name" {
  description = "Name of the deny policy."
  type        = string
  default     = "security-guardrails"
}
