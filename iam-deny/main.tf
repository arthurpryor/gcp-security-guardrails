locals {
  everyone    = ["principalSet://goog/public:all"]
  break_glass = ["principalSet://goog/group/${var.break_glass_group}"]
}

resource "google_iam_deny_policy" "guardrails" {
  parent       = urlencode("cloudresourcemanager.googleapis.com/organizations/${var.organization_id}")
  name         = var.policy_name
  display_name = "Security guardrails"

  rules {
    description = "Only break-glass can manage workload identity pools and providers."
    deny_rule {
      denied_principals    = local.everyone
      exception_principals = local.break_glass
      denied_permissions = [
        "iam.googleapis.com/workloadIdentityPools.create",
        "iam.googleapis.com/workloadIdentityPools.update",
        "iam.googleapis.com/workloadIdentityPools.delete",
        "iam.googleapis.com/workloadIdentityPoolProviders.create",
        "iam.googleapis.com/workloadIdentityPoolProviders.update",
        "iam.googleapis.com/workloadIdentityPoolProviders.delete",
      ]
    }
  }

  rules {
    description = "Only break-glass can create service account keys."
    deny_rule {
      denied_principals    = local.everyone
      exception_principals = local.break_glass
      denied_permissions   = ["iam.googleapis.com/serviceAccountKeys.create"]
    }
  }

  rules {
    description = "Only break-glass can delete projects."
    deny_rule {
      denied_principals    = local.everyone
      exception_principals = local.break_glass
      denied_permissions   = ["cloudresourcemanager.googleapis.com/projects.delete"]
    }
  }
}
