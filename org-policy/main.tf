locals {
  parent = "organizations/${var.organization_id}"

  # Managed constraints support dry-run. A null value means enforce with no parameters.
  managed_constraints = {
    "iam.managed.disableServiceAccountKeyCreation"                     = null
    "iam.managed.disableServiceAccountKeyUpload"                       = null
    "iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts" = null
    "compute.managed.requireOsLogin"                                   = null
    "compute.managed.disableSerialPortAccess"                          = null
    "compute.managed.vmExternalIpAccess"                               = null
    "sql.managed.restrictPublicIp"                                     = null
    "sql.managed.restrictAuthorizedNetworks"                           = null
    "essentialcontacts.managed.allowedContactDomains"                  = { allowedDomains = var.allowed_contact_domains }
  }

  # Legacy constraints with no managed equivalent, or whose managed equivalent
  # takes different values (see README).
  legacy_boolean_constraints = [
    "compute.skipDefaultNetworkCreation",
    "storage.uniformBucketLevelAccess",
    "storage.publicAccessPrevention",
  ]

  # A null value means deny all.
  legacy_list_constraints = {
    "iam.allowedPolicyMemberDomains"      = [for id in var.allowed_customer_ids : "is:${id}"]
    "iam.workloadIdentityPoolProviders"   = length(var.allowed_wif_issuers) > 0 ? var.allowed_wif_issuers : null
    "iam.serviceAccountKeyExpiryHours"    = [var.service_account_key_expiry_hours]
    "iam.workloadIdentityPoolAwsAccounts" = length(var.allowed_wif_aws_accounts) > 0 ? var.allowed_wif_aws_accounts : null
  }
}

resource "google_org_policy_policy" "managed" {
  for_each = local.managed_constraints

  name   = "${local.parent}/policies/${each.key}"
  parent = local.parent

  dynamic "spec" {
    for_each = var.dry_run ? [] : [1]
    content {
      rules {
        enforce    = "TRUE"
        parameters = each.value == null ? null : jsonencode(each.value)
      }
    }
  }

  dynamic "dry_run_spec" {
    for_each = var.dry_run ? [1] : []
    content {
      rules {
        enforce    = "TRUE"
        parameters = each.value == null ? null : jsonencode(each.value)
      }
    }
  }
}

# Legacy constraints reject dry_run_spec, so they are only created once dry_run is off.
resource "google_org_policy_policy" "boolean" {
  for_each = toset([for c in local.legacy_boolean_constraints : c if !var.dry_run])

  name   = "${local.parent}/policies/${each.key}"
  parent = local.parent

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "list" {
  for_each = { for c, v in local.legacy_list_constraints : c => v if !var.dry_run }

  name   = "${local.parent}/policies/${each.key}"
  parent = local.parent

  spec {
    rules {
      deny_all = each.value == null ? "TRUE" : null

      dynamic "values" {
        for_each = each.value == null ? [] : [each.value]
        content {
          allowed_values = values.value
        }
      }
    }
  }
}

resource "google_org_policy_custom_constraint" "wif_attribute_condition" {
  name         = "custom.requireWifAttributeCondition"
  parent       = local.parent
  display_name = "Require an attribute condition on WIF providers"
  description  = "Workload identity pool providers must set an attribute condition so only trusted identities from the external IdP can authenticate."

  resource_types = ["iam.googleapis.com/WorkloadIdentityPoolProvider"]
  method_types   = ["CREATE", "UPDATE"]
  action_type    = "DENY"
  condition      = "resource.attributeCondition == \"\""
}

resource "google_org_policy_policy" "wif_attribute_condition" {
  name   = "${local.parent}/policies/${google_org_policy_custom_constraint.wif_attribute_condition.name}"
  parent = local.parent

  dynamic "spec" {
    for_each = var.dry_run ? [] : [1]
    content {
      rules {
        enforce = "TRUE"
      }
    }
  }

  dynamic "dry_run_spec" {
    for_each = var.dry_run ? [1] : []
    content {
      rules {
        enforce = "TRUE"
      }
    }
  }
}
