# gcp-security-guardrails

Google Cloud security guardrails as code. Three independent layers that each cover gaps in the others:

| Path | Tool | What it controls |
| --- | --- | --- |
| `org-policy/` | Terraform | What resources are allowed to look like, enforced by the Organization Policy Service |
| `iam-deny/` | Terraform | Who can perform a few high-risk actions, regardless of IAM allow grants |
| `policy/wif/` | OPA (Rego v1) | Workload Identity Federation provider settings, checked at plan time in CI |

## org-policy

Sets a baseline of organization policy constraints at the organization level. It uses managed constraints wherever Google has a managed equivalent with documented values, and falls back to legacy constraints otherwise.

Managed constraints, all enforced:

| Constraint | Replaces | Parameters |
| --- | --- | --- |
| `iam.managed.disableServiceAccountKeyCreation` | `iam.disableServiceAccountKeyCreation` | |
| `iam.managed.disableServiceAccountKeyUpload` | `iam.disableServiceAccountKeyUpload` | |
| `iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` | `iam.automaticIamGrantsForDefaultServiceAccounts` | |
| `compute.managed.requireOsLogin` | `compute.requireOsLogin` | |
| `compute.managed.disableSerialPortAccess` | `compute.disableSerialPortAccess` | |
| `compute.managed.vmExternalIpAccess` | `compute.vmExternalIpAccess` | |
| `sql.managed.restrictPublicIp` | `sql.restrictPublicIp` | |
| `sql.managed.restrictAuthorizedNetworks` | `sql.restrictAuthorizedNetworks` | |
| `essentialcontacts.managed.allowedContactDomains` | `essentialcontacts.allowedContactDomains` | `allowedDomains` from `allowed_contact_domains`, in the form `@example.com` |

Legacy boolean constraints, all enforced. These have no managed equivalent:

- `compute.skipDefaultNetworkCreation`
- `storage.uniformBucketLevelAccess`
- `storage.publicAccessPrevention`

Legacy list constraints:

| Constraint | Value | Why legacy |
| --- | --- | --- |
| `iam.allowedPolicyMemberDomains` | `allowed_customer_ids`, sent as `is:C0abc123d` | `iam.managed.allowedPolicyMembers` takes organization principal sets and member subjects, not customer IDs, and Google's docs show conflicting formats for its principal sets |
| `iam.workloadIdentityPoolProviders` | `allowed_wif_issuers`. Deny all when empty. | The parameters for `iam.managed.workloadIdentityPoolProviders` aren't documented |
| `iam.serviceAccountKeyExpiryHours` | `service_account_key_expiry_hours`. One of `1h`, `8h`, `24h`, `168h`, `336h`, `720h`, `1440h`, `2160h`. | No managed equivalent |
| `iam.workloadIdentityPoolAwsAccounts` | `allowed_wif_aws_accounts`. Deny all when empty. | No managed equivalent |

It also creates a custom constraint, `custom.requireWifAttributeCondition`, on `iam.googleapis.com/WorkloadIdentityPoolProvider`. It denies `CREATE` and `UPDATE` when `resource.attributeCondition == ""`, and a policy enforces it. A provider with no attribute condition accepts any token the external IdP issues. For GitHub Actions, that means any workflow in any repository on github.com.

### dry_run

Google only allows dry-run org policies for custom constraints, managed constraints, and four specific legacy constraints (restrict service usage, restrict endpoint usage, restrict TLS versions, restrict TLS cipher suites). Setting `dry_run_spec` on any other constraint returns an error. None of the legacy constraints above are in that list.

So the module behaves like this:

| `dry_run` | Managed and custom constraint policies | Legacy constraint policies |
| --- | --- | --- |
| `true` (default) | `dry_run_spec` only | Not created |
| `false` | `spec` only | Created with `spec` |

## iam-deny

One IAM deny policy attached to the organization. It denies `principalSet://goog/public:all` (every principal) the following permissions. The only exception is the break-glass group, given as `principalSet://goog/group/<email>`.

| Rule | Permissions |
| --- | --- |
| Workload identity pools and providers | `iam.googleapis.com/workloadIdentityPools.{create,update,delete}`, `iam.googleapis.com/workloadIdentityPoolProviders.{create,update,delete}` |
| Service account keys | `iam.googleapis.com/serviceAccountKeys.create` |
| Projects | `cloudresourcemanager.googleapis.com/projects.delete` |

Deny policies override allow policies and are inherited down the hierarchy. A project Owner or an org admin still can't perform these actions unless they are in the break-glass group.

## policy/wif

Rego v1 policy, `package wif`, rule set `deny`. It reads `terraform show -json` output and checks every `google_iam_workload_identity_pool_provider` being created or updated. Replacements are checked too. Deletes, no-ops, and other resource types are ignored. A provider is flagged when:

1. `attribute_condition` is missing, null, or blank.
2. The OIDC issuer is GitHub Actions (`https://token.actions.githubusercontent.com`, including GHES issuers under that prefix) and the condition doesn't compare `assertion.repository_owner_id` to a numeric ID. Owner names can be renamed and later registered by someone else. The numeric ID can't.
3. The condition is trivially true: `true`, `!false`, `x == x`, or any of those joined at the top level with `||`.
4. It's an OIDC provider with no explicit `allowed_audiences`.

`wif_test.rego` has passing and failing cases for each rule, plus cases showing that deletes, no-ops, and unrelated resources are ignored.

## Why three layers

Each layer stops something the others miss.

- **Plan-time checks (OPA)** fail fast in a pull request and can express richer rules, like the owner ID check. They only see changes made through Terraform in pipelines that run the check. Someone using the console or `gcloud` skips them entirely.
- **Org policy** is enforced by the Google Cloud API for every caller and every client. It controls how a resource is configured, not who is configuring it. The custom constraint here only catches an empty condition, because a weak but non-empty condition is hard to express in CEL.
- **IAM deny** controls who can act at all, regardless of allow grants. A compromised Owner role can't create a service account key or a new identity provider. It says nothing about how a resource is configured once someone is allowed to create it.

Put together: OPA catches mistakes early, org policy blocks the clearly unsafe configurations no matter how they arrive, and the deny policy keeps the most sensitive operations limited to a small, audited group.

## Rollout order

1. **Run `policy/wif` in CI**, reporting only at first. Make it blocking once existing providers are fixed.
2. **Apply `org-policy` with `dry_run = true`.** This creates the managed and custom constraint policies in dry-run mode. Nothing is blocked. Check each constraint's Dry run tab, or the dry-run audit logs, for resources that would be rejected. Policy Simulator can also test managed constraints before you apply.
3. **Review existing usage for the legacy constraints.** Policy Simulator can't test legacy managed constraints, so check by hand: buckets that rely on ACLs or public access, projects that depend on a default network, service accounts with long-lived keys, IAM bindings for identities outside `allowed_customer_ids`, and existing WIF providers. `storage.publicAccessPrevention` also applies to existing buckets and objects, not just new ones.
4. **Set `dry_run = false`** and apply. If you need exceptions, add project or folder level policies before this step.
5. **Create the break-glass group and apply `iam-deny` last.** Deny policies have no dry-run mode. Any automation that creates WIF pools or providers, creates keys, or deletes projects must be in the break-glass group before you apply, or it will start failing.

## Usage

```hcl
module "org_policy" {
  source = "git::https://github.com/arthurpryor/gcp-security-guardrails.git//org-policy"

  organization_id         = "123456789012"
  dry_run                 = true
  allowed_customer_ids    = ["C0abc123d"]
  allowed_contact_domains = ["@example.com"]
  allowed_wif_issuers     = ["https://token.actions.githubusercontent.com"]

  # Optional
  allowed_wif_aws_accounts         = []
  service_account_key_expiry_hours = "24h"
}

module "iam_deny" {
  source = "git::https://github.com/arthurpryor/gcp-security-guardrails.git//iam-deny"

  organization_id   = "123456789012"
  break_glass_group = "break-glass@example.com"
}
```

Checking a plan with the WIF policy:

```sh
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
opa eval --fail-defined -d policy/ -i plan.json 'data.wif.deny[x]' -f pretty
```

`--fail-defined` exits 1 when there is at least one violation and 0 when there are none.

An attribute condition that passes all four rules:

```hcl
attribute_condition = "assertion.repository_owner_id == '123456' && assertion.repository_id == '654321'"
```

Running the checks locally:

```sh
terraform -chdir=org-policy init -backend=false && terraform -chdir=org-policy validate
terraform -chdir=iam-deny init -backend=false && terraform -chdir=iam-deny validate
opa fmt --fail -l policy/
opa test policy/ -v
```

## Requirements

- Terraform 1.5 or later
- `hashicorp/google` provider 6.14 or later for `org-policy` (the first release with `parameters` on org policy rules), and 6.0 or later for `iam-deny`. Validated against those minimums and 8.7.0.
- OPA 1.x (the policy uses Rego v1 syntax)
- Roles at the organization: `roles/orgpolicy.policyAdmin` for `org-policy` and `roles/iam.denyAdmin` for `iam-deny`

## Notes and caveats

- These modules have been checked with `terraform validate` and `terraform plan` but not applied to a live organization. Apply them to a test organization first.
- Newer organizations get several of these constraints automatically as part of Google's security baseline. If a constraint already has a policy at the org level, creating it fails. Import the existing policy into state first.
- `compute.managed.vmExternalIpAccess` blocks IPv4 external IPs on new and updated VMs. It doesn't restrict IPv6. To allow specific VMs, tag them and add a conditional rule.
- `iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` is stricter than the legacy constraint it replaces. It blocks granting Editor or Owner to the Compute Engine and App Engine default service accounts at any time, not only the automatic grant.
- If your organization already has policies on the legacy versions of the managed constraints (Google's security baseline creates some automatically), those are separate policies and stay in effect. Remove them once the managed versions are enforced if you want a single source of truth.
- `iam.workloadIdentityPoolProviders` and `iam.workloadIdentityPoolAwsAccounts` deny everything when their variables are empty. Set them before enforcing if you use WIF.
- `iam.serviceAccountKeyExpiryHours` can't be merged with a parent policy. It only matters where key creation is allowed through an exception to `iam.disableServiceAccountKeyCreation`.
- The custom constraint only checks for an empty string. A whitespace-only condition gets past it but is caught by the OPA policy. Because it enforces on `UPDATE`, an existing provider without a condition can't be changed until a condition is added.
- `principalSet://goog/public:all` covers every principal, including service accounts. A resource can have at most 500 deny rules across all of its deny policies.
- Denying `workloadIdentityPools.delete` and `workloadIdentityPoolProviders.delete` doesn't deny `undelete`. Add those permissions if you want them restricted too.
- The OPA policy matches strings. It doesn't parse CEL. The trivially-true check is a heuristic that catches common patterns and avoids flagging nested expressions. A condition that is unknown at plan time is reported as missing.
- Pinning `repository_owner_id` still trusts every repository under that owner. Pin `repository_id`, and a branch or environment where it makes sense.

## License

Apache 2.0. See [LICENSE](LICENSE).
