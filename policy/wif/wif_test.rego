package wif_test

import data.wif

addr := "google_iam_workload_identity_pool_provider.github"

github_oidc := [{
	"issuer_uri": "https://token.actions.githubusercontent.com",
	"allowed_audiences": ["https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"],
	"jwks_json": null,
}]

good_condition := "assertion.repository_owner_id == '123456' && assertion.repository_id == '654321'"

provider(overrides) := object.union(
	{"attribute_condition": good_condition, "aws": [], "oidc": github_oidc},
	overrides,
)

plan(actions, after) := {"resource_changes": [{
	"address": addr,
	"mode": "managed",
	"type": "google_iam_workload_identity_pool_provider",
	"name": "github",
	"change": {"actions": actions, "after": after},
}]}

msg_missing := sprintf("%s: attribute_condition is missing or empty", [addr])

msg_owner := sprintf("%s: GitHub Actions provider must pin assertion.repository_owner_id to a numeric ID", [addr])

msg_trivial := sprintf("%s: attribute_condition is trivially true", [addr])

msg_audience := sprintf("%s: OIDC provider must set allowed_audiences explicitly", [addr])

# Baseline

test_compliant_provider_passes if {
	count(wif.deny) == 0 with input as plan(["create"], provider({}))
}

# attribute_condition missing or empty

test_missing_condition_denied if {
	msg_missing in wif.deny with input as plan(["create"], object.remove(provider({}), ["attribute_condition"]))
}

test_null_condition_denied if {
	msg_missing in wif.deny with input as plan(["create"], provider({"attribute_condition": null}))
}

test_empty_condition_denied if {
	msg_missing in wif.deny with input as plan(["create"], provider({"attribute_condition": ""}))
}

test_whitespace_condition_denied if {
	msg_missing in wif.deny with input as plan(["create"], provider({"attribute_condition": "   "}))
}

test_present_condition_not_flagged_as_missing if {
	not msg_missing in wif.deny with input as plan(["create"], provider({}))
}

# GitHub owner ID pinning

test_github_owner_name_denied if {
	msg_owner in wif.deny with input as plan(["create"], provider({"attribute_condition": "assertion.repository_owner == 'example-org'"}))
}

test_github_repository_name_only_denied if {
	msg_owner in wif.deny with input as plan(["create"], provider({"attribute_condition": "assertion.repository == 'example-org/example-repo'"}))
}

test_github_owner_id_non_numeric_denied if {
	msg_owner in wif.deny with input as plan(["create"], provider({"attribute_condition": "assertion.repository_owner_id == 'example-org'"}))
}

test_github_ghes_issuer_checked if {
	oidc := [object.union(github_oidc[0], {"issuer_uri": "https://token.actions.githubusercontent.com/example-enterprise"})]
	msg_owner in wif.deny with input as plan(["create"], provider({"oidc": oidc, "attribute_condition": "assertion.repository_owner == 'example-org'"}))
}

test_github_owner_id_equality_passes if {
	not msg_owner in wif.deny with input as plan(["create"], provider({"attribute_condition": "assertion.repository_owner_id==\"123456\""}))
}

test_github_owner_id_in_list_passes if {
	not msg_owner in wif.deny with input as plan(["create"], provider({"attribute_condition": "assertion.repository_owner_id in ['123456', '234567']"}))
}

test_non_github_issuer_not_checked_for_owner_id if {
	oidc := [object.union(github_oidc[0], {"issuer_uri": "https://gitlab.example.com"})]
	count(wif.deny) == 0 with input as plan(["create"], provider({"oidc": oidc, "attribute_condition": "assertion.namespace_id == '42'"}))
}

# Trivially true conditions

test_literal_true_denied if {
	msg_trivial in wif.deny with input as plan(["create"], provider({"attribute_condition": "true"}))
}

test_parenthesized_true_denied if {
	msg_trivial in wif.deny with input as plan(["create"], provider({"attribute_condition": " (( true )) "}))
}

test_not_false_denied if {
	msg_trivial in wif.deny with input as plan(["create"], provider({"attribute_condition": "!false"}))
}

test_self_equality_denied if {
	msg_trivial in wif.deny with input as plan(["create"], provider({"attribute_condition": "1 == 1"}))
}

test_or_true_denied if {
	msg_trivial in wif.deny with input as plan(["create"], provider({"attribute_condition": "assertion.repository_owner_id == '123456' || true"}))
}

test_nested_or_true_not_flagged if {
	c := "assertion.repository_owner_id == '123456' && (assertion.ref == 'refs/heads/main' || true)"
	not msg_trivial in wif.deny with input as plan(["create"], provider({"attribute_condition": c}))
}

test_real_condition_not_trivial if {
	not msg_trivial in wif.deny with input as plan(["create"], provider({}))
}

# OIDC allowed_audiences

test_null_audiences_denied if {
	oidc := [object.union(github_oidc[0], {"allowed_audiences": null})]
	msg_audience in wif.deny with input as plan(["create"], provider({"oidc": oidc}))
}

test_empty_audiences_denied if {
	oidc := [object.union(github_oidc[0], {"allowed_audiences": []})]
	msg_audience in wif.deny with input as plan(["create"], provider({"oidc": oidc}))
}

test_missing_audiences_denied if {
	oidc := [object.remove(github_oidc[0], ["allowed_audiences"])]
	msg_audience in wif.deny with input as plan(["create"], provider({"oidc": oidc}))
}

test_explicit_audiences_pass if {
	not msg_audience in wif.deny with input as plan(["create"], provider({}))
}

test_aws_provider_not_checked_for_audiences if {
	aws := provider({"oidc": [], "aws": [{"account_id": "123456789012"}], "attribute_condition": "attribute.aws_role == 'example-role'"})
	count(wif.deny) == 0 with input as plan(["create"], aws)
}

# Actions

test_update_checked if {
	msg_missing in wif.deny with input as plan(["update"], provider({"attribute_condition": ""}))
}

test_replace_checked if {
	msg_missing in wif.deny with input as plan(["delete", "create"], provider({"attribute_condition": ""}))
}

test_delete_ignored if {
	count(wif.deny) == 0 with input as plan(["delete"], null)
}

test_no_op_ignored if {
	count(wif.deny) == 0 with input as plan(["no-op"], provider({"attribute_condition": ""}))
}

# Unrelated resources

test_unrelated_resource_ignored if {
	unrelated := {"resource_changes": [{
		"address": "google_storage_bucket.logs",
		"mode": "managed",
		"type": "google_storage_bucket",
		"name": "logs",
		"change": {"actions": ["create"], "after": {"name": "example-logs"}},
	}]}
	count(wif.deny) == 0 with input as unrelated
}

test_empty_plan_passes if {
	count(wif.deny) == 0 with input as {"resource_changes": []}
}
