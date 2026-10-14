# Plan-time checks for Workload Identity Federation providers.
# Input: the output of `terraform show -json <planfile>`.
package wif

github_issuer := "https://token.actions.githubusercontent.com"

# Replacements show up as ["delete", "create"] or ["create", "delete"], so they are covered too.
providers contains rc if {
	some rc in input.resource_changes
	rc.type == "google_iam_workload_identity_pool_provider"
	some action in rc.change.actions
	action in {"create", "update"}
}

condition(rc) := c if {
	c := rc.change.after.attribute_condition
	is_string(c)
	trim_space(c) != ""
}

oidc(rc) := rc.change.after.oidc[0]

# Covers github.com and GHES issuers that append an enterprise slug.
is_github(rc) if startswith(oidc(rc).issuer_uri, github_issuer)

# Owner names can be renamed and re-registered; the numeric owner ID cannot.
pins_owner_id(c) if regex.match(`assertion\.repository_owner_id\s*(==\s*['"][0-9]+['"]|in\s*\[\s*['"][0-9]+['"])`, c)

# Catches conditions that are always true, either outright or through a top-level `|| true`.
# Splitting on || is a heuristic; terms with unbalanced parentheses never match an atom, so
# nested expressions like `a && (b || true)` are not flagged.
trivially_true(c) if {
	some term in split(regex.replace(c, `\s+`, ""), "||")
	trivial_atom(strip_parens(term))
}

strip_parens(t) := substring(t, n, count(t) - (2 * n)) if {
	lead := count(t) - count(trim_left(t, "("))
	trail := count(t) - count(trim_right(t, ")"))
	n := min([lead, trail])
}

trivial_atom(t) if t in {"true", "!false"}

trivial_atom(t) if {
	sides := split(t, "==")
	count(sides) == 2
	sides[0] != ""
	sides[0] == sides[1]
}

has_audiences(o) if count(o.allowed_audiences) > 0

deny contains msg if {
	some rc in providers
	not condition(rc)
	msg := sprintf("%s: attribute_condition is missing or empty", [rc.address])
}

deny contains msg if {
	some rc in providers
	is_github(rc)
	c := condition(rc)
	not pins_owner_id(c)
	msg := sprintf("%s: GitHub Actions provider must pin assertion.repository_owner_id to a numeric ID", [rc.address])
}

deny contains msg if {
	some rc in providers
	c := condition(rc)
	trivially_true(c)
	msg := sprintf("%s: attribute_condition is trivially true", [rc.address])
}

deny contains msg if {
	some rc in providers
	o := oidc(rc)
	not has_audiences(o)
	msg := sprintf("%s: OIDC provider must set allowed_audiences explicitly", [rc.address])
}
