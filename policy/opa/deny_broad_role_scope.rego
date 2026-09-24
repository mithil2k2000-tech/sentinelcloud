# SentinelCloud v1 spec §12, Layer B — same intent as Azure's native
# "deny-owner-contributor-assignment" policy (modules/policy), generalized
# across all three clouds: no identity should ever hold a broad,
# account/project/subscription-wide administrative role, matching the
# least-privilege posture the Terraform IAM modules (and threat_engine.py's
# rule_broad_role_scope, IAM-BROAD-01) already enforce elsewhere.
#
# Input shape: see no_public_storage.rego. Fixtures are SIMULATED (§14).

package policy.guardrails.iam

import rego.v1

azure_broad_roles := {"Owner", "Contributor"}

gcp_broad_roles := {"roles/owner", "roles/editor"}

aws_admin_policy_arn := "arn:aws:iam::aws:policy/AdministratorAccess"

# Azure: a role assignment granting Owner or Contributor, at any scope —
# matches the existing native policy, which denies these roles outright
# rather than trying to judge "is this scope narrow enough".
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	role := rc.change.after.role_definition_name
	role in azure_broad_roles
	msg := sprintf("%s: azurerm_role_assignment must not grant %v — use a purpose-scoped custom role", [rc.address, role])
}

# GCP: a project-level IAM binding/member granting Owner or Editor.
deny contains msg if {
	some rc in input.resource_changes
	rc.type in {"google_project_iam_binding", "google_project_iam_member"}
	rc.change.after.role in gcp_broad_roles
	msg := sprintf("%s: %v must not grant %v at project scope — use a purpose-scoped custom role", [rc.address, rc.type, rc.change.after.role])
}

# AWS: a managed-policy attachment (role or user) granting full
# AdministratorAccess.
deny contains msg if {
	some rc in input.resource_changes
	rc.type in {"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"}
	rc.change.after.policy_arn == aws_admin_policy_arn
	msg := sprintf("%s: %v must not attach AdministratorAccess — use a scoped custom policy", [rc.address, rc.type])
}
