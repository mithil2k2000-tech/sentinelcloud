package policy.guardrails.iam

import rego.v1

test_azure_owner_assignment_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "azurerm_role_assignment.payment_service",
		"type": "azurerm_role_assignment",
		"change": {"after": {"role_definition_name": "Owner"}},
	}]}
}

test_azure_contributor_assignment_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "azurerm_role_assignment.payment_service",
		"type": "azurerm_role_assignment",
		"change": {"after": {"role_definition_name": "Contributor"}},
	}]}
}

test_azure_custom_role_assignment_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_role_assignment.payment_service",
		"type": "azurerm_role_assignment",
		"change": {"after": {"role_definition_name": "IAM-004-payment-service-data-access"}},
	}]}
}

test_gcp_owner_binding_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "google_project_iam_member.payment_service",
		"type": "google_project_iam_member",
		"change": {"after": {"role": "roles/owner"}},
	}]}
}

test_gcp_custom_role_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "google_project_iam_member.payment_service",
		"type": "google_project_iam_member",
		"change": {"after": {"role": "projects/p/roles/payment_data_access"}},
	}]}
}

test_aws_admin_policy_attachment_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_iam_role_policy_attachment.payment_service",
		"type": "aws_iam_role_policy_attachment",
		"change": {"after": {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
	}]}
}

test_aws_scoped_policy_attachment_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_iam_role_policy_attachment.payment_service",
		"type": "aws_iam_role_policy_attachment",
		"change": {"after": {"policy_arn": "arn:aws:iam::123456789012:policy/payment-data-access"}},
	}]}
}
