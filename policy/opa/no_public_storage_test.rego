package policy.guardrails.storage

import rego.v1

test_azure_public_nested_items_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "azurerm_storage_account.customer",
		"type": "azurerm_storage_account",
		"change": {"after": {"allow_nested_items_to_be_public": true}},
	}]}
}

test_azure_private_nested_items_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_storage_account.customer",
		"type": "azurerm_storage_account",
		"change": {"after": {"allow_nested_items_to_be_public": false}},
	}]}
}

test_gcp_missing_prevention_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "google_storage_bucket.customer",
		"type": "google_storage_bucket",
		"change": {"after": {"name": "customer-storage"}},
	}]}
}

test_gcp_enforced_prevention_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "google_storage_bucket.customer",
		"type": "google_storage_bucket",
		"change": {"after": {"public_access_prevention": "enforced"}},
	}]}
}

test_aws_missing_block_flag_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.customer",
		"type": "aws_s3_bucket_public_access_block",
		"change": {"after": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": false,
			"restrict_public_buckets": true,
		}},
	}]}
}

test_aws_all_flags_true_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.customer",
		"type": "aws_s3_bucket_public_access_block",
		"change": {"after": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		}},
	}]}
}

test_aws_bucket_without_block_resource_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.customer",
		"type": "aws_s3_bucket",
		"change": {"after": {"bucket": "customer-storage"}},
	}]}
}

test_aws_bucket_with_block_resource_allowed if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.customer",
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "customer-storage"}},
		},
		{
			"address": "aws_s3_bucket_public_access_block.customer",
			"type": "aws_s3_bucket_public_access_block",
			"change": {"after": {
				"bucket": "customer-storage",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
	]}
}
