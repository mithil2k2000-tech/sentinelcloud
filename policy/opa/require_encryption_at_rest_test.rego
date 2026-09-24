package policy.guardrails.encryption

import rego.v1

test_azure_missing_infra_encryption_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "azurerm_storage_account.customer",
		"type": "azurerm_storage_account",
		"change": {"after": {"infrastructure_encryption_enabled": false}},
	}]}
}

test_azure_infra_encryption_enabled_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_storage_account.customer",
		"type": "azurerm_storage_account",
		"change": {"after": {"infrastructure_encryption_enabled": true}},
	}]}
}

test_gcp_missing_cmek_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "google_storage_bucket.customer",
		"type": "google_storage_bucket",
		"change": {"after": {"name": "customer-storage"}},
	}]}
}

test_gcp_cmek_bound_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "google_storage_bucket.customer",
		"type": "google_storage_bucket",
		"change": {"after": {"encryption": {"default_kms_key_name": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}}},
	}]}
}

test_aws_bucket_without_sse_config_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.customer",
		"type": "aws_s3_bucket",
		"change": {"after": {"bucket": "customer-storage"}},
	}]}
}

test_aws_sse_config_with_aes256_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.customer",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {"after": {
			"bucket": "customer-storage",
			"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}],
		}},
	}]}
}

test_aws_sse_config_with_kms_allowed if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.customer",
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "customer-storage"}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.customer",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {
				"bucket": "customer-storage",
				"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "aws:kms"}}],
			}},
		},
	]}
}
