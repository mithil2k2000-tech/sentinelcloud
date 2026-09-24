# SentinelCloud v1 spec §12, Layer B — same intent as the native
# encryption guardrails (Azure Policy "require-encryption-at-rest", GCP's
# CMEK bindings, AWS's SSE-KMS default) expressed once, cloud-agnostically.
#
# Input shape: see no_public_storage.rego — a Terraform plan's
# `resource_changes` array. Fixtures here are SIMULATED (v1 spec §14),
# same status as elsewhere in this repo.

package policy.guardrails.encryption

import rego.v1

# Azure: storage account without infrastructure (double) encryption.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	object.get(rc.change.after, "infrastructure_encryption_enabled", false) == false
	msg := sprintf("%s: azurerm_storage_account must set infrastructure_encryption_enabled = true", [rc.address])
}

# GCP: bucket without a customer-managed encryption key bound.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	kms_key := object.get(object.get(rc.change.after, "encryption", {}), "default_kms_key_name", "")
	kms_key == ""
	msg := sprintf("%s: google_storage_bucket must set encryption.default_kms_key_name (CMEK)", [rc.address])
}

# AWS: a bucket with no server-side-encryption configuration resource at
# all — as exposed to "written to disk unencrypted" as one with a weak
# algorithm.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	bucket_name := rc.change.after.bucket
	not has_encryption_config(bucket_name)
	msg := sprintf("%s: aws_s3_bucket %v has no aws_s3_bucket_server_side_encryption_configuration resource", [rc.address, bucket_name])
}

# AWS: a bucket with an SSE configuration that isn't using KMS (e.g. plain
# AES256 with an AWS-managed key rather than a customer-managed KMS key —
# matches the "customer-managed key" bar the other two clouds are held to).
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	some rule in object.get(rc.change.after, "rule", [])
	algo := object.get(object.get(rule, "apply_server_side_encryption_by_default", {}), "sse_algorithm", "")
	algo != "aws:kms"
	msg := sprintf("%s: aws_s3_bucket_server_side_encryption_configuration must use sse_algorithm = \"aws:kms\" (customer-managed key), got %v", [rc.address, algo])
}

has_encryption_config(bucket_name) if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.change.after.bucket == bucket_name
}
