# SentinelCloud v1 spec §12, Layer B — centralized, cloud-agnostic policy.
#
# Same intent as the native guardrails already enforced per cloud
# (Azure Policy "deny-public-storage-accounts", GCP Org Policy
# "enforced public access prevention", and the equivalent posture AWS's
# public-access-block resources give S3) expressed ONCE here and checked
# against a Terraform plan's resource_changes, regardless of which cloud
# produced the plan.
#
# Input shape: a Terraform plan JSON's top-level object, specifically the
# `resource_changes` array (`terraform show -json` shape). This repo has
# no real `terraform plan` output yet (no cloud account — v1 spec §14),
# so `policy/opa/testdata/*.json` are SIMULATED plan fixtures, hand-built
# to match real provider schemas, same status as the architecture.json
# fixtures in threat-model/.

package policy.guardrails.storage

import rego.v1

# Azure: a storage account that allows public access to blobs in any
# container, even if no container currently opts in.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.allow_nested_items_to_be_public == true
	msg := sprintf("%s: azurerm_storage_account must set allow_nested_items_to_be_public = false", [rc.address])
}

# GCP: a bucket without public access prevention enforced.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	prevention := object.get(rc.change.after, "public_access_prevention", "inherited")
	prevention != "enforced"
	msg := sprintf("%s: google_storage_bucket must set public_access_prevention = \"enforced\"", [rc.address])
}

# AWS: an S3 public-access-block resource missing, or with any of its
# four protections turned off.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	some flag in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	object.get(rc.change.after, flag, false) == false
	msg := sprintf("%s: aws_s3_bucket_public_access_block must set %s = true", [rc.address, flag])
}

# AWS: a bucket that has no corresponding public-access-block resource at
# all is just as exposed as one with the flags turned off — a bucket
# should never be deployed without its block resource alongside it.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	bucket_name := rc.change.after.bucket
	not has_public_access_block(bucket_name)
	msg := sprintf("%s: aws_s3_bucket %v has no aws_s3_bucket_public_access_block resource", [rc.address, bucket_name])
}

has_public_access_block(bucket_name) if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	rc.change.after.bucket == bucket_name
}
