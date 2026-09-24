# Storage module — the S3 equivalent of Azure's storage module: this is
# the exact resource the roadmap's "Storage bucket publicly accessible"
# example gate is about. Every knob here defaults closed.

resource "aws_s3_bucket" "customer_data" {
  bucket = "${var.project_name}-customer-data-${var.environment}"
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs disabled entirely — IAM only
  }
}
