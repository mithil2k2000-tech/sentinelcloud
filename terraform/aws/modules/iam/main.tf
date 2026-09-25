# IAM module — IRSA (IAM Roles for Service Accounts): each workload gets
# its own IAM role, assumable only by its specific Kubernetes service
# account via the cluster's OIDC provider, with a policy scoped to exactly
# the resource it needs. This is the AWS equivalent of Azure's workload
# identity + custom-role pattern and GCP's per-workload service account.
#
# Nobody gets AdministratorAccess or a wildcard "s3:*" on "*" — that's the
# control encoded here for control IAM-004.

data "aws_iam_policy_document" "payment_service_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:default:payment-service"]
    }
  }
}

resource "aws_iam_role" "payment_service" {
  name               = "${var.project_name}-payment-service-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.payment_service_trust.json
}

data "aws_iam_policy_document" "payment_data_access" {
  statement {
    sid     = "IAM004PaymentDataAccess"
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    # Scoped to the ONE bucket, not "*" — the exact fix for the "excessive
    # IAM permissions" / "payment service unrestricted access" findings.
    resources = [
      var.payments_bucket_arn,
      "${var.payments_bucket_arn}/*",
    ]
  }
}

resource "aws_iam_policy" "payment_data_access" {
  name   = "IAM-004-payment-service-data-access-${var.environment}"
  policy = data.aws_iam_policy_document.payment_data_access.json
}

resource "aws_iam_role_policy_attachment" "payment_service_scoped" {
  role       = aws_iam_role.payment_service.name
  policy_arn = aws_iam_policy.payment_data_access.arn
}

# Phase 4 (Zero Trust, RR-02): account-service's identity, closing the
# gap the comment above used to describe. Same IRSA shape as
# payment-service, scoped to the one secret it actually needs.

data "aws_iam_policy_document" "account_service_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:default:account-service"]
    }
  }
}

resource "aws_iam_role" "account_service" {
  name               = "${var.project_name}-account-service-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.account_service_trust.json
}

data "aws_iam_policy_document" "account_service_secrets_access" {
  statement {
    sid     = "IAM004AccountServiceSecretsAccess"
    effect  = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    # Scoped to the ONE secret, not "*" — same pattern as
    # payment_data_access above.
    resources = [var.app_secrets_arn]
  }
}

resource "aws_iam_policy" "account_service_secrets_access" {
  name   = "IAM-004-account-service-secrets-access-${var.environment}"
  policy = data.aws_iam_policy_document.account_service_secrets_access.json
}

resource "aws_iam_role_policy_attachment" "account_service_scoped" {
  role       = aws_iam_role.account_service.name
  policy_arn = aws_iam_policy.account_service_secrets_access.arn
}
