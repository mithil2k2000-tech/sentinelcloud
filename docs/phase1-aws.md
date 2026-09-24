# Phase 1 — AWS Security Foundation

Status: **Terraform scaffold written and run through the threat-model agent.**
Not applied to a real account (no AWS account available in this environment).

## What was built

| Concept | Where | What it does |
|---|---|---|
| IAM | `modules/iam` | IRSA (IAM Roles for Service Accounts): `payment-service` gets an IAM role assumable only by its specific Kubernetes service account via the cluster's OIDC provider, with a policy scoped to exactly one S3 bucket ARN — never `AdministratorAccess` or a wildcard `s3:*` on `*`. |
| VPC | `modules/network` | One VPC, four subnets as trust boundaries (gateway/eks/data/mgmt); only the gateway subnet has a route to the internet gateway — eks/data/mgmt are private by default, no default route out. |
| Security groups | `modules/network` | Deny-by-default (no ingress unless stated); cross-tier rules reference the *source security group*, not a CIDR — e.g. the data-tier SG only accepts 443 from the eks SG, matching Azure's NSG / GCP's tag-based firewall control. |
| Secrets Manager / KMS | `modules/secrets` | Customer-managed KMS key with rotation, encrypting a Secrets Manager secret with a 30-day recovery window (blocks instant/accidental permanent deletion). |
| S3 security | `modules/storage` | Full public-access block (all four flags), default SSE-KMS encryption, versioning, bucket-owner-enforced ownership (disables ACLs entirely — IAM only). |
| AWS Config (policy-as-code) | `modules/policy` | Five managed Config rules: S3 public read/write prohibited, encrypted volumes, no IAM policies with admin access, restricted SSH — plus the recorder/delivery-channel/IAM-role plumbing Config needs to actually run. (True SCPs need an AWS Organization; Config rules work at single-account scope too, so they're the more portable choice here.) |
| EKS | `modules/eks` | Private-by-default API endpoint (public access only if `authorized_cidrs` is set, never `0.0.0.0/0`), control-plane audit/API/authenticator logging enabled, secrets envelope-encrypted with a dedicated KMS key, OIDC provider for IRSA. |

## Real gap this scaffold caught in itself

The IAM OIDC provider for the EKS cluster needs a certificate thumbprint. An
early draft left `thumbprint_list = []`, reasoning that AWS auto-verifies
via its managed root CA — true in the console, but not a safe assumption to
hardcode into Terraform across provider versions. Fixed by adding a
`tls_certificate` data source that fetches the cluster OIDC issuer's actual
thumbprint at apply time, which is the pattern AWS/HashiCorp document as
correct regardless of provider version. Same lesson as the GCP firewall
issue: written once, checked again before calling it done.

## Run through the threat-model agent

`threat-model/architecture-hardened-aws.json` → `agent/analyze.py`:

- 6 findings, 0 CRITICAL, 2 HIGH, 4 MEDIUM — same shape as GCP's result,
  which makes sense: it's the same architecture pattern on a different
  cloud, so it should have the same gaps unless one cloud's scaffold is
  actually more complete than the other's.
- HIGH findings: no application-layer auth on `account-service →
  secrets-manager`, no centralized logging (CloudTrail isn't wired up yet
  — Config rules catch configuration drift, but there's no log *sink*,
  which is a distinct gap; Phase 9 closes both).

Full findings: `threat-model/report-hardened-aws.json`.

## Next steps

1. Get a real AWS account (free tier covers most of this), configure
   credentials, set an S3+DynamoDB backend for state.
2. Fill in `environments/dev.tfvars` from the `.example`, `terraform init && plan`.
3. Close the two HIGH findings: bind `account-service`'s own IRSA role once
   it needs Secrets Manager access, wire CloudTrail + a central log
   destination (Phase 9).
4. `aws_eks_node_group` currently uses a single subnet — real deployments
   should spread node groups across the two data-tier AZs already created
   in `modules/network` for actual high availability.
