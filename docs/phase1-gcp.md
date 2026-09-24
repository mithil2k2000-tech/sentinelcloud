# Phase 1 — GCP Security Foundation

Status: **Terraform scaffold written and run through the threat-model agent.**
Not applied to a real project (no GCP project available in this environment).

## What was built

| Concept | Where | What it does |
|---|---|---|
| IAM | `modules/iam` | One service account per workload (`payment-service`, `account-service`); a custom IAM role (`payment_data_access`) with only the three storage permissions payment-service actually needs, bound at the specific bucket — never `roles/owner`/`roles/editor`. |
| VPC | `modules/network` | One VPC, four subnets as trust boundaries (gateway/gke/data/mgmt), same layout as Azure/AWS. |
| Firewall rules | `modules/network` | Deny-all-ingress baseline plus explicit allow rules scoped by network **tags** (not CIDR-to-CIDR, which isn't how GCP firewalls select instances) — GKE nodes get the `gke` tag so the gateway→gke and gke→data rules actually bind to them. |
| Secret Manager / KMS | `modules/secrets` | A customer-managed KMS key (90-day rotation) encrypting a Secret Manager secret replica. |
| Cloud Storage security | `modules/storage` | Uniform bucket-level access (disables ACLs entirely), `public_access_prevention = enforced`, CMEK encryption, versioning. |
| Org Policy | `modules/policy` | Four project-level constraints: no external IPs on VMs, enforced public-access prevention, required Shielded VM, disabled service-account key creation (forces workload identity instead of downloadable keys). |
| GKE | `modules/gke` | Private cluster (no public control-plane endpoint unless `authorized_cidrs` is set), Workload Identity, Calico network policy, Shielded nodes, secondary ranges for pod/service IPs. |

## Real gap this scaffold caught in itself

Cross-cloud consistency turned out to matter in practice, not just in theory: an early draft of `modules/network`'s firewall rules used a `destination_ranges` filter on **INGRESS** rules to restrict traffic to a subnet CIDR. That's not how GCP firewalls work — INGRESS rules select target *instances* via network tags (or service accounts), not a destination CIDR; `destination_ranges` only applies to EGRESS rules. `terraform validate` wouldn't have caught this either (it's an API-level semantic constraint, not a schema error) — it would have failed at `apply` against a real project. Fixed by switching to `target_tags`/`source_tags` and tagging the GKE node pool `["gke"]` to match. Recorded here rather than silently corrected, because it's a good example of why "the LLM writes IaC" and "the IaC is actually correct for that cloud's model" are two different claims.

## Run through the threat-model agent

`threat-model/architecture-hardened-gcp.json` → `agent/analyze.py`:

- 6 findings, 0 CRITICAL, 2 HIGH, 4 MEDIUM. Overall risk HIGH, blocked (default threshold).
- The two HIGH findings: no application-layer auth on `account-service → secrets-kms` (this one's a bit sharper than Azure's equivalent, because `account-service` has no IAM binding *and* a flow into a `critical`-sensitivity asset, which the engine scores higher than a flow into a merely `high`-sensitivity one), and no centralized logging (same Phase 9 gap as every cloud so far).
- One genuine improvement over the current Azure scaffold: `payment-service`'s IAM binding is scoped to the specific bucket resource, not a resource group — worth backporting to Azure once a real payments resource exists there to scope against.

Full findings: `threat-model/report-hardened-gcp.json`.

## Next steps

1. Get a real GCP project (free tier), `gcloud auth login`, set a GCS backend for state.
2. Fill in `environments/dev.tfvars` from the `.example`, `terraform init && plan`.
3. Close the two HIGH findings: bind `account-service` to Secret Manager via IAM (not left unauthenticated), wire Cloud Logging + a log sink (Phase 9).
4. Add this scaffold to the CI workflow alongside Azure once there's a real project to validate against.
