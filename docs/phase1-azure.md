# Phase 1 — Azure Security Foundation

Status: **Terraform scaffold written** (`terraform/azure/`). Not yet applied to a
real subscription — that's a deliberate choice (see "Why this isn't applied yet"
below).

This doc explains each control the scaffold implements, why it matters, and
where to look in the code.

## What was built

| Concept | Where | What it does |
|---|---|---|
| Entra ID | `modules/iam` | One app registration + service principal per microservice (`payment_service`, `account_service`) instead of shared credentials. |
| RBAC | `modules/iam` | Custom `azurerm_role_definition`s scoped to exactly what a workload needs (e.g. `IAM-004-payment-service-data-access` reaches only the payments container) — no built-in Owner/Contributor ever assigned to a workload identity. |
| VNets | `modules/network` | One VNet, four subnets as trust boundaries: `gateway` (internet-facing), `aks` (workloads), `data` (private endpoints only), `mgmt` (admin access). |
| NSGs | `modules/network` | Deny-by-default on every subnet; only the specific adjacent-subnet traffic needed is allowed (e.g. `data` subnet only accepts inbound 443 from the `aks` subnet CIDR — this is the actual fix for the roadmap's "payment service → unrestricted database access" example). |
| Key Vault | `modules/keyvault` | RBAC-authorized (not legacy access policies), public network access disabled, reachable only via private endpoint, purge protection on. |
| Storage security | `modules/storage` | Public access disabled, shared-key auth disabled (Entra ID/RBAC only), TLS 1.2 minimum, blob versioning + soft delete, private endpoint only. |
| Azure Policy | `modules/policy` | Three custom deny policies (`deny-public-storage-accounts`, `require-encryption-at-rest`, `deny-owner-contributor-assignment`) bundled into one initiative and assigned at subscription scope — these are the guardrails that turn a bad `terraform plan` into a blocked deployment. |
| Defender for Cloud | referenced in `modules/aks` (`microsoft_defender` block, workspace wired up in Phase 9) | Placeholder — full config lands with the SIEM/logging module. |
| Monitor | referenced, not yet built | Diagnostic settings + Log Analytics workspace land in Phase 9. |
| AKS | `modules/aks` | Private cluster (no public API server), Entra-only auth (`local_account_disabled`), Azure RBAC, Azure CNI + network policy for pod segmentation, workload identity + OIDC instead of pod secrets, Azure Policy add-on enabled so the guardrail initiative is enforced *inside* the cluster too. |

## How this maps to the threat-model example

The roadmap's worked example was:

```
Finding:  Payment service → unrestricted database access
Threat:   Compromised payment container could access unnecessary customer records
Severity: HIGH
Control:  IAM-004 — least-privilege IAM + database segmentation
Policy:   Payment service may access only payments_db.transactions
```

Three independent layers now enforce that, so a single misconfiguration can't
reopen the hole:

1. **Network** — the `data` subnet NSG only accepts traffic from the `aks`
   subnet, and only on 443.
2. **Identity** — `payment_service`'s only role assignment is the
   `IAM-004-payment-service-data-access` custom role, scoped to the payments
   resource, not the resource group or subscription.
3. **Policy** — `deny-owner-contributor-assignment` blocks anyone (human or
   pipeline) from ever assigning that service principal Owner/Contributor as
   a "quick fix" later.

## Why this isn't applied yet

Terraform `plan`/`apply` need a real Azure subscription and credentials,
which this environment doesn't have. Rather than block on that, the scaffold
was validated the way it can be right now:

- Every `.tf` file parses as valid HCL2 (`python-hcl2`, 20/20 files clean).
- The module boundaries and variable/output contracts were hand-checked for
  consistency (e.g. every module that needs `data_subnet_id` receives it
  from `module.network.subnet_ids["data"]` in the root `main.tf`).

Next real steps, when there's a subscription to point at:

1. Create a free-tier Azure subscription, `az login`, set up a remote state
   backend (private storage account, RBAC-only, versioned).
2. Copy `environments/dev.tfvars.example` → `dev.tfvars`, fill in a real
   `allowed_admin_cidrs`.
3. `terraform init && terraform plan -var-file=environments/dev.tfvars` and
   review the plan by hand before ever running `apply`.
4. Wire up Phase 2's IaC security scanner (Checkov or tfsec) to run against
   this plan in CI before it's ever allowed to reach `apply`.

## Job-requirement mapping

- Entra ID / RBAC / least-privilege IAM → `modules/iam`
- Network segmentation / Zero Trust groundwork → `modules/network`
- Key Vault / secrets management → `modules/keyvault`
- Data security / encryption → `modules/storage`, `require-encryption-at-rest` policy
- Policy-as-code / governance → `modules/policy`
- AKS / Kubernetes security → `modules/aks`
