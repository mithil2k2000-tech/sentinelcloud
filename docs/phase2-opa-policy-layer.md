# Phase 2 — Centralized OPA/Rego Policy Layer (SentinelCloud v1 spec, §12 Layer B)

Status: **written and tested for real**, against a real Rego interpreter —
not eyeballed syntax. 22 tests, all passing. Never yet run against a real
`terraform plan` (no cloud account — same honest limitation as everywhere
else in this project, see §14 of the v1 spec).

## What this layer is for

The native guardrails already built in Phase 1 (`terraform/{azure,gcp,aws}/modules/policy`)
enforce real controls, but each one is written in that cloud's own
policy language — an Azure Policy definition, a GCP Org Policy constraint,
an AWS Config rule. There's no single place that says "no public storage"
once and checks it against all three. `policy/opa/` is that place: three
Rego policies, each expressing one guardrail's *intent* once, and checking
it against a normalized shape any cloud's Terraform plan JSON can be read
into (`resource_changes`, the shape `terraform show -json` actually
produces).

| Policy | Package | Mirrors (Layer A, already native) |
|---|---|---|
| `no_public_storage.rego` | `policy.guardrails.storage` | Azure "deny-public-storage-accounts", GCP enforced `public_access_prevention`, AWS S3 public-access-block |
| `require_encryption_at_rest.rego` | `policy.guardrails.encryption` | Azure "require-encryption-at-rest", GCP CMEK binding, AWS SSE-KMS |
| `deny_broad_role_scope.rego` | `policy.guardrails.iam` | Azure "deny-owner-contributor-assignment", generalized to GCP's `roles/owner`/`roles/editor` and AWS's `AdministratorAccess` managed policy |

This doesn't replace the native policies (v1 spec §12 explains why: they
still catch a violation even if this layer is down). It's a second,
independent, cloud-agnostic check — and in writing it, it already caught
real gaps the native-only view didn't have a way to express, like "does
this S3 bucket even have a `aws_s3_bucket_public_access_block` resource at
all" — a cross-resource check no single Config rule states as directly.

## How this got tested without the real `opa` binary

The build sandbox can't reach `openpolicyagent.org` to download `opa`
(same network-allowlist restriction that blocked the `terraform` CLI —
see `docs/phase1-azure.md`). Rather than leave 22 Rego assertions
unverified, `tools/rego-test-runner/` is a small Rust program (built
against [`regorus`](https://github.com/microsoft/regorus), Microsoft's
independent Rego interpreter, pulled from crates.io which *is*
reachable here) that:

1. Loads every `.rego` file under a directory into a real Rego engine.
2. Discovers OPA-convention `test_*` rules in `*_test.rego` files.
3. Evaluates each one and checks it's `true` — the same pass/fail rule
   `opa test` itself uses.

This is a genuine evaluation of real Rego semantics against the real
policy files — not a syntax guess, and it caught two real mistakes before
they shipped: an unsupported `%q` `sprintf` verb (Rego only supports a
subset of Go's format verbs), and a test written with invalid
`deny contains _ with input as ...` query syntax (fixed to
`count(deny) > 0 with input as ...`). Both are exactly the class of error
a "looks right" read-through would have missed.

**What it doesn't replicate:** `opa test`'s CLI output format, coverage
reporting, and the full OPA conformance-test suite behind the reference
implementation. The CI workflow's `opa-policy-test` job uses the real
`open-policy-agent/setup-opa` action and the real `opa test` binary — this
tool is a local, honest stand-in for the sandbox this was built in, not a
long-term replacement.

## Running it yourself

With the real `opa` CLI (what CI actually uses):

```bash
opa test policy/opa -v
```

With the local substitute (what was actually run to verify this phase, in
an environment where `opa` itself isn't reachable):

```bash
cd tools/rego-test-runner
cargo build --release
./target/release/rego-test-runner ../../policy/opa
```

Both read the exact same `.rego` files — nothing about the policies
themselves is written differently for one runner versus the other.

## Next steps for this piece

1. Add a real `terraform show -json` → `resource_changes` translation
   step once a cloud account exists (v1 spec §14, REAL CLOUD stretch
   goal) — today's fixtures are hand-built JSON, same SIMULATED status as
   `threat-model/architecture-*.json`.
2. Add policies for the remaining native guardrails not yet mirrored here
   (Azure's AKS-hardening baseline, GCP's Shielded-VM/no-external-IP
   constraints, AWS's restricted-SSH Config rule).
3. Wire this layer's `deny` output into `agent/analyze.py`'s aggregation
   alongside the threat engine's findings, so a Terraform-level policy
   violation and an architecture-level threat-engine finding show up in
   one unified report instead of two separate tools a reviewer has to
   check by hand.
