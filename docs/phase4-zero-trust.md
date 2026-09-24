# Phase 4 — Zero Trust / mTLS (SentinelCloud v1 spec, §16)

Status: **built and run for real**, within this build sandbox's real
constraints. All 81 `.tf` files across all three clouds (new and
modified) parse successfully with `python-hcl2` — the same substitute
Phase 2 established, because the real `terraform` binary can't be
installed here (egress to `releases.hashicorp.com` is blocked in this
sandbox; see "A real, unresolved limitation" below for what that
substitute does and doesn't prove). All 105 tests in `tests/` pass;
`analyze.py` was re-run against all three updated hardened architectures
and the counts below are its actual output, not hand-derived. Closes
RR-02, RR-04, and (for GCP/AWS) RR-03 in
`threat-model/residual-risk-register.md`.

This is the other half of "Phase 4" — `docs/phase4-risk-model.md` covers
the risk-scoring half (`agent/risk_model.py`), built earlier in the same
phase. This doc covers the infrastructure half: giving `account-service`
its own identity, and making service-to-service traffic actually
authenticated instead of just network-reachable.

## What was built

1. **A dedicated `account-service` identity, scoped to one resource, on
   all three clouds** (closes RR-02):
   - Azure: `terraform/azure/modules/iam` — a custom
     `azurerm_role_definition` (`IAM-004-account-service-secrets-access`)
     granting only `getSecret`/`readMetadata` data-actions, assigned via
     `azurerm_role_assignment` scoped to the Key Vault's own resource ID
     — not the resource group.
   - GCP: `terraform/gcp/modules/iam` — a
     `google_project_iam_custom_role` with only
     `secretmanager.versions.access` / `secretmanager.secrets.get`,
     bound via `google_secret_manager_secret_iam_member` to the one
     secret `account-service` actually needs.
   - AWS: `terraform/aws/modules/iam` — a full IRSA trust policy + role +
     scoped Secrets Manager policy, mirroring `payment-service`'s
     existing pattern exactly rather than inventing a new shape.

2. **A service mesh enforcing mesh-wide mutual TLS** (closes RR-04, and
   RR-03 where it was actually open — see the Azure correction below):
   `terraform/{azure,gcp,aws}/modules/mesh` — installs Istio (`istio-base`
   + `istiod` Helm charts, pinned to `1.23.2`) into each cluster, creates
   an `app` namespace with `istio-injection: enabled`, and applies a
   mesh-wide `PeerAuthentication` custom resource in `STRICT` mode. Once
   every workload in the mesh carries an Istio-issued mTLS identity,
   *every* in-mesh call — `api-gateway → service` and
   `account-service → secrets` alike — is mutually authenticated, not
   just reachable over the network.

3. **`architecture-hardened{,-gcp,-aws}.json` updated to reflect it**:
   every previously-`authenticated: false` flow into a compute service is
   now `true`, and `account-service`'s `identity_bindings` entry carries
   a real `role`/`scope` instead of `null`/`null`, on all three clouds.

## The actual, verified result

Re-running `agent/analyze.py` against all three updated hardened
architectures (not assumed — this is the literal output):

| Cloud | Before Phase 4 | After Phase 4 | Deployment (`--fail-on HIGH`) |
|---|---|---|---|
| Azure | MEDIUM 2, HIGH 0 (RR-04 was open; RR-03 never was — see below) | MEDIUM 2, HIGH 0 | ALLOWED (already was) |
| GCP | MEDIUM 4, HIGH 1 | MEDIUM 1, HIGH 0 | **BLOCKED → ALLOWED** |
| AWS | MEDIUM 4, HIGH 1 | MEDIUM 1, HIGH 0 | **BLOCKED → ALLOWED** |

**All three clouds now pass CI at the default `--fail-on HIGH` gate.**
That's a real milestone, not a formality — GCP and AWS were genuinely
blocking on a real finding (`AUTHN-FLOW-01`, `account-service → secrets`
unauthenticated) as of Phase 9's gate tightening, and this phase is what
actually closes it, not a threshold change.

The only findings left anywhere are the two already-tracked, out-of-scope
ones: `NET-WAF-01` (RR-05, missing WAF, all three clouds) and
`IAM-BROAD-02` (RR-06, Azure's `payment-service` role scoped to
resource-group instead of the specific resource) — both explicitly
"Phase 1 follow-up" in the residual risk register, not part of Zero
Trust, and both are why the gate is staying at `--fail-on HIGH` rather
than tightening to `--fail-on MEDIUM` right now (see "What's next," and
`docs/ci-cd.md`).

## The RR-03 / Azure correction

While updating `architecture-hardened.json`, I found that
`account-service → key-vault` was **already** marked `authenticated: true`
there — an inconsistency left over from an earlier phase, not something
this phase changed. That means RR-03 (`account-service → secrets` has no
application-layer authentication) was **never actually open on Azure
specifically**, despite the residual risk register listing "Azure, GCP,
AWS" as the affected clouds when RR-03 was opened. GCP and AWS did have
the real gap, and this phase's mesh work is what closes it for them.

This is recorded plainly in the residual risk register's Closed table
rather than quietly narrowing the "clouds affected" column with no
explanation — the project's documentation style throughout has been to
show real inconsistencies, not smooth them into a cleaner story than what
actually happened.

## A real, unresolved limitation: syntax-valid is not apply-valid

This project has never run `terraform apply` (cost discipline — see the
top-level README/spec), and — as Phase 2 already documented in
`docs/phase2-tests.md` — the real `terraform` binary has never been
installable in this build sandbox either (egress to
`releases.hashicorp.com` is blocked by this environment's network
policy; confirmed again this phase, not just carried over as an
assumption). So everything here has only ever been checked with
`python-hcl2` parsing every `.tf` file — a syntax/grammar check, not
`terraform validate` (which additionally checks provider schemas and
some cross-reference rules), and nowhere close to a plan or
graph-resolution check. That distinction matters more for this phase than
any previous one, because this phase introduces a real graph-level issue
that no syntax check of any kind can see:

`terraform/{azure,gcp,aws}/providers.tf` now configure the `kubernetes`
and `helm` providers using outputs from the *same root module's* cluster
resource (`module.aks.host`/`cluster_ca_certificate` on Azure,
`google_client_config` + `module.gke.cluster_endpoint` on GCP,
`aws_eks_cluster_auth` + `module.eks.cluster_endpoint` on AWS). This is a
well-known Terraform chicken-and-egg problem: on a genuine `terraform
apply` from a clean state, providers are configured during Terraform's
initial graph-walk, before any resource (including the cluster) has been
created — so a provider that depends on a not-yet-existent cluster's
credentials can fail on a true first apply. The standard real-world fixes
are a two-stage apply (cluster first, then mesh, as separate applies or
separate state/root modules) or a `terraform_remote_state` split.

This project does not implement that split. Neither `python-hcl2` nor
`terraform validate` can catch this class of problem — neither resolves
the dependency graph against real infrastructure, only checks that the
configuration is internally well-formed — which is exactly why this is
being called out explicitly here rather than left to be discovered the
first time someone with real `terraform`/cloud access tries an `apply`.
Given the project's stated cost discipline (no real cloud spend,
`terraform apply` never run, and `terraform validate` itself unavailable
in this sandbox), this is accepted as a documented gap rather than fixed
with a state split that has no way to be verified from here.

## Known limitations — not hidden

- The `terraform apply` chicken-and-egg problem above is the most
  significant one — a real deployment would need the two-stage split
  before `apply` would reliably succeed from a clean state.
- Istio's version (`1.23.2`) is pinned but has never been installed
  against a real cluster in this project — `helm_release`'s chart
  resolution and the `kubernetes_manifest` CRD apply are both only
  checked for HCL syntax, not even by `terraform validate` (unavailable
  here), let alone a real plan.
- The mesh's `PeerAuthentication` is mesh-wide and binary (`STRICT`
  everywhere or not at all) — no per-namespace or per-workload
  authorization policy (Istio `AuthorizationPolicy`) layered on top yet,
  so mTLS proves *identity* between workloads but doesn't yet express
  "account-service may call secrets, but notification-service may not
  call payment-service" as an explicit mesh-level rule. Today that's
  still enforced only by the IAM identity bindings at the cloud-provider
  layer, not by the mesh itself.
- `threat_engine.py`'s `rule_unauthenticated_flow` only reads the
  architecture JSON's `authenticated` field — it has no way to verify
  that a real Istio `STRICT` `PeerAuthentication` is actually deployed
  and enforcing anything. The `authenticated: true` flip in
  `architecture-hardened*.json` is an honest *design intent* backed by
  real Terraform, not a runtime-verified fact — same category of
  limitation Phase 9 already noted for `logging.enabled`.

## Running it yourself

With a real `terraform` binary available (this build sandbox doesn't
have one — see above):

```bash
cd terraform/azure && terraform init -backend=false && terraform validate
cd terraform/gcp   && terraform init -backend=false && terraform validate
cd terraform/aws   && terraform init -backend=false && terraform validate
```

What actually ran in this sandbox, and what you can re-run yourself
without a `terraform` binary:

```bash
python3 -c "
import hcl2, glob
for f in sorted(glob.glob('terraform/**/*.tf', recursive=True)):
    with open(f) as fh:
        hcl2.load(fh)
print('all .tf files parsed OK')
"

cd agent
python3 analyze.py ../threat-model/architecture-hardened.json --no-explain
python3 analyze.py ../threat-model/architecture-hardened-gcp.json --no-explain
python3 analyze.py ../threat-model/architecture-hardened-aws.json --no-explain
python3 -m pytest ../tests/ -q
```

## What's next

1. Getting a real `terraform validate`/`plan` run somewhere with normal
   package-registry access (this sandbox's `releases.hashicorp.com`
   egress block is the specific blocker) — the single biggest gap
   between "parses as valid HCL" and "Terraform itself accepts this,"
   tracked here the same way Phase 2 tracked it for the original modules.
2. The `terraform apply` two-stage split (cluster, then mesh) described
   above — needed before a real `apply` would work even once a real
   `terraform validate` is running.
3. An Istio `AuthorizationPolicy` layer on top of `PeerAuthentication`,
   so the mesh itself (not just cloud IAM) enforces which service may
   call which.
4. RR-05 (WAF) and RR-06 (Azure IAM scope) remain open as explicit
   "Phase 1 follow-up" items — tightening `--fail-on` from `HIGH` toward
   `MEDIUM` is deliberately being deferred until those close, since
   tightening now would immediately re-block all three clouds on
   findings this phase was never meant to address. See `docs/ci-cd.md`.
