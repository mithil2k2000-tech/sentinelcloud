# Phase 5 — Kubernetes Security (SentinelCloud v1 spec, §16 table item 6)

Status: **built, tested, and run for real**. 43 tests total for this piece
(40 engine/CLI tests + 3 schema-validation tests added later — see "Real
schema validation" below). A third deterministic engine, sibling to
`threat_engine.py` (Phase 3) and `detection_engine.py` (Phase 9).

**A note on divergence from the spec's own table.** §16 table item 6 lists
this phase's key files as `kubernetes/manifests/*.yaml`, a schema
extension in `SCHEMA.md`, and "new rules in `threat_engine.py`" — i.e. it
originally envisioned Kubernetes rules being added directly to the
existing engine, not a separate `k8s_engine.py`. What was actually built
diverges from that on purpose: seeing the actual shape of the problem
while building it (a Kubernetes manifest is a different input document
from `architecture.json`, even though a finding about it is the same kind
of thing), a sibling engine reusing `Finding`/`Severity`/`Stride` turned
out to be the better design — see "Why this reuses `Finding`, not a new
dataclass" below for the full reasoning, and `docs/phase9-siem-detection.md`
for the same distinction applied to `Alert`. Per this spec's own
Definition-of-Done item ("this document... is re-read against the
finished repository... and any place where the build diverged from the
plan... is reflected back into this document rather than left to silently
drift out of date"), this paragraph is that reflection: the file split is
intentional and documented, not an oversight, and no `SCHEMA.md` was
written separately because `K8sManifest`'s docstring and this doc together
serve that purpose for now.

## What was built

1. **A deliberately vulnerable manifest set**, `kubernetes/manifests/vulnerable/`
   — real Kubernetes YAML for the same three workloads the rest of the
   project already models (`payment-service`, `account-service`,
   `notification-service`), each carrying different, realistic problems
   rather than one manifest piling on every mistake at once: a privileged
   container, a pod sharing the host's network/PID namespace, a container
   adding `NET_ADMIN` instead of dropping capabilities, a `ClusterRole`
   granting wildcard verbs/resources on everything, no resource limits, a
   `:latest` image tag, and — project-wide, by omission — no
   `NetworkPolicy` in the namespace at all.

2. **The hardened counterpart**, `kubernetes/manifests/hardened/` — the
   same three workloads with `runAsNonRoot`, dropped capabilities, no
   privileged/host-namespace flags, a scoped `Role` instead of a wildcard
   `ClusterRole`, resource requests/limits, pinned version tags, and a
   real `NetworkPolicy` set (default-deny plus explicit allows for DNS,
   the mesh control plane, and gateway-to-service traffic).

3. **`agent/k8s_engine.py`** — 8 deterministic rules over the manifests:
   `K8S-PRIV-01` (privileged container), `K8S-HOSTNS-01`
   (hostNetwork/hostPID/hostIPC), `K8S-ROOT-01` (missing `runAsNonRoot`),
   `K8S-CAP-01` (capabilities not dropped, or a dangerous one re-added),
   `K8S-RBAC-01` (wildcard `Role`/`ClusterRole`), `K8S-NETPOL-01` (no
   `NetworkPolicy` for a namespace with workloads), `K8S-RESOURCE-01`
   (missing CPU/memory limits), `K8S-IMAGE-01` (mutable `:latest`/untagged
   image reference).

4. **`agent/k8s_scan.py`** — the CLI, sibling to `analyze.py`/`detect.py`:
   same `--json`/`--no-explain`/`--fail-on` flags, same BLOCKED/ALLOWED
   exit-code convention (1/0), same report shape.

## Why this reuses `Finding`, not a new dataclass

`threat_engine.py`'s `Finding`/`Severity`/`Stride` are generic already —
`rule_id`, `stride`, `severity`, `asset_ids`, `title`, `threat`, `impact`,
`control_id`, `policy`, `mitigation`. A Kubernetes misconfiguration is
still a design-time, STRIDE-classifiable property of a manifest, exactly
the same *category* of thing as an architecture.json finding — just over
a different input document. So `k8s_engine.py` imports `Finding` directly
rather than inventing a fourth shape, and `explain.py`'s `narrate_finding`
works on Kubernetes findings completely unchanged — no new explanation
layer was needed, and `tests/test_k8s_engine.py`'s fixtures confirm the
narration reads correctly for a handful of the new rule_ids, not just
assumed to work because the types line up.

Contrast with `detection_engine.py`'s `Alert` (Phase 9), which correctly
has its *own* dataclass: a log-derived alert is a retrospective claim
about events that already happened, a genuinely different kind of thing
from a design-time property, not just a different input format. Reusing
`Finding` here and *not* reusing it there is the same underlying
distinction applied consistently, not an inconsistency between the two
phases — see `docs/phase9-siem-detection.md`'s "why two engines" section
for the fuller version of that reasoning.

`k8s_scan.py`'s `aggregate()` is, deliberately, a near-identical copy of
`analyze.py`'s and `detect.py`'s own aggregate functions rather than an
import — matching `detect.py`'s existing convention of keeping each
engine's CLI self-contained and independently testable even though the
three read identically.

## The actual, verified result

Running `k8s_scan.py` for real against both manifest sets (not
hand-derived):

| Manifest set | Findings | Overall | Deployment (`--fail-on HIGH`) |
|---|---|---|---|
| `vulnerable/` | 14 (3 CRITICAL, 6 HIGH, 5 MEDIUM) | CRITICAL | BLOCKED |
| `hardened/` | 0 | NONE | ALLOWED |

`kubernetes/manifests/report-hardened.json` is that real `hardened/` run's
JSON output, generated the same way `threat-model/report-hardened*.json`
are for the cloud architectures.

## A design choice worth explaining: why `K8S-RBAC-01` only fires on the combination

`rule_broad_rbac` only flags a `Role`/`ClusterRole` rule when it grants
**both** wildcard verbs (`["*"]`) **and** wildcard resources (`["*"]`) —
not either alone. `tests/test_k8s_engine.py::test_wildcard_verbs_alone_without_wildcard_resources_does_not_fire`
documents this boundary directly: a role granting `verbs: ["*"]` on a
single named resource type (e.g. `configmaps`) is still broader than
ideal, but it's a materially different, much narrower risk than "any verb
on any resource of any kind" — flagging both cases identically at
CRITICAL would have made the finding less actionable, not more. This
mirrors `threat_engine.py`'s own existing judgment calls about where a
rule's boundary sits (e.g. `rule_broad_role_scope`'s CRITICAL-only-for-
subscription-scope cutoff) — documented in the test, not left implicit.

## Real schema validation — closing the spec's "kubeval/kubeconform" requirement

§16 table item 6's own "Tests required before done" cell names a specific
check this doc didn't originally cover: "Manifests validated with
`kubeval`/`kubeconform`." Neither tool can be installed in this sandbox —
both ship as GitHub-release Go binaries, and egress to the hosts that
would serve them is blocked, the same restriction that blocks the real
`terraform` and `opa` binaries (see `docs/phase2-tests.md`,
`docs/phase4-zero-trust.md`). `tests/test_k8s_manifest_schema.py` uses
`kubernetes-validate` (PyPI) instead — it checks a manifest against the
actual official Kubernetes OpenAPI schemas for a real cluster version
(pinned to 1.29, matching this project's Terraform), which is the same
underlying check `kubeval`/`kubeconform` perform, just via a
pip-installable library rather than a binary this sandbox can't fetch.
Same substitution pattern as `python-hcl2` for `terraform validate` and
the local `regorus`-based runner for the real `opa` binary. Run for real:
all 24 manifest documents across `vulnerable/` (9) and `hardened/` (15)
pass schema validation — 0 errors. This is schema validity only
("is this valid Kubernetes API syntax"), a deliberately different,
narrower question from "is this configuration secure" (what
`k8s_engine.py` answers) — the `vulnerable/` set passes this check and
still fails every one of `k8s_engine.py`'s 8 security rules, which is the
whole point: the two checks are independent, same relationship as
`terraform-validate` vs. `threat-model-gate` in the CI workflow.

## A real, honest limitation: no cluster to check this against

Every finding here is a static property of the YAML text — `k8s_engine.py`
never talks to a real Kubernetes API server, and this project has never
run `kubectl apply` against a real cluster (same cost-discipline stance as
never running `terraform apply`). That means a few real gaps:

- Admission-controller-level policies (Kyverno, OPA Gatekeeper,
  Pod Security Admission) that would enforce these same rules *at deploy
  time*, rejecting a bad manifest before it's ever scheduled, are not
  built here — this engine is a pre-commit/CI check, not a runtime
  enforcement layer. A manifest that passes this gate today could still
  be hand-edited and `kubectl apply`'d directly, bypassing it entirely,
  unless an admission controller is also deployed.
- The rules can't see effective RBAC (aggregated ClusterRoles, default
  RBAC bindings Kubernetes itself ships with, or a `Role` that's broad
  only when combined with another) — only what's written directly in the
  manifests this engine is pointed at.
- `K8S-NETPOL-01` only checks whether *any* `NetworkPolicy` exists for a
  namespace with workloads — it doesn't verify the policy's rules are
  actually correct or complete (e.g. it wouldn't catch a `NetworkPolicy`
  that exists but accidentally allows all ingress). That's a real,
  narrower check than the finding's title might suggest, same honesty
  standard as `docs/phase9-siem-detection.md`'s `DET-PRIVESC-01` caveat.
- The hardened image tags (`1.4.2`, `2.1.0`, `1.0.7`) are illustrative
  version strings, not references to images that actually exist in any
  registry — `K8S-IMAGE-01`'s mitigation text recommends pinning by
  digest too, which these fixtures don't demonstrate (there's no real
  registry to pull a real digest from in this sandbox).

## Running it yourself

```bash
cd agent
python3 k8s_scan.py ../kubernetes/manifests/vulnerable --fail-on HIGH
python3 k8s_scan.py ../kubernetes/manifests/hardened --fail-on HIGH
python3 -m pytest ../tests/test_k8s_engine.py ../tests/test_k8s_scan_cli.py -v
```

## Next steps for this piece

1. An admission-controller layer (Kyverno or Gatekeeper policies mirroring
   these same 8 rules) so a bad manifest is rejected at `kubectl apply`
   time too, not only in CI — closing the "bypass CI entirely" gap noted
   above.
2. `K8S-NETPOL-01` upgraded to actually parse each `NetworkPolicy`'s rules
   (ingress/egress selectors) rather than just checking one exists, so an
   overly permissive policy doesn't read as "fixed."
3. Wire `risk_model.py`-style impact/likelihood scoring onto Kubernetes
   findings too, the same gap already noted as open for detection alerts
   in `docs/phase9-siem-detection.md`.
4. A real cluster (kind/minikube in CI, or a real AKS/GKE/EKS cluster once
   `terraform apply` is ever run for real) to actually deploy the hardened
   manifests against and confirm they schedule and run correctly — today
   "hardened" means "passes this static check," not "verified to actually
   work."
