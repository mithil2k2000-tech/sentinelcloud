# SentinelCloud

AI-assisted, multi-cloud security governance for a fictional bank
("Meridian Trust Bank" — never a real institution). A deterministic
policy engine makes every BLOCKED/ALLOWED deployment decision; an LLM
layer explains *why*, in plain language, but never gets a vote (SR-4/
SR-4a). Built to the [SentinelCloud v1 Technical Specification](https://claude.ai/code/artifact/bfe9d86d-4b9d-45bf-b332-d2b2a91aa06d),
a 22-section living spec whose own §22 "Definition of Done" is what
"finished" means for this project.

**See it in under two minutes:**

```bash
python3 demo/run_all.py
```

Five self-narrating, self-verifying demonstration scripts — see
[`demo/README.md`](demo/README.md) and [`docs/demo-scenarios.md`](docs/demo-scenarios.md).

## What this is

Three real (syntax-validated) Terraform footprints — Azure, GCP, AWS —
implementing the same reference architecture for a mobile banking app:
an API gateway, payment/account/notification services, a customer
database and blob storage, behind a governance layer that:

- **Threat-models the architecture before it's deployed** (`agent/analyze.py`,
  `agent/threat_engine.py`) — a deterministic STRIDE-based rule engine
  over a cloud-agnostic `architecture.json`, gating CI on anything at or
  above a configured severity.
- **Scans Kubernetes manifests the same way** (`agent/k8s_scan.py`,
  `agent/k8s_engine.py`) — the same discipline applied to the workload
  layer, not just the cloud layer.
- **Detects incidents retrospectively from logs** (`agent/detect.py`,
  `agent/detection_engine.py`) and **flags configuration drift** between
  a baseline and a current snapshot (`agent/drift_scan.py`, `agent/drift.py`).
- **Explains every finding in plain language** (`agent/explain.py`,
  `agent/triage.py`) — real Anthropic API calls when a key is configured,
  a deterministic template otherwise, with the actual deployment decision
  byte-identical either way (see `tests/test_explain_fallback.py` and
  `demo/scenario3_ai_explanation_decision_neutral.py`).
- **Maps findings to compliance frameworks, reference only** (`agent/compliance.py`,
  `agent/report_compliance.py`) — every framework mapping and audit-style
  report is explicitly labeled "reference only, not a certification"
  (SR-6) — this project makes no compliance claims.
- **Captures events into a local, queryable log store** (`logging/log_store.py`,
  `logging/query_cli.py`) — a local SQLite simulation of centralized log
  aggregation, zero new dependencies.
- **Benchmarks its own AI-explanation layer** against a documented pass
  threshold (`agent/eval/benchmark.py`) — "the AI layer works" is a
  measured number over a real, engine-derived fixture set, not an
  impression.
- **Enforces a centralized, cloud-agnostic policy layer** (`policy/opa/*.rego`)
  independent of any one cloud's native policy engine.
- **Simulates attack paths as a graph-reachability check** (`agent/attack_sim.py`)
  — walks `architecture.json`'s own flow graph from every entry point to
  every sensitive-data asset, flagging paths with an unauthenticated hop;
  read-only, never a live probe (SR-6-style honesty label on every
  report: reachability analysis only, not a penetration test).
- **Rolls every report into one dashboard** (`agent/dashboard.py`) — a
  single self-contained HTML page aggregating every other CLI's JSON
  output, clearly labeled as a snapshot (not live monitoring) since it
  computes nothing new itself.

## Cost discipline

Default posture: **$0**. Every phase is designed to be completable,
tested, and demonstrable with no paid cloud resource — LOCAL and
SIMULATED are the intended steady state, not a fallback (see the spec's
§14/§20). No `terraform apply` has ever been run against a real cloud
account; no `ANTHROPIC_API_KEY` is configured in this project's own
development sandbox, which is itself the live proof that the AI
explanation layer degrades gracefully rather than being load-bearing.

## Repository layout

| Path | What's there |
|---|---|
| `terraform/{azure,gcp,aws}/` | The three real (schema-validated) Terraform footprints |
| `threat-model/` | `architecture*.json` fixtures, the JSON schema, generated reports |
| `agent/` | The deterministic engines, CLIs, AI-explanation layer, compliance/eval tooling |
| `kubernetes/manifests/{hardened,vulnerable}/` | K8s manifest fixtures for the manifest-scanning engine |
| `logging/` | The local centralized-log-store simulation |
| `policy/opa/` | The centralized, cloud-agnostic Rego policy layer |
| `demo/` | Five self-verifying demonstration scenarios — start here |
| `docs/` | One write-up per phase, in the same honest style: real bugs, real numbers, no unearned claims |
| `tests/` | The full pytest suite — 295 tests as of this phase, gating every push |
| `.github/workflows/security-gate.yml` | 13-job CI pipeline — 2 real deployment gates, 1 unit-test gate, 1 non-gating AI-quality check, 9 always-green visibility/demo jobs |

## Running it locally

```bash
# the full test suite
cd tests && python3 -m pytest -v

# threat-model an architecture
cd agent && python3 analyze.py ../threat-model/architecture-hardened.json --fail-on HIGH

# the whole demonstration walkthrough
python3 demo/run_all.py
```

No cloud account or API key required for any of the above. See
`docs/ci-cd.md` for the full CI pipeline, and `docs/demo-scenarios.md`
for a guided walkthrough of what each demo scenario proves and why.

## Honesty, as a design principle

This project treats undocumented divergence between what a design doc
claims and what the code actually does as a bug in itself, not just the
underlying issue. Every `docs/*.md` file states real bugs caught, real
limitations, and real consequences — never smoothed over — and the spec
document itself has been re-read against the finished repository and
corrected in place wherever it had drifted out of date (see
`docs/demo-scenarios.md` for the most recent example: two places in the
spec's own §19/§21 text were stale relative to what Phase 4 had already
built, found and fixed during this final phase).

## Status

All 11 items in the v1 spec's §16 development-phase table are built,
tested, and documented. See the spec's own §22 "Definition of Done" for
what "finished" means here, and `docs/demo-scenarios.md` for the closing
phase's own write-up. Beyond the spec's own table, this repository also
includes architecture diagrams (`docs/architecture-diagrams.md`), an
attack-path simulation module (`docs/attack-simulation.md`), and a
security posture dashboard (`docs/dashboard.md`) as portfolio
deliverables in their own right.
