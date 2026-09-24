# Phase 3 — Threat Modelling Agent (thin slice, working end-to-end)

Status: **built and run for real** against two architectures. Not a mockup —
`agent/analyze.py` is executable code with real output, captured below.

## Design

```
architecture.json → threat_engine.py (deterministic STRIDE rules)
                   → explain.py (LLM narrative, or template fallback)
                   → analyze.py (risk aggregation + BLOCKED/ALLOWED decision)
```

This is the roadmap's core split, made literal in code:

- **`threat_engine.py`** decides everything that matters — whether something
  is a finding, its severity, its control ID, its policy statement. Pure
  functions over a graph, no model call, same input always gives the same
  output. This is what a CI gate can safely block a deployment on.
- **`explain.py`** only turns an already-decided finding into readable
  prose. It calls the Anthropic API when `ANTHROPIC_API_KEY` is set,
  otherwise falls back to a deterministic template built from the same
  fields — so the agent's actual enforcement behavior (the block/allow
  decision) is identical with or without an LLM in the loop. The LLM
  can make the explanation nicer; it can never make a bad architecture
  pass.
- **`analyze.py`** is the CLI: loads an architecture, runs the engine,
  narrates each finding, aggregates a risk score, and exits 1 when
  BLOCKED — so it drops straight into a CI pipeline as-is.

8 rules currently implemented, one per STRIDE category (some categories
have more than one rule): broad IAM role scope, missing workload identity,
public network access, public blob access, missing encryption at rest, no
network segmentation between compute and data tiers, no app-layer auth on a
flow, no WAF on an internet-facing gateway, no centralized logging.

## Two architectures, run through it for real

`threat-model/architecture-proposed.json` — the roadmap's "engineer submits
architecture" scenario, written as a first-draft would actually look:
Contributor role at subscription scope, one flat network, public storage,
no encryption, no logging.

`threat-model/architecture-hardened.json` — the same scenario, but
translated from what `terraform/azure/` actually builds (Phase 1).

Actual output (`agent/analyze.py <file> --json <out>`):

| | Proposed (naive) | Hardened (our Terraform) |
|---|---|---|
| Findings | 13 | 6 |
| CRITICAL | 6 | 0 |
| HIGH | 3 | 1 |
| MEDIUM | 4 | 5 |
| Overall risk | CRITICAL | HIGH |
| Deployment | ❌ BLOCKED | ❌ BLOCKED |

Full reports: `threat-model/report-proposed.json`,
`threat-model/report-hardened.json`.

## What this actually demonstrates

Going from the naive design to our Terraform eliminated all 6 CRITICAL
findings and cut the HIGH count from 3 to 1 — that's the IAM/network work
from Phase 1 measurably paying off, not just asserted.

It's also honest about what's still open, on purpose — the hardened
architecture is still BLOCKED. The remaining findings are real and already
tracked: no centralized logging (Phase 9, not built yet), `account-service`
still has no role assignment (a genuine gap in `modules/iam`), no
app-layer/mTLS auth between the gateway and services (Phase 4 — Zero
Trust), no WAF in front of the gateway. A version of this project that
claimed a clean bill of health at this stage would be lying; this one isn't.

## Running it yourself

```bash
cd agent
python3 analyze.py ../threat-model/architecture-proposed.json
python3 analyze.py ../threat-model/architecture-hardened.json --json report.json
```

Set `ANTHROPIC_API_KEY` in the environment to get LLM-generated narratives
instead of the deterministic template — the findings, severities, and
BLOCKED/ALLOWED decision won't change either way.

## Next steps for this piece

1. Wire `analyze.py`'s exit code into a CI job so it actually gates
   `terraform apply` (closes the loop with Phase 2).
2. Replace hand-written `architecture.json` with one parsed from
   `terraform show -json` against the real plan, so the agent analyzes
   what's about to be deployed, not a hand-transcribed summary of it.
3. Add the remaining STRIDE rules the roadmap calls out (MITRE ATT&CK /
   OWASP mappings, attack-path chaining across multiple findings rather
   than one at a time).
