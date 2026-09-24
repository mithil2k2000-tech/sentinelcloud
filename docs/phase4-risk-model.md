# Phase 4 — Risk Model + Residual Risk Register (SentinelCloud v1 spec, §11, §16)

Status: **built, tested, and run for real** against all four architecture
fixtures. 9 new tests (57 total in `tests/`), all passing.

## What was built

- `agent/risk_model.py` — a second, independent scoring dimension layered
  on top of `threat_engine.py`'s output. Never modifies a finding, never
  changes which findings exist, never touches the BLOCKED/ALLOWED
  decision — purely descriptive, opt-in.
- `analyze.py --risk-model` — prints an additional risk table and (with
  `--json`) an additional `risk_model` array in the JSON report. Without
  the flag, `analyze.py`'s output and exit code are byte-identical to
  before this phase (`test_cli_risk_model_flag_is_purely_additive` proves
  it).
- `threat-model/residual-risk-register.md` — every currently-open finding
  across all three clouds, with an owner, a target phase, and why it's
  accepted for now rather than blocking merges.

## The problem this closes

`Severity` in `threat_engine.py` is a fixed property of the *rule*: every
`IAM-MISSING-01` finding is MEDIUM, whether the workload touches nothing
sensitive or a `critical` secrets store. `rule_unauthenticated_flow`
already branches on destination sensitivity (HIGH vs MEDIUM); most other
rules don't. That's a real, previously-documented gap (v1 spec §11 and
§10's account-service/notification-service example).

`test_account_vs_notification_service_same_severity_different_risk`
proves the fix directly: two synthetic workloads trigger the *same rule*
at the *same fixed Severity.MEDIUM* — the engine genuinely cannot tell
them apart — but `risk_model.py` gives the one touching `critical` data a
strictly higher `impact` and `risk_score` than the one touching `low`
data. `test_differentiation_collapses_when_both_touch_equally_sensitive_data`
is the matching negative case: when both touch equally sensitive data,
the model doesn't invent a difference that isn't there.

## How impact and likelihood are actually computed

Both are small, fully-inspectable functions (not a black box, per v1 spec
§11) — the whole derivation is in `agent/risk_model.py`'s docstrings:

- **Impact (1-4):** the rule's own severity, raised to match the most
  sensitive asset the finding touches *or flows into* (one hop). The
  one-hop-forward lookup matters: `IAM-MISSING-01` only records the
  workload itself in `asset_ids`, not the sensitive data it reaches, so
  without following that one flow, impact would never differ from raw
  severity at all — the exact gap this phase exists to close.
- **Likelihood (1-3):** the highest structural exposure among the
  finding's touched assets — 3 if internet-facing or reachable from the
  internet edge via an *unauthenticated* hop, 2 if reachable via an
  *authenticated* hop, 1 otherwise.
- **risk_score** = impact × likelihood (1-12), mapped to a label via
  published thresholds (CRITICAL ≥10, HIGH ≥6, MEDIUM ≥3, else LOW).

## A real calibration problem this caught, and how it was fixed

Running `--risk-model` against the real AWS fixture with the first
threshold draft (CRITICAL ≥9) put 5 of 6 findings at CRITICAL — including
ones the raw engine calls MEDIUM. That's not automatically wrong (§ below
explains one case where the elevation is *correct*), but a model where
almost everything is CRITICAL adds no information over "everything is
already blocked." Raised the CRITICAL cutoff to ≥10, which separated
`NET-WAF-01` (score 9) into HIGH while leaving the four genuinely
edge-adjacent, critical-data-touching findings at CRITICAL — tuned
against the real output, not picked in the abstract.

## A known, documented limitation — not hidden

`LOG-001` ("no centralized logging") applies to the *whole* architecture
— `threat_engine.py` sets its `asset_ids` to every asset in the graph.
`risk_model.py`'s impact calculation takes the *maximum* sensitivity
across a finding's touched assets, so a global finding like this
automatically inherits the architecture's single most sensitive asset and
scores CRITICAL every time, regardless of whether logging is actually
missing for the critical asset specifically or just for a low-sensitivity
one. This is a real modeling limitation, tracked here rather than quietly
accepted: a future refinement (not yet built) would need `LOG-001` to
reason per-asset rather than architecture-wide before its risk score
means what it currently appears to mean. `residual-risk-register.md`'s
RR-01 score is honest about being CRITICAL for this reason, not because
the model was re-tuned to hide it.

## Running it yourself

```bash
cd agent
python3 analyze.py ../threat-model/architecture-hardened-aws.json --no-explain --risk-model
python3 -m pytest ../tests/test_risk_model.py -v
```

## Next steps for this piece

1. Fix the `LOG-001` global-finding limitation above — likely by having
   `rule_logging_disabled` emit one finding per trust boundary instead of
   one finding for the whole architecture, so impact reflects what's
   actually at risk in each boundary specifically.
2. Wire the residual risk register into CI as a checked artifact: fail
   the build if a finding the register calls "Closed" still appears in a
   fresh `analyze.py` run (register/reality drift is exactly the kind of
   silent staleness this project's honesty requirement (v1 spec §5)
   exists to prevent).
3. Extend `likelihood_score` to account for authentication properly once
   Phase 4 (Zero Trust/mTLS) actually closes RR-03/RR-04 — right now
   "authenticated" only means "flagged authenticated in the schema," not
   verified against a real mTLS/OAuth deployment.
