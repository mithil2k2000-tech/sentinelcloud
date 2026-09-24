# Drift detection (FR-9 — spec §16 table item 7)

Status: **built, tested, and run for real**. 25 new tests (206 total in
`tests/`, all passing: 15 in `test_drift_engine.py`, 10 in
`test_drift_scan_cli.py`), plus the 3 Kubernetes schema-validation tests
and 1 compliance-mapping test added alongside this phase (see below) —
206 is the grand total after all of this session's work, not drift alone.

## What FR-9 asks for, verbatim

> Detect when a cloud resource's actual configuration (as read back from
> the provider, or from a stored last-known-good Terraform state) no
> longer matches the security baseline it was provisioned with, and raise
> it through the same finding/report pipeline as FR-3.

And from §14 (cost strategy): a planned "simulated drift" mode that
"diffs two architecture-JSON snapshots instead of comparing against a
live API, so the capability can be demonstrated and tested without a real
account either." That's exactly what was built — this project has never
had a real cloud account (SR-2/cost discipline, unchanged since Phase 1),
so a live-API mode was never on the table for this build.

## What was built

1. **`agent/drift.py`** — the engine. Takes two `Architecture` objects
   (`baseline`, `current` — both loaded from ordinary `architecture.json`
   files, reusing `Architecture.from_file` unchanged) and yields `Finding`
   objects, exactly as FR-9 asks ("raise it through the same
   finding/report pipeline as FR-3"). 8 rules:
   - `rule_public_access_drift` — a sensitive asset's public-exposure
     flags flipped closed→open since baseline (control `NET-001`).
   - `rule_encryption_drift` — encryption at rest flipped on→off on a
     high/critical-sensitivity asset (control `DATA-002`).
   - `rule_logging_disabled_drift` — centralized logging flipped
     enabled→disabled (control `LOG-001`).
   - `rule_identity_binding_drift` — any change to an identity's role or
     scope; broadening to `Owner`/subscription-wide is CRITICAL, any
     other change is MEDIUM (control `IAM-004`).
   - `rule_flow_authentication_drift` — a flow into a high/critical asset
     flipped authenticated→unauthenticated (control `ZT-001`).
   - `rule_waf_drift` — an internet-facing gateway's WAF flipped
     on→off (control `NET-003`).
   - `rule_asset_added` — an asset exists in `current` with no baseline
     counterpart at all (new control `DRIFT-001`).
   - `rule_asset_removed` — an asset in `baseline` is missing from
     `current` (also `DRIFT-001`).

2. **`agent/drift_scan.py`** — the CLI, sibling to `analyze.py`/
   `k8s_scan.py`/`detect.py`: `python3 drift_scan.py <baseline.json>
   <current.json> [--json out.json] [--no-explain] [--fail-on HIGH]
   [--risk-model] [--compliance]`. Same BLOCKED/ALLOWED exit-code
   convention (1/0) as every other CLI in this project.

3. **`threat-model/architecture-drifted.json`** — a hand-authored
   SIMULATED "current" snapshot with seven deliberate, realistic deltas
   from `architecture-hardened.json` (the baseline), one per triggerable
   rule (`rule_waf_drift` doesn't fire on this fixture — `api-gateway`'s
   WAF was already off in the baseline, RR-05, so there's nothing left to
   drift there). Its own `_notes` field documents every delta by hand so
   the fixture is auditable, not just asserted correct by the tests.

## Why every rule uses `Stride.TAMPERING`

A deliberate simplification, explained in full in `drift.py`'s own module
docstring: a drift finding is fundamentally a claim about *unauthorized
or undetected modification of configuration state* — that's what
Tampering means — regardless of what STRIDE category the eventual
consequence would fall under once exploited. `threat_engine.py`'s
`NET-PUBLIC-01` already covers "this resource is publicly exposed, full
stop" as a static, design-time property; `DRIFT-PUBLIC-NET-01` covers a
genuinely different claim — "this resource's exposure *changed* since it
was last reviewed" — and that act of unreviewed change is Tampering,
whatever the exposed data would eventually be used for.

## Six of eight control_ids are reused, not new — a real payoff from FR-8

`rule_public_access_drift` → `NET-001`, `rule_encryption_drift` →
`DATA-002`, `rule_logging_disabled_drift` → `LOG-001`,
`rule_identity_binding_drift` → `IAM-004`, `rule_flow_authentication_drift`
→ `ZT-001`, `rule_waf_drift` → `NET-003` — every one of these is an
EXISTING control_id from `threat_engine.py` (Phase 3), already mapped in
`policy/framework-mappings.yaml` (Phase 5/FR-8). The reasoning: the
underlying control a drifted resource now violates is the same control
`threat_engine.py` would have flagged had the resource been provisioned
that way from day one — drift just means it was discovered by comparison
instead of by inspecting one snapshot. Practical result: `--compliance`
on `drift_scan.py` works out of the box, no new YAML entries needed for
six of the eight rules. Only `rule_asset_added`/`rule_asset_removed` have
no design-time equivalent (nothing in `threat_engine.py` answers "did a
resource appear or disappear"), so those two use one genuinely new
control_id, `DRIFT-001`, added to `policy/framework-mappings.yaml` this
phase (now 15 entries total, up from 14).

## The two anti-patterns named directly in the spec's own risks table

The spec's own risks/anti-patterns table lists, immediately next to FR-9's
description: *"Drift detector (new) — Auto-remediate without human
approval; assume 'no error' means 'no drift.'"* Both are addressed head
on, not just avoided by accident:

1. **No auto-remediation.** `drift.py`/`drift_scan.py` never write to
   either input file or call any cloud SDK — they only read two JSON
   files and return `Finding` objects, same reporting-only shape as every
   other engine in this project.
   `test_cli_never_writes_to_its_input_files` in
   `tests/test_drift_scan_cli.py` checks this directly: it runs the CLI
   with every flag combination against copies of both fixtures and
   asserts both files are byte-identical before and after.
2. **"No error" must not mean "no drift."** A diff that only walks
   `current`'s keys would silently miss an asset that existed in
   `baseline` and is simply gone — exactly the case
   `rule_asset_removed` exists to catch. Every rule in this module walks
   the UNION of both snapshots' relevant keys, never just one side.
   `architecture-drifted.json` deliberately removes `notification-service`
   entirely (not just changes one of its fields) specifically so this
   fixture proves the anti-pattern is actually closed, not just described
   in a docstring — `test_real_drifted_fixture_produces_documented_findings`
   asserts `DRIFT-ASSET-REMOVED-01` is among the seven real findings.

## The two required tests, run for real

The spec's own §16 table names exactly one test for this phase: "Test
that two differing architecture-JSON snapshots produce a drift finding,
and identical snapshots produce none." Both halves are covered multiple
ways in `tests/test_drift_engine.py`:

- `test_real_drifted_fixture_produces_documented_findings` — the real
  baseline/drifted fixture pair produces exactly 7 findings (2 CRITICAL,
  3 HIGH, 2 MEDIUM), matching every rule_id by name — confirmed by
  actually running `drift_scan.py`, not hand-derived.
- `test_real_identical_snapshots_produce_zero_findings` — the same
  baseline compared against itself produces zero findings.
- `test_identical_snapshots_produce_no_findings_from_any_rule` — a
  synthetic fixture exercising every field every rule inspects, compared
  against an identical copy of itself, also produces zero findings (a
  stricter version of the same claim, independent of the one hand-authored
  demo fixture happening to be correct).

Plus 22 more per-rule positive/negative tests (one pair per rule, plus
boundary cases like "a flow removed entirely doesn't double-count as an
authentication regression") and 10 CLI-level tests covering exit codes,
`--json`, `--fail-on` boundaries, `--compliance`, `--risk-model`, and the
no-auto-remediation guarantee above.

## Honest limitations

- **SIMULATED mode only, permanently, in this build.** There is no code
  path anywhere in this module that reads live cloud state — that's a
  deliberate scope boundary, not a TODO this doc is hiding. A real-cloud
  mode would need a separate, not-yet-built adapter per provider (Azure
  Resource Graph, GCP Asset Inventory, AWS Config) that translates live
  resource state into this project's `architecture.json` shape — genuinely
  new work, not an extension of `drift.py` itself, which only ever
  compares two documents already in that shape.
- **The demo fixture is fixed, not regenerated.** `architecture-drifted.json`
  is a hand-authored, one-time snapshot — it doesn't change from run to
  run, so `drift-detection-demo` in CI is really "prove the diff logic
  still works against a known pair," not "detect real drift in a real
  environment on every push." That's exactly why the CI job is
  deliberately non-gating (see the job's own comment in
  `.github/workflows/security-gate.yml`).
- **The risk model's impact score degrades gracefully, not accurately,
  for a removed asset.** `agent/risk_model.py` looks up an asset's
  sensitivity from the `Architecture` it's scored against; for
  `DRIFT-ASSET-REMOVED-01`, the asset is by definition absent from
  `current` (the architecture the CLI scores against), so
  `risk_model.py` falls back to its default "low" sensitivity weight
  rather than the asset's real, pre-removal sensitivity. The engine-level
  `Severity.MEDIUM` on that finding is unaffected (severity comes from
  `drift.py`, not `risk_model.py`) — only the optional, purely-additive
  `--risk-model` view understates that specific finding's risk score.
  Not fixed here: doing so would mean threading the baseline architecture
  into `risk_model.py` as a fallback lookup, a real but small enhancement
  left for later.
- **Identity-binding drift treats any change as reportable, with no
  allowlist for routine rotation.** A legitimate, reviewed role rotation
  that keeps the same scope still fires `DRIFT-IAM-01` at MEDIUM — by
  design (an unreviewed-looking change and a reviewed one look identical
  from the outside of two JSON snapshots), but it does mean a real
  deployment of this rule would need a way to mark an expected change as
  "already reviewed" to avoid alert fatigue, which doesn't exist yet.

## Running it yourself

```bash
cd agent
python3 drift_scan.py ../threat-model/architecture-hardened.json ../threat-model/architecture-drifted.json --no-explain
python3 drift_scan.py ../threat-model/architecture-hardened.json ../threat-model/architecture-hardened.json --no-explain   # identical -> no drift
python3 -m pytest ../tests/test_drift_engine.py ../tests/test_drift_scan_cli.py -v
```

## Next steps for this piece

1. A real-cloud read-back adapter (Azure Resource Graph / GCP Asset
   Inventory / AWS Config, one per cloud) that produces a real `current`
   architecture.json from actual provisioned resources, so this stops
   being simulated-only whenever a real cloud account is available.
2. Thread `baseline` into `risk_model.py`'s lookup as a fallback for a
   removed asset, closing the risk-score-understatement gap noted above.
3. A way to mark an identity-binding change as pre-reviewed/expected (e.g.
   a small allowlist file of approved rotations), so `DRIFT-IAM-01`
   doesn't alert on routine, already-approved changes.
4. Wire `drift_scan.py` into a scheduled (not just push-triggered) CI run
   once a real-cloud mode exists — drift is fundamentally a
   "did anything change since I last looked" question, which a
   push-triggered pipeline alone can't answer for out-of-band changes
   that happen between deploys.
