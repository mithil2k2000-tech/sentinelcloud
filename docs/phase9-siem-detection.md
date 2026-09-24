# Phase 9 — SIEM + Detection (SentinelCloud v1 spec §16)

Status: **built, tested, and run for real**. 47 new tests (104 total in
`tests/`, all passing). Closes RR-01 in
`threat-model/residual-risk-register.md` on all three clouds.

## What was built

Two halves, because Phase 9 is actually two different problems that share
one name:

1. **The logging infrastructure Phase 1-3 always said was missing.**
   `terraform/{azure,gcp,aws}/modules/logging` — a Log Analytics workspace
   with diagnostic settings (Azure), a project-wide audit-log sink into a
   locked-down GCS bucket plus Data Access audit logging (GCP), and a
   multi-region CloudTrail with object-level data events into an
   encrypted S3 bucket and CloudWatch Log Group (AWS). Wired into each
   cloud's root module, living in the `mgmt` trust boundary that's existed
   — empty — since Phase 1. `architecture-hardened{,-gcp,-aws}.json` now
   carry a `log-workspace` asset and `"logging": {"enabled": true}`,
   which is what actually flips `threat_engine.py`'s `LOG-001` rule off.

2. **A second deterministic engine that reasons about what actually
   happened**, once that infrastructure exists to produce logs in the
   first place. `agent/detection_engine.py` — five correlation rules over
   synthetic log events (`threat-model/logs/`): brute-force/credential-
   stuffing logins, impossible travel, after-hours privilege escalation on
   a sensitive target, large-volume data exfiltration, and audit-log
   tampering. `agent/triage.py` is the LLM layer for alerts, built as a
   direct structural mirror of `explain.py` — same lazy client, same
   deterministic template fallback, same decision-neutrality guarantee
   (SR-4a), now proven for this layer too by
   `tests/test_triage_fallback.py`. `agent/detect.py` is the CLI, sibling
   to `analyze.py`.

## Why these are two separate engines, not one

`threat_engine.py` answers "is this architecture built safely" —
static, pre-deployment, independent of whether anything has ever run.
`detection_engine.py` answers "did something bad already happen" —
dynamic, retrospective, and meaningless without real (here, synthetic)
event data. Conflating them would mean either running architecture rules
against log events (category error) or gating deployments on log-based
alerts (also wrong — a bad login attempt yesterday shouldn't block today's
Terraform apply). Same split principle as SR-4/SR-4a applied to a second
axis: **what** decides is still 100% deterministic rules in both cases,
but **when** each engine runs, and what it's allowed to affect, is
different. `agent/detect.py`'s own header comment says this explicitly,
and `detection-engine-demo` in CI is deliberately non-gating — it always
exits 0 regardless of the INCIDENT/CLEAR result, purely so the output is
visible on every run.

## The five detection rules, and why each threshold is what it is

All five are small, fully-inspectable functions in
`agent/detection_engine.py` (v1 spec §11's "documented function, not a
black box" principle, same as `risk_model.py`):

- **`DET-BRUTEFORCE-01`** — 5+ failed logins, same principal + source IP.
  HIGH if no success follows (still just guessing); CRITICAL if a success
  follows from the same IP (the guess likely worked).
- **`DET-TRAVEL-01`** — two successful logins for the same principal, two
  different regions, within 60 minutes. Always CRITICAL — no legitimate
  explanation fits.
- **`DET-PRIVESC-01`** — an IAM/role change outside 06:00-22:00 UTC,
  scoped to targets whose name contains `secrets`, `payment`,
  `customer-storage`, or `key-vault`. HIGH. Deliberately scoped to
  sensitive targets only — an after-hours change to a low-value resource
  is a much weaker signal and would just add noise.
- **`DET-EXFIL-01`** — a single data transfer over 500 MB from a
  sensitive store. CRITICAL. The 500 MB line is an arbitrary, documented
  threshold, not tuned against real traffic — same honesty stance as
  `risk_model.py`'s thresholds: a synthetic project has no legitimate
  baseline to tune against, so the number is stated plainly rather than
  dressed up as empirically derived.
- **`DET-LOGTAMPER-01`** — a principal disabling logging or deleting logs.
  Always CRITICAL regardless of anything else that principal did — it's
  usually an attacker covering their tracks, and it removes the evidence
  needed to investigate everything else.

## The demonstration fixture, and what it's for

`threat-model/logs/logs-multi-stage-incident.json` runs all four
rule-triggering behaviors (credential-stuffing success, after-hours
privilege escalation, large exfiltration, log tampering) under one
principal and source IP, in sequence — the detection-layer counterpart to
`architecture-proposed.json`'s "before hardening" demo (v1 spec §19). It
exists to show *why* five rules exist together: a real incident isn't one
alert, it's several, and `test_multi_stage_incident_alerts_all_share_the_same_principal_and_source`
asserts that correlation is actually real (every alert traces back to the
same attacker) rather than four coincidentally-adjacent alerts.

## A real bug this caught

Early integration tests computed the fixture's overall severity with
`max(a.severity for a in alerts)`. `Severity` (from `threat_engine.py`,
reused here) is a plain `Enum` with only a `.value` int and no `__lt__` —
comparing two `Severity` members directly raises `TypeError`, which only
surfaced once a test actually exercised a fixture with *more than one
distinct severity present* (`logs-multi-stage-incident.json`, mixing
CRITICAL and HIGH) — every single-rule fixture has only one alert, so
`max()` over a length-1 iterable never needed to compare anything, and the
bug stayed hidden until that specific test ran. Fixed by comparing on
`.value` explicitly (`max(alerts, key=lambda a: a.severity.value)`), and
kept as the actual mechanism in both the test and `analyze.py`/`detect.py`'s
own `aggregate()`/`aggregate_alerts()` (which already did this correctly).

## A consequence, not smoothed over

Closing RR-01 removed the specific reason `docs/ci-cd.md` gave for
loosening the CI gate to `--fail-on CRITICAL` — so the gate has been
tightened back to `--fail-on HIGH`, as that doc always said it would be
once Phase 9 landed. The honest result: **Azure now passes CI**, but
**GCP and AWS now correctly BLOCK**, because each still has one real,
previously-invisible-under-the-looser-threshold HIGH finding
(`AUTHN-FLOW-01` — RR-03, target Phase 4/Zero Trust). That's the gate
doing exactly what tightening it is supposed to do, not a regression —
see `docs/ci-cd.md` for the full explanation.

## Known limitations — not hidden

- The 500 MB exfiltration threshold and the 60-minute impossible-travel
  window are both round numbers chosen for a readable demo, not derived
  from any real traffic baseline. A real deployment would need to tune
  these against actual usage patterns first — using them as-is against
  real traffic would likely produce a lot of false positives or false
  negatives depending on the organization.
- `DET-PRIVESC-01`'s sensitive-target match is a plain substring check
  against the target's name (`"secrets" in e.target`), not a lookup
  against the actual architecture graph's `sensitivity` field the way
  `risk_model.py` does it for design-time findings. That's a real
  inconsistency between the two engines' notion of "sensitive," tracked
  here rather than papered over — a future refinement should have
  `detection_engine.py` accept an `Architecture` and look sensitivity up
  properly, the same way `risk_model.py` does.
- There's no actual log ingestion pipeline wiring the Terraform-deployed
  logging infrastructure to `agent/detect.py` — `detect.py` reads a local
  `logs.json` file. Connecting a real export (CloudWatch Logs Insights,
  Log Analytics KQL, Cloud Logging query, exported to the same JSON shape
  documented in `threat-model/logs/SCHEMA.md`) is real, unbuilt work, not
  a detail.

## Running it yourself

```bash
cd agent
python3 detect.py ../threat-model/logs/logs-multi-stage-incident.json --triage
python3 -m pytest ../tests/test_detection_engine.py ../tests/test_triage_fallback.py ../tests/test_detect_cli.py -v
```

## Next steps for this piece

1. Real log ingestion (see "known limitations" above) — the single
   biggest gap between this and something actually deployable.
2. Fix `DET-PRIVESC-01`'s sensitivity check to use the architecture graph
   instead of a name substring match.
3. Once Phase 4 (Zero Trust/mTLS) closes RR-03/RR-04, revisit whether
   `--fail-on HIGH` can tighten further toward `--fail-on MEDIUM` (see
   `docs/ci-cd.md`).
4. Wire `risk_model.py`-style impact/likelihood scoring onto alerts too,
   so a CRITICAL `DET-EXFIL-01` against a low-sensitivity asset and one
   against `customer-storage` aren't presented identically — the same gap
   Phase 4 closed for design-time findings, not yet closed here.
