# Agent evaluation harness (spec §16 table item 10, FR-11)

Status: **built, tested, and run for real**. 17 new tests (261 total in
`tests/`, all passing).

## What the spec asks for, verbatim

> **Objective:** FR-11: benchmark every AI-assisted capability.
> **Key files:** `agent/eval/benchmark.py`, fixture set.
> **Tests required before "done":** Harness runs and scores against a
> fixed fixture set with a documented pass threshold.

This directly targets the user's own standing rule for every project in
this workspace: solve a real problem, or reduce the cost of an existing
solution, **by using the agent** — not just by adding more deterministic
automation. Every other phase in this project measures the deterministic
engines (threat/K8s/drift/detection rules, all covered by exact-count
tests since Phase 2). Nothing, until now, measured the one part of this
system that actually *is* the agent in the AI-assistant sense —
`explain.py`/`triage.py`'s LLM narration layer. This phase closes that
gap: "the AI layer works" becomes a number, not an impression, exactly as
the spec's own §16 text (quoted when this table row was first read) says
it should.

## What counts as an "AI-assisted capability" here

Exactly two functions: `explain.py`'s `narrate_finding()` — reused
unchanged by three different CLIs (`analyze.py` for threat-engine
findings, `k8s_scan.py` for Kubernetes findings, `drift_scan.py` for
drift findings, per `k8s_engine.py`'s own design note about reusing
`Finding` rather than inventing a fourth narration path) — and
`triage.py`'s `narrate_alert()`, used by `detect.py`. `report_compliance.py`
is deliberately excluded: it never calls an LLM at all (a pure rendering
layer over data two earlier phases already produced), so there's nothing
there to benchmark.

## What this does — and deliberately does not — measure

`agent/eval/benchmark.py` does **not** judge whether a narrative is
well-written. That would need a human rater or a second LLM acting as
judge, and this project has consistently avoided non-deterministic, paid,
or non-reproducible steps in anything that claims to be a repeatable test
(the same reasoning that keeps `drift.py` SIMULATED-only and keeps
`report_compliance.py` from re-deciding BLOCKED/ALLOWED, applied here to
evaluation instead of detection).

What it does check, per narrative, is a fixed five-check grounding
rubric — every check must pass for that item to score PASS:

1. **Present and substantial** — non-empty, at least 20 characters.
2. **No silent LLM failure** — an API-error fallback marker (`[LLM
   explanation unavailable...]`) is scored a FAIL here, not a silent
   pass. A benchmark item that hit a real API error genuinely didn't
   produce a working narration this run.
3. **No SR-6 overclaim language** — the same forbidden-vocabulary spot
   check this project already applies at the report-rendering layer
   (`compliance.py`'s `REFERENCE_ONLY_LABEL`,
   `report_compliance.py`'s report), applied here to confirm the
   *explanation* layer itself never accidentally claims a certification
   either.
4. **No contradicting severity word** — the narrative must never state a
   severity other than the finding/alert's real one.
5. **Shares real vocabulary with the title** — at least one content word
   (≥5 characters, stopwords excluded) from the finding/alert's own title
   must appear in the narrative — a cheap, deterministic proxy for "this
   narrative is actually about what it claims to be about."

**Honest limitation, stated up front rather than discovered later:**
check 5 in particular is a heuristic, not a proof of correctness. A real
LLM call, prompted to paraphrase in 2-3 natural sentences, could
legitimately produce a grounded, accurate narrative that happens to avoid
every literal content word from the title — and check 4's word-boundary
severity match could, in principle, false-flag a narrative that uses a
severity word in an unrelated everyday sense (e.g. "highly sensitive"
doesn't trigger it — `\bHIGH\b` requires a whole-word match — but a
phrase like "this is a critical service" legitimately using "critical" as
an adjective, not a severity claim, could). This is exactly why
`DEFAULT_PASS_THRESHOLD` is deliberately **not** 100%, even though every
real run in this sandbox scores 100% — see below.

## Why the fixture set is real engine output, not a new hand-written file

Rather than inventing and maintaining a separate benchmark-fixture file,
`build_fixture_set()` runs the same real engines
(`threat_engine`/`k8s_engine`/`drift`/`detection_engine`) against the
same real fixtures every other CLI and test in this repo already uses:

| Source | Fixture | Items |
|---|---|---|
| `threat_engine` | `architecture-proposed.json` (all 6 threat rules) | 13 findings |
| `k8s_engine` | `kubernetes/manifests/vulnerable` (all 8 K8s rules) | 14 findings |
| `drift` | `architecture-hardened.json` vs. `architecture-drifted.json` | 7 findings |
| `detection_engine` | `logs-multi-stage-incident.json` (all 4 triggerable rules) | 4 alerts |
| **Total** | | **38 items** |

Confirmed by a real run before any test was written (established practice
throughout this project): `python3 benchmark.py` really does produce
exactly 38 items, split 13/14/7/4 across the four sources. Every rule in
every AI-narrated engine is represented at least once, with zero
duplicated fixture maintenance — if a fixture's finding count ever
changes, the benchmark set changes with it automatically, the same way
`report_compliance.py`'s scoping already tracks `threat_engine.py`'s real
control surface rather than a hand-copied list.

## Why this sandbox's run is fallback-mode only, and why that's still meaningful

No `ANTHROPIC_API_KEY` is set in this environment (same cost-discipline
stance as every other phase — no real cloud account, no real
`terraform`/`opa`/`kubeval` binaries, and here, no paid LLM calls made
just to populate a benchmark). Every `narrate_finding()`/`narrate_alert()`
call in this sandbox's run goes through the deterministic template
fallback, never a real model call. The template fallback was always going
to score 100% against this rubric by construction — it verbatim embeds
the finding/alert's own title, never states a severity word, and never
emits SR-6-forbidden vocabulary. So a 100% run here is a **harness
regression test**: it proves `build_fixture_set()`, `score_item()`,
`run_benchmark()`, and the CLI are all wired together correctly end to
end, not a demonstration of real LLM narration quality — there's no real
narration happening to demonstrate. `DEFAULT_PASS_THRESHOLD = 0.95` is
set with that future state in mind, not this sandbox's: the day a real
key is configured, real paraphrased narrations replace the templates, and
the threshold leaves room for the honest heuristic imprecision described
above without silently accepting a genuinely broken narration layer
either.

## The required test, run for real

`test_run_benchmark_scores_the_real_fixture_set_against_the_documented_threshold`
in `tests/test_agent_eval_harness.py` is the spec's own required test,
taken literally: the harness runs, scores the real 38-item fixture set,
and is checked against `DEFAULT_PASS_THRESHOLD` (a named, documented
constant, not a magic number — its own test,
`test_pass_threshold_is_documented_and_deliberately_not_perfect`, pins it
between 0.5 and 1.0). Sixteen more tests cover: every individual rubric
check triggered and *not* falsely triggered in isolation; the real
fixture counts by source; determinism across repeated runs; a custom
threshold actually changing the pass/fail outcome; and the CLI's exit
code, report text, and `--json` output.

## Why this can fail its own CI job — and why that still never blocks a deployment

Unlike the other non-gating demo jobs (`detection-engine-demo`,
`drift-detection-demo`, `compliance-audit-report`,
`centralized-logging-demo`), which always exit 0 no matter what they
find, `agent-eval-benchmark`'s CI job genuinely can turn red: `main()`
returns 1 when `pass_rate < threshold`. This is a deliberate, real
distinction, not an oversight — SR-4a says the AI layer's *quality* can
never affect whether an architecture gets deployed, and that guarantee is
unconditional; it does **not** say an AI-quality regression should go
unreported. `agent-eval-benchmark` is wired into CI as its own
independent job, with no `needs:`/dependency relationship in either
direction with `threat-model-gate` or `k8s-manifest-gate` — a failing
eval-harness run flags a human that the explanation layer regressed; it
cannot, by construction, ever touch the BLOCKED/ALLOWED decision those
two jobs make.

## Honest limitations

- **Fallback-mode-only in this sandbox**, as explained above — the
  harness has never actually scored a real LLM narration, only the
  deterministic template. The rubric was designed with real-LLM
  paraphrasing in mind, but that design has not been validated against
  one.
- **The grounding rubric is a proxy, not a semantic judge** — see check 5
  above for the clearest example of where a real LLM's natural phrasing
  could legitimately trip a false negative, or (less likely, given the
  narrow severity-word set) a coincidental false positive.
- **No trend tracking.** Each run is scored independently; there's no
  history file or dashboard showing whether the pass rate is improving or
  degrading over time once real LLM calls are involved.

## Running it yourself

```bash
cd agent/eval
python3 benchmark.py
python3 benchmark.py --threshold 0.90 --json /tmp/eval.json

cd ../../tests
python3 -m pytest test_agent_eval_harness.py -v
```
