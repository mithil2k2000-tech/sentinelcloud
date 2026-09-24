# demo/ — SentinelCloud demonstration scenarios

Five short, self-verifying scripts that walk through the platform end to
end, per the v1 spec's §19 "Demonstration Scenarios." Run any one on its
own, or all five together:

```bash
python3 demo/scenario1_naive_vs_hardened.py
python3 demo/scenario2_three_clouds.py
python3 demo/scenario3_ai_explanation_decision_neutral.py
python3 demo/scenario4_ci_gate_in_action.py
python3 demo/scenario5_rule_catches_a_regression.py

# or, all five in sequence with a combined summary:
python3 demo/run_all.py
```

Run from anywhere — each script resolves paths relative to the repo root,
not the current working directory.

## What each one shows

| Script | Shows | Real command(s) it runs |
|---|---|---|
| `scenario1_naive_vs_hardened.py` | The engine actually discriminates between a bad design (13 findings, BLOCKED) and a hardened one (2 findings, ALLOWED) — same rules, different input. | `analyze.py` against `architecture-proposed.json`, then `architecture-hardened.json` |
| `scenario2_three_clouds.py` | One engine, one rule set, three real Terraform footprints — same report shape on Azure/GCP/AWS, with a genuine cloud-specific IAM-scoping difference surfacing as data, not a special case. | `analyze.py` against all three hardened baselines |
| `scenario3_ai_explanation_decision_neutral.py` | SR-4a live: the BLOCKED/ALLOWED decision and finding list are byte-identical whether AI explanation is requested or not. | `analyze.py` with and without `--no-explain` |
| `scenario4_ci_gate_in_action.py` | The CI gate is a real control: reintroducing a previously-fixed bug on a throwaway copy gets BLOCKED by the exact command CI runs. | `analyze.py --fail-on HIGH` against a regressed temp copy |
| `scenario5_rule_catches_a_regression.py` | The test suite protects rule *behavior*, not just "runs without crashing": removing one fixture line makes a specific unit test fail for a specific reason. | `pytest` against `tests/test_threat_engine.py`, before/after a reversible mutation |

## Two honest divergences from the spec's literal §19 text

The v1 spec's §19 text was written before Phase 4 (Zero Trust) landed.
Rather than quietly forcing today's output to match stale spec prose, or
silently rewriting the spec without comment, these scripts use the real
current state of the codebase and say so in their own module docstrings:

1. **Scenario 1** — the spec predicted the hardened Azure run would still
   be "BLOCKED on real remaining HIGH findings." Phase 4 closed the last
   open HIGH finding on all three clouds, so today's real result is
   stronger: 0 CRITICAL, 0 HIGH, ALLOWED.
2. **Scenario 5** — the spec named `account-service` as the workload
   missing an identity binding. Phase 4 gave `account-service` its own
   scoped identity; `notification-service` is the workload genuinely still
   missing one today.

Full details: [`docs/demo-scenarios.md`](../docs/demo-scenarios.md).

## Design: narrate AND assert

Every script both prints a narrated walkthrough and asserts, in code, that
reality matches what it's narrating (`_lib.py`'s `check()` — raises
`AssertionError`, non-zero exit, the moment something stops matching). A
script that only printed canned text could silently drift out of sync with
the actual codebase; these can't.

## Honest limitations

- **Scenario 3**: this sandbox has no `ANTHROPIC_API_KEY`, so it cannot
  show real LLM prose diverging from the deterministic template — both
  runs it performs use the same fallback. What it does show, for real, is
  that the decision is identical either way.
- **Scenario 4**: this repo hasn't been pushed to GitHub yet, so there's
  no live Actions run to watch turn red. It runs the exact command
  `threat-model-gate` runs in CI, locally, against a throwaway copy.
- **Scenario 5**: mutates the real `tests/test_threat_engine.py` file
  in place (there's no other way to make pytest observe a real failure and
  recovery of a real committed test), restoring it in a `try/finally` and
  verifying the restoration byte-for-byte before reporting success.

## Tests

`tests/test_demo_scenarios.py` runs each script as a subprocess from a
clean checkout and asserts it exits 0 — the spec's own required test for
this phase ("each demo scenario runs end-to-end from a clean checkout").
