# Phase 2 — Test Foundation (SentinelCloud v1 spec, §16)

Status: **built and passing for real.** 47 tests, `pytest tests/ -q` → `47 passed`.
This closes the single largest gap identified in the v1 Technical
Specification (§21, Risks and Limitations): before this phase, every claim
about the threat engine's behavior rested on manual runs, not CI-enforced
tests.

## What was built

| File | Covers | Count |
|---|---|---|
| `tests/conftest.py` | Puts `agent/` on `sys.path` so the flat scripts import cleanly as test targets, without restructuring them into a package mid-phase. | — |
| `tests/test_threat_engine.py` | One positive + one negative case per rule (8 rules), plus the `run_engine` sort-order guarantee. | 24 tests |
| `tests/test_explain_fallback.py` | SR-4a: the decision-neutrality guarantee — see below. | 5 tests |
| `tests/test_analyze_cli.py` | `aggregate()` unit tests (including the fail-on boundary case), integration tests against all four real architecture fixtures with their exact documented finding counts, and CLI-level exit-code tests. | 18 tests |

## Why unit tests needed their own fixtures, not just the four real architectures

Running the four real `architecture-*.json` files through the engine only
proves "the rules fire on architectures we already know trigger them." It
doesn't prove a rule's *actual condition* is what the code intends — for
example, `rule_unencrypted_at_rest` only fires when `encrypted_at_rest` is
explicitly `False` (not merely absent/`None`), which the real architecture
files never exercise either way since they always set the field explicitly.
`tests/test_threat_engine.py` builds minimal architecture dicts per rule
specifically to pin down these edge conditions — e.g.
`test_low_sensitivity_unencrypted_does_not_fire` documents, as a passing
test, that the rule deliberately ignores unencrypted low-sensitivity data
(a real scope decision, now impossible to silently change without a test
failing).

## SR-4a in detail — the test that matters most

The v1 spec's central architectural claim is that no LLM call ever sits on
the critical path of a BLOCKED/ALLOWED decision. `test_explain_fallback.py`
checks this three ways against the same fixture
(`architecture-hardened.json`):

1. **API key unset** — `narrate_finding` uses the template path; the
   aggregated decision is compared against a decision computed without
   calling `narrate_finding` at all.
2. **API key set, call mocked to raise** — simulates a real network/auth
   failure; asserts the decision is still identical, and that the
   `[LLM explanation unavailable: ...]` note actually appears (proving the
   failure path was really exercised, not silently skipped).
3. **API key set, call mocked to succeed** — proves the decision doesn't
   change even when the LLM is fully available, which matters as much as
   the failure case: the enforcement decision must never depend on the LLM
   working *or* not working.

All three produce the same `aggregate()` output and the same
`Finding.to_dict()` list — only the narrative text differs.

## Integration tests use the exact numbers already in the docs

`test_known_architecture_produces_documented_findings` asserts the specific
severity counts already written up in `docs/phase1-{azure,gcp,aws}.md` and
`docs/phase3-threat-agent.md` (e.g. AWS: 0 CRITICAL, 2 HIGH, 4 MEDIUM). If a
future change to a rule silently drops or adds a finding, this test fails
instead of the docs quietly going stale.

## What this substitutes for, and why

`terraform validate`/`tflint` are still not run — the real `terraform`
binary can't be installed in this build sandbox (egress to
`releases.hashicorp.com` is blocked here). `python-hcl2`-based syntax
checking is still the substitute for that specific gap; it's a separate,
not-yet-automated step (tracked for whenever this runs somewhere with
normal package-registry access, or on the developer's own machine).

## Running it yourself

```bash
cd sentinelcloud   # or cloud-security-platform, until the rename lands
pip install pytest --break-system-packages   # if not already installed
python3 -m pytest tests/ -v
```

## Next steps for this piece

1. Wire `pytest tests/` into the CI workflow (`ci-cd/security-gate.yml`) as
   a job that runs before `threat-model-gate`, so a broken rule fails CI
   before a bad architecture would even get analyzed.
2. Add the OPA/Rego centralized policy layer's own test cases
   (`tests/test_opa_policies/`) once that layer exists (v1 spec §16, later
   in Phase 2).
3. Add a coverage check once the suite is large enough that "did we test
   the new rule" needs a machine check, not just discipline.
