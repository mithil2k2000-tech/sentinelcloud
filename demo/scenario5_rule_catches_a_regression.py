#!/usr/bin/env python3
"""
demo/scenario5_rule_catches_a_regression.py — spec §19, Scenario 5: "A
rule catches a real regression." Deliberately remove an identity binding
from a test fixture, show the corresponding unit test fail, then
correctly restore it — demonstrating the test suite actually protects the
engine's behavior, not just its ability to run without crashing.

HONEST DIVERGENCE FROM THE SPEC'S OWN LITERAL §19 TEXT: the spec (written
before Phase 4/Zero Trust) names account-service as the workload with "no
identity binding." Phase 4 gave account-service its own dedicated,
resource-scoped identity on all three clouds (closing RR-02/RR-03/RR-04);
notification-service is the workload that's still genuinely missing one
today (see architecture-hardened.json's identity_bindings and
threat-model/residual-risk-register.md). This script uses the CURRENT
real state of the codebase, not the spec's now-stale example, which is
exactly what an honest demo should do — see docs/demo-scenarios.md.

SAFETY: this script mutates tests/test_threat_engine.py ON THE REAL
REPOSITORY FILE (there is no other way to make pytest observe a "real"
failure and recovery of a real committed test) and restores it in a
try/finally, then verifies byte-for-byte that the restored file matches
the original before reporting success. If anything goes wrong mid-run,
the file is still restored before this script exits or raises.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import REPO_ROOT, check, finish, header, run, step  # noqa: E402

TEST_FILE = REPO_ROOT / "tests" / "test_threat_engine.py"
TESTS_DIR = REPO_ROOT / "tests"

TARGET_FUNCTION_ANCHOR = (
    "def test_missing_identity_does_not_fire_when_bound():\n"
    "    a = arch(\n"
    "        assets=[\n"
    '            {"id": "svc", "type": "compute"},\n'
    '            {"id": "db", "type": "database"},\n'
    "        ],\n"
    '        flows=[{"from": "svc", "to": "db", "authenticated": True}],\n'
    '        identity_bindings=[{"principal": "svc", "role": "custom-role", "scope": "resource"}],\n'
    "    )\n"
    "    assert list(rule_missing_identity(a)) == []"
)

REGRESSED_FUNCTION = (
    "def test_missing_identity_does_not_fire_when_bound():\n"
    "    a = arch(\n"
    "        assets=[\n"
    '            {"id": "svc", "type": "compute"},\n'
    '            {"id": "db", "type": "database"},\n'
    "        ],\n"
    '        flows=[{"from": "svc", "to": "db", "authenticated": True}],\n'
    "        identity_bindings=[],  # <-- demo scenario 5: identity binding removed on purpose\n"
    "    )\n"
    "    assert list(rule_missing_identity(a)) == []"
)


def main() -> int:
    header("SCENARIO 5 — A rule catches a real regression (in the test suite itself)")

    original_text = TEST_FILE.read_text()
    occurrences = original_text.count(TARGET_FUNCTION_ANCHOR)
    check(occurrences == 1, "the target test function is present exactly once, as expected",
          f"expected exactly 1 occurrence of the target test function, found {occurrences} — "
          "tests/test_threat_engine.py has changed, update this script's anchor text")

    try:
        step("Confirm the real test suite passes before touching anything")
        before = run(
            ["python3", "-m", "pytest", "test_threat_engine.py::test_missing_identity_does_not_fire_when_bound", "-v"],
            cwd=TESTS_DIR,
        )
        check(before.returncode == 0, "the real, unmodified test passes",
              "the real test does not pass before any mutation — investigate before demoing")

        step("Deliberately remove the identity binding from this test's own fixture "
             "(simulating a regression in the engine that a careless edit could introduce)")
        TEST_FILE.write_text(original_text.replace(TARGET_FUNCTION_ANCHOR, REGRESSED_FUNCTION, 1))

        step("Run the same test again — it should now fail")
        after = run(
            ["python3", "-m", "pytest", "test_threat_engine.py::test_missing_identity_does_not_fire_when_bound", "-v"],
            cwd=TESTS_DIR,
        )
        check(after.returncode != 0, "the test now FAILS — the suite caught the regression",
              "the test still passed after the fixture was regressed — the test suite is not "
              "actually protecting this rule's behavior, a real problem worth investigating")
        check("assert 1 == 0" in after.stdout or "AssertionError" in after.stdout,
              "the failure is the expected assertion mismatch, not an unrelated error",
              "the test failed for an unexpected reason — inspect the output above")

    finally:
        step("Restore the test file to its original content")
        TEST_FILE.write_text(original_text)

    check(TEST_FILE.read_text() == original_text, "the test file is restored byte-for-byte",
          "the test file was NOT restored correctly — this is a bug in this demo script, fix by hand immediately")

    step("Confirm the restored test suite passes again")
    restored = run(
        ["python3", "-m", "pytest", "test_threat_engine.py::test_missing_identity_does_not_fire_when_bound", "-v"],
        cwd=TESTS_DIR,
    )
    check(restored.returncode == 0, "the restored test passes again",
          "the restored test does not pass — investigate immediately")

    print(
        "\nThe test suite isn't just 'runs without crashing' — remove the one line\n"
        "of fixture data that represents notification-service's still-missing\n"
        "identity binding today (see threat-model/residual-risk-register.md),\n"
        "and a real, specific test genuinely fails."
    )

    return finish("Scenario 5")


if __name__ == "__main__":
    sys.exit(main())
