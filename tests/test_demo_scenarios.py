"""
tests/test_demo_scenarios.py — spec §16 table item 11 / §22 Definition of
Done: "Five demonstration scenarios (§19) run end-to-end from a clean
checkout with no manual setup beyond documented prerequisites (Python,
pytest, optionally an API key) — verified by actually doing a clean
checkout and running them, not by assuming the README is accurate."

Each demo script (demo/scenarioN_*.py) is a standalone, narrated, self-
asserting walkthrough (see demo/_lib.py's module docstring). This test
runs each one as a real subprocess, from the repo root, and asserts it
exits 0 — the mechanical version of "runs end-to-end from a clean
checkout" that CI enforces on every push, the same way every other phase
in this project backs its documentation with an automated, not manual,
check.

Scenario 5 mutates and restores a real repository file
(tests/test_threat_engine.py) as part of its own demonstration. This test
file does not run concurrently with itself (pytest runs tests in a single
process by default here), and scenario5's own try/finally plus
byte-for-byte restoration check is exercised for real by this test, not
mocked around.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo"

SCENARIO_SCRIPTS = [
    "scenario1_naive_vs_hardened.py",
    "scenario2_three_clouds.py",
    "scenario3_ai_explanation_decision_neutral.py",
    "scenario4_ci_gate_in_action.py",
    "scenario5_rule_catches_a_regression.py",
]


@pytest.mark.parametrize("script_name", SCENARIO_SCRIPTS)
def test_demo_scenario_runs_end_to_end_from_a_clean_checkout(script_name):
    script_path = DEMO_DIR / script_name
    assert script_path.is_file(), f"expected demo script at {script_path}"

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"{script_name} exited {result.returncode}, expected 0\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
    assert "PASS" in result.stdout, (
        f"{script_name} exited 0 but did not print its own PASS confirmation "
        f"(see demo/_lib.py's finish())\n--- stdout ---\n{result.stdout}"
    )


def test_run_all_runs_every_scenario_and_reports_a_combined_pass():
    run_all_path = DEMO_DIR / "run_all.py"
    assert run_all_path.is_file(), f"expected {run_all_path}"

    result = subprocess.run(
        [sys.executable, str(run_all_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"run_all.py exited {result.returncode}, expected 0\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
    for script_name in SCENARIO_SCRIPTS:
        assert f"[PASS]" in result.stdout, "run_all.py did not report any [PASS] scenarios"
    assert "All 5 demonstration scenarios passed." in result.stdout


def test_demo_scenario_five_leaves_the_real_test_fixture_file_unmodified():
    """Independent check, outside scenario5's own internal assertion: the
    real committed tests/test_threat_engine.py is byte-identical before
    and after running scenario 5, proving this test file (and any other
    real file in the repo) was never left in a mutated state."""
    fixture_file = REPO_ROOT / "tests" / "test_threat_engine.py"
    before = fixture_file.read_text()

    result = subprocess.run(
        [sys.executable, str(DEMO_DIR / "scenario5_rule_catches_a_regression.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    after = fixture_file.read_text()
    assert result.returncode == 0, f"scenario 5 failed:\n{result.stdout}\n{result.stderr}"
    assert before == after, (
        "tests/test_threat_engine.py was NOT restored byte-for-byte after "
        "scenario 5 ran — this is a real bug, not a test artifact"
    )


def test_demo_scenario_four_leaves_the_real_hardened_baseline_unmodified():
    """Same independent-check pattern for scenario 4, which mutates a
    throwaway copy of architecture-hardened.json, never the real file."""
    baseline_file = REPO_ROOT / "threat-model" / "architecture-hardened.json"
    before = baseline_file.read_text()

    result = subprocess.run(
        [sys.executable, str(DEMO_DIR / "scenario4_ci_gate_in_action.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    after = baseline_file.read_text()
    assert result.returncode == 0, f"scenario 4 failed:\n{result.stdout}\n{result.stderr}"
    assert before == after, (
        "threat-model/architecture-hardened.json was NOT left unmodified "
        "after scenario 4 ran — this is a real bug, not a test artifact"
    )
