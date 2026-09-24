#!/usr/bin/env python3
"""
demo/run_all.py — spec §19 / §16 table item 11: run all five demonstration
scenarios back to back, timed, so the whole walkthrough can be watched (or
CI-checked) as one command. The spec frames this as an "under 10 minutes
total" walkthrough; in practice every scenario here is a handful of local
subprocess calls against small fixtures, so the real total is seconds, not
minutes — that's reported at the end rather than assumed.

Each scenario is its own standalone script (`python3 demo/scenarioN_*.py`
also works on its own) — this just sequences all five and gives one
combined PASS/FAIL summary. A failure in one scenario does not stop the
others from running: this script wants to report the full picture, not
stop at the first red light.

Scenario 5 mutates and restores a real repository file
(tests/test_threat_engine.py) as part of demonstrating that the test suite
catches a real regression — see that script's own module docstring for the
safety mechanism (try/finally + byte-for-byte restoration check). Running
scenarios out of order, or running scenario5 concurrently with anything
else that touches that same file, is not supported.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent

SCENARIOS = [
    ("Scenario 1 — Naive vs. hardened", "scenario1_naive_vs_hardened.py"),
    ("Scenario 2 — Same pattern, three clouds", "scenario2_three_clouds.py"),
    ("Scenario 3 — AI explanation degrades gracefully", "scenario3_ai_explanation_decision_neutral.py"),
    ("Scenario 4 — CI gate in action (local equivalent)", "scenario4_ci_gate_in_action.py"),
    ("Scenario 5 — A rule catches a real regression", "scenario5_rule_catches_a_regression.py"),
]


def main() -> int:
    print("=" * 78)
    print("SentinelCloud — full demonstration walkthrough (spec §19)")
    print("=" * 78)

    overall_start = time.monotonic()
    results: list[tuple[str, bool, float]] = []

    for name, filename in SCENARIOS:
        start = time.monotonic()
        proc = subprocess.run([sys.executable, str(DEMO_DIR / filename)])
        elapsed = time.monotonic() - start
        results.append((name, proc.returncode == 0, elapsed))

    overall_elapsed = time.monotonic() - overall_start

    print()
    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    all_passed = True
    for name, passed, elapsed in results:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"  [{status}] {name}  ({elapsed:.2f}s)")

    print(f"\nTotal wall time: {overall_elapsed:.2f}s (spec framing: 'under 10 minutes')")

    if all_passed:
        print("\nAll 5 demonstration scenarios passed.")
        return 0
    else:
        print("\nAt least one demonstration scenario failed — see its output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
