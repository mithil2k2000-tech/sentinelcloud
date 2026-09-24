#!/usr/bin/env python3
"""
demo/scenario1_naive_vs_hardened.py — spec §19, Scenario 1: "Naive vs.
hardened, side by side." Run analyze.py against the naive first-draft
design and the hardened Azure baseline back to back — shows the engine
actually discriminating between a bad design and a better one with real
numbers, not a scripted "pass" demo.

HONEST DIVERGENCE FROM THE SPEC'S OWN LITERAL §19 TEXT: the spec (written
before Phase 4/Zero Trust existed) predicts the hardened run would be "0
CRITICAL, still BLOCKED on real remaining HIGH findings." That was true
when it was written. Phase 4 (mesh-wide mTLS + a scoped account-service
identity) closed the last open HIGH finding on all three clouds, so the
hardened Azure baseline today is 0 CRITICAL, 0 HIGH, ALLOWED — a
stronger result than the spec predicted, not a weaker one. This script
asserts the REAL current numbers rather than quietly matching stale
spec prose to reality — see docs/demo-scenarios.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import REPO_ROOT, check, finish, header, run, step  # noqa: E402


def main() -> int:
    header("SCENARIO 1 — Naive vs. hardened, side by side")

    step("Run analyze.py against the naive first-draft design (architecture-proposed.json)")
    naive = run([
        "python3", "analyze.py",
        str(REPO_ROOT / "threat-model" / "architecture-proposed.json"),
        "--no-explain",
    ])
    check(naive.returncode == 1, "naive design is BLOCKED", "naive design did not BLOCK — investigate before demoing")
    check("CRITICAL: 6" in naive.stdout, "6 CRITICAL findings on the naive design, as documented",
          "CRITICAL count drifted from the documented 6 — investigate before demoing")
    check("Findings (13," in naive.stdout, "13 total findings on the naive design, as documented",
          "finding count drifted from the documented 13")

    step("Run analyze.py against the hardened Azure baseline (architecture-hardened.json)")
    hardened = run([
        "python3", "analyze.py",
        str(REPO_ROOT / "threat-model" / "architecture-hardened.json"),
        "--no-explain", "--fail-on", "HIGH",
    ])
    check(hardened.returncode == 0, "hardened Azure baseline is ALLOWED at --fail-on HIGH",
          "hardened baseline did not ALLOW — a real regression, investigate before demoing")
    check("CRITICAL: 0  HIGH: 0" in hardened.stdout, "0 CRITICAL, 0 HIGH on the hardened baseline",
          "finding counts drifted from the documented current state")

    print(
        "\nSame engine, same rules, two different inputs: 13 findings / BLOCKED\n"
        "vs. 2 findings / ALLOWED. That's the engine actually discriminating\n"
        "between a bad design and a better one, with real numbers each time\n"
        "this script runs — not a scripted \"pass\" demo."
    )

    return finish("Scenario 1")


if __name__ == "__main__":
    sys.exit(main())
