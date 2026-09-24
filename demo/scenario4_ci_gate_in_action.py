#!/usr/bin/env python3
"""
demo/scenario4_ci_gate_in_action.py — spec §19, Scenario 4: "CI gate in
action." The spec's own text: push a change that reintroduces a fixed
bug and show the GitHub Actions run failing threat-model-gate —
demonstrating the gate is a real control, not a job that always passes.

HONEST LIMITATION, STATED UP FRONT: this repo hasn't been pushed to
GitHub yet (that needs the user's own GitHub auth — see docs/ci-cd.md's
"Getting this onto GitHub" section), so there is no live Actions run to
show, and this script cannot produce one. What follows is the closest
honest local equivalent: it runs the EXACT command threat-model-gate runs
in CI (`analyze.py --fail-on HIGH` against a hardened baseline), against
a deliberately reintroduced, previously-real regression, on a throwaway
temp-file copy — the real committed architecture-hardened.json is never
touched, and this script proves that with its own assertion at the end.
Once the repo is pushed, the true version of this scenario is: make the
same one-line change to threat-model/architecture-hardened.json on a
branch, open a PR, and watch the `threat-model-gate` job go red in the
Actions tab.
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import REPO_ROOT, check, finish, header, run, step  # noqa: E402

HARDENED_PATH = REPO_ROOT / "threat-model" / "architecture-hardened.json"


def main() -> int:
    header("SCENARIO 4 — CI gate in action (local equivalent)")
    print(
        "\nThis repo isn't pushed to GitHub yet, so there's no live Actions run\n"
        "to watch fail. What follows is the honest local equivalent — the exact\n"
        "command threat-model-gate runs in CI, against a deliberately\n"
        "reintroduced regression, on a throwaway copy only. See this script's\n"
        "own module docstring for what the real version looks like once the\n"
        "repo is pushed."
    )

    original_text = HARDENED_PATH.read_text()
    original = json.loads(original_text)

    step("Confirm the real, current hardened baseline passes the gate")
    clean = run(["python3", "analyze.py", str(HARDENED_PATH), "--no-explain", "--fail-on", "HIGH"])
    check(clean.returncode == 0, "current hardened baseline is ALLOWED, as CI expects",
          "current hardened baseline is not ALLOWED — investigate before demoing")

    step("Reintroduce a real, previously-fixed regression on a throwaway copy: "
         "customer-storage.public_network_access -> true")
    regressed = copy.deepcopy(original)
    found_asset = False
    for asset in regressed["assets"]:
        if asset["id"] == "customer-storage":
            asset["public_network_access"] = True
            found_asset = True
    check(found_asset, "found customer-storage in the hardened baseline to regress",
          "customer-storage asset not found — the fixture has changed, update this script")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(regressed, f)
        regressed_path = f.name

    step("Run the exact command threat-model-gate runs in CI, against the regressed copy")
    blocked = run(["python3", "analyze.py", regressed_path, "--no-explain", "--fail-on", "HIGH"])
    check(blocked.returncode == 1, "the regressed copy is BLOCKED — the gate caught it",
          "the regressed copy was NOT blocked — the gate would have missed a real regression")
    check("NET-PUBLIC-01" in blocked.stdout, "the specific reintroduced finding (NET-PUBLIC-01) is present",
          "the reintroduced finding did not appear as expected")

    step("Confirm the real committed baseline was never touched")
    check(HARDENED_PATH.read_text() == original_text, "the real committed baseline is untouched",
          "the real committed baseline was modified — this is a bug in this demo script")

    print(
        "\nSame gate, same command CI runs, a genuine regression caught. The one\n"
        "thing this local run can't show is the GitHub Actions UI itself turning\n"
        "red — that's the honest gap, not something this script pretends around."
    )

    return finish("Scenario 4")


if __name__ == "__main__":
    sys.exit(main())
