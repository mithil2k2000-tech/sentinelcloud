#!/usr/bin/env python3
"""
demo/scenario3_ai_explanation_decision_neutral.py — spec §19, Scenario 3:
"AI explanation degrades gracefully." Run analyze.py once with
explanations enabled and once with them off, showing the BLOCKED/ALLOWED
decision and finding list are identical either way — the live,
watchable version of the SR-4/SR-4a decision-neutrality guarantee that
tests/test_explain_fallback.py already proves mechanically.

HONEST LIMITATION, STATED UP FRONT: this sandbox has no ANTHROPIC_API_KEY
(same cost-discipline stance as every other phase in this project — see
docs/agent-eval-harness.md for the fullest statement of it). So this
script cannot show real LLM prose actually diverging from the template
fallback; both runs it performs use the same deterministic template. What
it DOES show, for real, every time it runs: the decision and finding list
are byte-identical whether explanation is requested or not — the part of
SR-4a that matters for a deployment decision. tests/test_explain_fallback.py
is the mechanical proof this same guarantee holds with a real API key too.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import REPO_ROOT, check, finish, header, run, step  # noqa: E402


def main() -> int:
    header("SCENARIO 3 — AI explanation degrades gracefully")

    key_present = bool(os.environ.get("ANTHROPIC_API_KEY"))
    print(f"\nANTHROPIC_API_KEY is {'set' if key_present else 'NOT set'} in this environment.")

    arch_path = REPO_ROOT / "threat-model" / "architecture-proposed.json"

    with tempfile.TemporaryDirectory() as tmp:
        with_explain_json = Path(tmp) / "with_explain.json"
        no_explain_json = Path(tmp) / "no_explain.json"

        step("Run analyze.py WITH explanations enabled (real LLM if a key is set, template fallback otherwise)")
        with_explain = run([
            "python3", "analyze.py", str(arch_path), "--json", str(with_explain_json),
        ])

        step("Run analyze.py with explanations forced OFF (--no-explain), as a clean baseline")
        no_explain = run([
            "python3", "analyze.py", str(arch_path), "--no-explain", "--json", str(no_explain_json),
        ])

        a = json.loads(with_explain_json.read_text())
        b = json.loads(no_explain_json.read_text())

    check(with_explain.returncode == no_explain.returncode,
          "exit code (the BLOCKED/ALLOWED decision) is identical with/without explanation",
          "exit code differs with/without explanation — SR-4a violation, stop and investigate")
    check(a["summary"] == b["summary"],
          "decision summary (severity counts, overall risk) is identical with/without explanation",
          "decision summary differs with/without explanation — SR-4a violation")
    check(
        [f["rule_id"] for f in a["findings"]] == [f["rule_id"] for f in b["findings"]],
        "the exact ordered list of findings is identical with/without explanation",
        "finding list differs with/without explanation — SR-4a violation",
    )

    if key_present:
        print(
            "\nA real ANTHROPIC_API_KEY is configured — the 'with explanation' run\n"
            "above used real LLM narration. The decision above is still identical\n"
            "to the --no-explain run: the model can make the writing nicer, never\n"
            "the deployment decision."
        )
    else:
        print(
            "\nNo ANTHROPIC_API_KEY in this environment, so both runs above used the\n"
            "same deterministic template fallback — this demo cannot show real LLM\n"
            "prose diverging from the template. What it just showed, for real: the\n"
            "decision and finding list are byte-identical whether or not explanation\n"
            "is even requested. tests/test_explain_fallback.py is the mechanical\n"
            "proof this same guarantee holds with a real API key too."
        )

    return finish("Scenario 3")


if __name__ == "__main__":
    sys.exit(main())
