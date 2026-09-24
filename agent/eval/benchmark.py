#!/usr/bin/env python3
"""
agent/eval/benchmark.py — SentinelCloud v1 spec §16 development table,
item 10 ("Agent evaluation harness"), FR-11: "benchmark every AI-assisted
capability."

WHAT COUNTS AS AN "AI-ASSISTED CAPABILITY" HERE. Exactly two:
explain.py's narrate_finding() (used by analyze.py, k8s_scan.py, AND
drift_scan.py — three different engines, one narration function, per
k8s_engine.py's own design note about reusing Finding/explain.py rather
than inventing a fourth shape) and triage.py's narrate_alert() (used by
detect.py). report_compliance.py is deliberately excluded — it never
calls an LLM at all (see its own module docstring: a pure rendering layer
over data two earlier phases already produced) — so there is nothing to
benchmark there.

WHAT THIS DOES NOT DO. It does not, and cannot, judge whether a narrative
is *well-written* — that would need either a human rater or a second LLM
call acting as judge, and this project has consistently avoided adding
non-deterministic, paid, or non-reproducible steps to anything that
claims to be a repeatable "test" (same stance as agent/drift.py staying
SIMULATED-only and report_compliance.py never re-deciding BLOCKED/ALLOWED,
applied here to evaluation instead of detection). What it DOES check, per
narrative, is a fixed, deterministic grounding rubric — five checks, all
of which must pass for that item to score PASS:
  1. the narrative is present and long enough to be useful;
  2. the LLM layer didn't silently fail over to its own error marker
     (an API failure is scored a FAIL here, never a silent pass);
  3. the narrative avoids the exact SR-6 overclaim vocabulary this
     project polices everywhere else (report_compliance.py's own report,
     compliance.py's REFERENCE_ONLY_LABEL) — a spot-check that the
     explanation layer itself never accidentally claims a certification;
  4. the narrative never states a severity word other than the real one;
  5. the narrative shares at least one real content word with the
     underlying finding/alert's own title — a cheap, deterministic proxy
     for "this narrative is actually about what it claims to be about,"
     NOT a proof of semantic correctness. See docs/agent-eval-harness.md
     for the honest limitation this leaves (false positives are possible
     on natural, paraphrased LLM prose — this is why the pass threshold
     below is deliberately not 100%, even though this sandbox's own run
     always scores 100% — see the next paragraph).

WHY THE FIXTURE SET IS "REAL ENGINE OUTPUT," NOT A NEW HAND-WRITTEN FILE.
Rather than inventing and maintaining a separate fixture file, the
benchmark set is built by running the same real engines
(threat_engine, k8s_engine, drift, detection_engine) against the same
real fixtures every other CLI and test in this repo already uses:
architecture-proposed.json (13 findings, all 6 threat rules),
kubernetes/manifests/vulnerable (14 findings, all 8 K8s rules), the
architecture-hardened/architecture-drifted pair (7 drift findings), and
logs-multi-stage-incident.json (4 alerts, all 4 triggerable detection
rules). That's every rule in every AI-narrated engine represented at
least once — 38 items total — with zero duplicated fixture maintenance
and zero risk of the benchmark set silently drifting out of sync with
what the engines actually produce.

WHY THIS SANDBOX'S RUN IS FALLBACK-MODE ONLY, DOCUMENTED HONESTLY. No
ANTHROPIC_API_KEY is set in this environment (same cost-discipline stance
followed throughout this project), so every narrate_finding()/
narrate_alert() call here goes through the deterministic template
fallback, never a real model call. The rubric was deliberately designed
so the template fallback scores 100% by construction (it verbatim
includes the finding/alert's own title, never states a severity word, and
never emits the SR-6-forbidden vocabulary) — a real run in this sandbox
is a harness regression test proving the scoring mechanism and pipeline
are wired correctly end to end, not a demonstration of real LLM narration
quality. DEFAULT_PASS_THRESHOLD is set below 1.0 anyway, specifically to
leave headroom for the day a real API key is configured and real,
paraphrased narrations start landing here instead — see
docs/agent-eval-harness.md.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from threat_engine import Architecture, run_engine as run_threat_engine  # noqa: E402
from k8s_engine import K8sManifest, run_engine as run_k8s_engine  # noqa: E402
from drift import run_engine as run_drift_engine  # noqa: E402
from detection_engine import load_events, run_detection  # noqa: E402
from explain import narrate_finding  # noqa: E402
from triage import narrate_alert  # noqa: E402

# Documented pass threshold (spec's own required-test wording: "a
# documented pass threshold"). Deliberately below 1.0 even though this
# sandbox's fallback-only run always scores 100% — see the module
# docstring's last paragraph for why.
DEFAULT_PASS_THRESHOLD = 0.95

_ERROR_MARKERS = ("[LLM explanation unavailable", "[LLM triage unavailable")
_FORBIDDEN_PHRASES = (
    "certified", "certification", "guarantee compliance", "guaranteed compliant",
    "fully compliant", "passes audit", "audit passed",
)
_SEVERITY_WORDS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_STOPWORDS = {
    "the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "is", "no",
    "not", "with", "at", "by", "this", "that", "into", "from", "as", "are",
    "left", "could", "would", "should",
}


@dataclass
class BenchmarkItem:
    kind: str  # "finding" | "alert"
    source: str  # which engine/fixture this came from, for reporting
    identifier: str  # rule_id
    severity: str
    title: str
    narrative: str


def _content_words(text: str) -> set[str]:
    return {
        w.strip(".,:;()\"'").lower()
        for w in text.split()
        if len(w) >= 5 and w.strip(".,:;()\"'").lower() not in _STOPWORDS
    }


def build_fixture_set() -> list[BenchmarkItem]:
    """Run the real engines against the real fixtures already in this
    repo and narrate every finding/alert they produce. See the module
    docstring for why this is built from real engine output rather than a
    separately hand-maintained fixture file."""
    items: list[BenchmarkItem] = []

    proposed = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-proposed.json")
    for f in run_threat_engine(proposed):
        items.append(BenchmarkItem(
            "finding", "threat_engine/architecture-proposed.json", f.rule_id,
            str(f.severity), f.title, narrate_finding(f),
        ))

    manifest = K8sManifest.from_dir(REPO_ROOT / "kubernetes" / "manifests" / "vulnerable")
    for f in run_k8s_engine(manifest):
        items.append(BenchmarkItem(
            "finding", "k8s_engine/manifests/vulnerable", f.rule_id,
            str(f.severity), f.title, narrate_finding(f),
        ))

    baseline = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-hardened.json")
    current = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-drifted.json")
    for f in run_drift_engine(baseline, current):
        items.append(BenchmarkItem(
            "finding", "drift/architecture-hardened-vs-drifted.json", f.rule_id,
            str(f.severity), f.title, narrate_finding(f),
        ))

    events = load_events(REPO_ROOT / "threat-model" / "logs" / "logs-multi-stage-incident.json")
    for a in run_detection(events):
        items.append(BenchmarkItem(
            "alert", "detection_engine/logs-multi-stage-incident.json", a.rule_id,
            str(a.severity), a.title, narrate_alert(a),
        ))

    return items


def score_item(item: BenchmarkItem) -> dict:
    """Score one narrative against the five-check grounding rubric
    described in the module docstring. Returns {"passed": bool,
    "checks": {name: bool}} — every individual check is reported, not
    just the aggregate, so a failure is diagnosable without re-running
    anything."""
    checks: dict[str, bool] = {}

    checks["nonempty_and_substantial"] = len(item.narrative.strip()) >= 20

    checks["no_llm_error_fallback"] = not any(m in item.narrative for m in _ERROR_MARKERS)

    narrative_lower = item.narrative.lower()
    checks["no_forbidden_overclaim_language"] = not any(p in narrative_lower for p in _FORBIDDEN_PHRASES)

    other_severities = [s for s in _SEVERITY_WORDS if s != item.severity]
    checks["no_contradicting_severity_word"] = not any(
        re.search(rf"\b{s}\b", item.narrative.upper()) for s in other_severities
    )

    title_words = _content_words(item.title)
    narrative_words = _content_words(item.narrative)
    checks["shares_a_real_word_with_title"] = bool(title_words) and bool(title_words & narrative_words)

    return {"passed": all(checks.values()), "checks": checks}


def run_benchmark(items: list[BenchmarkItem] | None = None, threshold: float = DEFAULT_PASS_THRESHOLD) -> dict:
    items = items if items is not None else build_fixture_set()
    results = []
    for item in items:
        scored = score_item(item)
        results.append({
            "kind": item.kind,
            "source": item.source,
            "identifier": item.identifier,
            "severity": item.severity,
            "title": item.title,
            "narrative": item.narrative,
            **scored,
        })
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    pass_rate = passed / total if total else 0.0
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": pass_rate,
        "threshold": threshold,
        "meets_threshold": pass_rate >= threshold,
        "results": results,
    }


def render_report(summary: dict) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("AGENT EVALUATION HARNESS — AI-assisted capability benchmark")
    lines.append("=" * 72)
    lines.append(f"Items scored:  {summary['total']}")
    lines.append(f"Passed:        {summary['passed']}")
    lines.append(f"Failed:        {summary['failed']}")
    lines.append(f"Pass rate:     {summary['pass_rate']:.1%}  (threshold: {summary['threshold']:.0%})")
    lines.append(f"Result:        {'PASS' if summary['meets_threshold'] else 'FAIL'}")
    lines.append("")

    failing = [r for r in summary["results"] if not r["passed"]]
    if failing:
        lines.append(f"Failing items ({len(failing)}):")
        lines.append("-" * 72)
        for r in failing:
            failed_checks = [k for k, v in r["checks"].items() if not v]
            lines.append(f"[{r['severity']}] {r['source']} — {r['identifier']}: {r['title']}")
            lines.append(f"    Failed checks: {', '.join(failed_checks)}")
            lines.append(f"    Narrative: {r['narrative'][:160]}")
            lines.append("")
    else:
        lines.append("No failing items.")

    return "\n".join(lines)


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_out", help="Write the full benchmark result as JSON to this path")
    parser.add_argument(
        "--threshold", type=float, default=DEFAULT_PASS_THRESHOLD,
        help=f"Override the documented pass-rate threshold (default: {DEFAULT_PASS_THRESHOLD}).",
    )
    args = parser.parse_args()

    summary = run_benchmark(threshold=args.threshold)
    print(render_report(summary))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(summary, indent=2))
        print(f"\n(full JSON result written to {args.json_out})")

    # Unlike analyze.py/k8s_scan.py's exit code, this one never touches a
    # deployment decision (SR-4a: the AI layer's quality can never affect
    # BLOCKED/ALLOWED) — it only reports whether the AI-assisted
    # capabilities themselves are healthy. See docs/agent-eval-harness.md
    # for why this CAN still fail its own CI job without that job ever
    # being wired into threat-model-gate/k8s-manifest-gate.
    return 0 if summary["meets_threshold"] else 1


if __name__ == "__main__":
    sys.exit(main())
