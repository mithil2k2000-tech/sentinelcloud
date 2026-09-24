#!/usr/bin/env python3
"""
CLI entrypoint — Phase 7's drift detector, sibling to analyze.py/k8s_scan.py/detect.py.

Usage:
    python3 drift_scan.py <baseline.json> <current.json> [--json out.json] [--no-explain] [--fail-on HIGH] [--compliance] [--risk-model]

Pipeline:
    baseline architecture.json + current architecture.json
        -> drift.py (deterministic diff -> findings)
        -> explain.narrate_finding (LLM or template, per finding)
        -> aggregate risk + BLOCKED/ALLOWED decision
        -> human-readable report (+ optional JSON export)

SIMULATED MODE ONLY — see drift.py's module docstring. `current` is never
fetched from a live cloud API here; both arguments are architecture.json
files, exactly like analyze.py's single argument. In a real deployment,
`current` would be produced by a separate, not-yet-built step that reads
actual provider state back into this same JSON shape — this CLI's job
starts after that translation, not before it.

READ-ONLY, ALWAYS. This CLI never writes to `baseline`, `current`, or any
cloud resource — seedrift.py's module docstring for why "no auto-remediate"
is a hard rule here, not a missing feature.

Exit code is 1 when the decision is BLOCKED, 0 when ALLOWED — same
convention as every other CLI in this project.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threat_engine import Architecture, Severity
from drift import run_engine
from explain import narrate_finding
from risk_model import score_findings
from compliance import load_mappings, render_mapping_table, mapping_rows_for_json

DEFAULT_FAIL_ON = Severity.HIGH  # any HIGH or CRITICAL finding blocks by default


def aggregate(findings, fail_on: Severity = DEFAULT_FAIL_ON) -> dict:
    """Same shape as analyze.py's/k8s_scan.py's/detect.py's own aggregate
    functions, deliberately — see those modules' docstrings for why each
    CLI keeps its own copy rather than importing a shared one."""
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    if counts[Severity.CRITICAL] > 0:
        overall = "CRITICAL"
    elif counts[Severity.HIGH] > 0:
        overall = "HIGH"
    elif counts[Severity.MEDIUM] > 0:
        overall = "MEDIUM"
    elif counts[Severity.LOW] > 0:
        overall = "LOW"
    else:
        overall = "NONE"
    blocked = any(f.severity.value >= fail_on.value for f in findings)
    return {
        "overall_risk": overall,
        "counts": {str(s): counts[s] for s in Severity},
        "fail_on": str(fail_on),
        "deployment": "BLOCKED" if blocked else "ALLOWED",
    }


def render_report(baseline_name: str, current_name: str, findings, summary: dict, explanations: dict[str, str]) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f"DRIFT REPORT — baseline: {baseline_name}  vs  current: {current_name}")
    lines.append("=" * 72)
    lines.append(f"Overall Risk: {summary['overall_risk']}")
    lines.append(
        "CRITICAL: {CRITICAL}  HIGH: {HIGH}  MEDIUM: {MEDIUM}  LOW: {LOW}".format(
            **summary["counts"]
        )
    )
    deploy_symbol = "❌ BLOCKED" if summary["deployment"] == "BLOCKED" else "✅ ALLOWED"
    lines.append(f"Deployment: {deploy_symbol}  (gate threshold: {summary['fail_on']}+)")
    lines.append("")

    if not findings:
        lines.append(f"No drift detected. (Engine compared {len(findings)} findings across 8 drift rules; current matches baseline.)")
        return "\n".join(lines)

    lines.append(f"Drift findings ({len(findings)}, most severe first):")
    lines.append("-" * 72)
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f.severity} — {f.stride.value} — {f.rule_id}")
        lines.append(f"    Finding:    {f.title}")
        lines.append(f"    Control:    {f.control_id}")
        lines.append(f"    Policy:     {f.policy}")
        lines.append(f"    Status:     FAIL")
        narrative = explanations.get(f.rule_id + "|" + ",".join(f.asset_ids))
        if narrative:
            lines.append(f"    Explained:  {narrative}")
        lines.append("")

    return "\n".join(lines)


def render_risk_table(scored) -> str:
    lines = ["", "Risk model (impact x likelihood, most urgent first):", "-" * 72]
    lines.append(f"{'Rule':<24}{'Impact':<8}{'Likelihood':<12}{'Score':<7}{'Label'}")
    for s in scored:
        lines.append(
            f"{s.finding.rule_id:<24}{s.impact:<8}{s.likelihood:<12}{s.risk_score:<7}{s.risk_label}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="Path to the last-known-good architecture.json")
    parser.add_argument("current", help="Path to the current/observed architecture.json (simulated — see drift.py's docstring)")
    parser.add_argument("--json", dest="json_out", help="Also write the full report as JSON to this path")
    parser.add_argument("--no-explain", action="store_true", help="Skip the narrative explanation layer entirely")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Minimum severity that blocks deployment (default: HIGH — any HIGH or CRITICAL drift finding blocks).",
    )
    parser.add_argument(
        "--risk-model",
        action="store_true",
        help="Also print the impact x likelihood risk table (agent/risk_model.py), scored against the current architecture. Purely additive.",
    )
    parser.add_argument(
        "--compliance",
        action="store_true",
        help="Also print the CIS/NIST/PCI framework mapping table (agent/compliance.py, FR-8) for each drift finding's control_id. Reference only, not a certification. Purely additive.",
    )
    args = parser.parse_args()

    baseline = Architecture.from_file(args.baseline)
    current = Architecture.from_file(args.current)
    findings = run_engine(baseline, current)
    summary = aggregate(findings, fail_on=Severity[args.fail_on])

    explanations: dict[str, str] = {}
    if not args.no_explain:
        for f in findings:
            key = f.rule_id + "|" + ",".join(f.asset_ids)
            explanations[key] = narrate_finding(f)

    report_text = render_report(baseline.name, current.name, findings, summary, explanations)
    print(report_text)

    scored = None
    if args.risk_model:
        scored = score_findings(findings, current)
        print(render_risk_table(scored))

    compliance_rows = None
    if args.compliance:
        mappings = load_mappings()
        control_ids = [f.control_id for f in findings]
        print("")
        print(render_mapping_table(control_ids, mappings))
        compliance_rows = mapping_rows_for_json(control_ids, mappings)

    if args.json_out:
        payload = {
            "baseline": args.baseline,
            "current": args.current,
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        if scored is not None:
            payload["risk_model"] = [s.to_dict() for s in scored]
        if compliance_rows is not None:
            payload["compliance"] = compliance_rows
        Path(args.json_out).write_text(json.dumps(payload, indent=2))
        print(f"\n(full JSON report written to {args.json_out})")

    return 1 if summary["deployment"] == "BLOCKED" else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
