#!/usr/bin/env python3
"""
CLI entrypoint — the Phase 11 "AI Cloud Security Architect" agent, thin slice.

Usage:
    python3 analyze.py <architecture.json> [--json out.json] [--no-explain]

Pipeline:
    architecture.json -> threat_engine (deterministic findings)
                       -> explain.narrate_finding (LLM or template, per finding)
                       -> aggregate risk + BLOCKED/ALLOWED decision
                       -> human-readable report (+ optional JSON export)

Exit code is 1 when the decision is BLOCKED, 0 when ALLOWED — so this can be
dropped straight into a CI pipeline as the Phase 2 deployment gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threat_engine import Architecture, Severity, run_engine
from explain import narrate_finding
from risk_model import score_findings
from compliance import load_mappings, render_mapping_table, mapping_rows_for_json


DEFAULT_FAIL_ON = Severity.HIGH  # matches the original "CRITICAL or HIGH blocks" behavior


def aggregate(findings, fail_on: Severity = DEFAULT_FAIL_ON) -> dict:
    """Summarize findings and decide BLOCKED/ALLOWED against a severity
    threshold. fail_on=HIGH (the default) blocks on any HIGH or CRITICAL
    finding — that's the right default for a human running this by hand.
    A CI pipeline may deliberately choose a looser threshold (e.g. CRITICAL
    only) as an explicit, documented risk-acceptance decision rather than
    silently blocking on everything until every phase of the roadmap is
    done — see docs/ci-cd.md for why that's not the same as ignoring the
    findings; they still show up in the report either way."""
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


def render_report(arch_name: str, findings, summary: dict, explanations: dict[str, str]) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f"ARCHITECTURE DECISION — {arch_name}")
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
        lines.append("No findings. (Engine ran 8 rules across the supplied architecture.)")
        return "\n".join(lines)

    lines.append(f"Findings ({len(findings)}, most severe first):")
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
    """Phase 4 (v1 spec §11) supplementary view — opt-in via --risk-model.
    Purely descriptive: reorders/re-labels the SAME findings by a second,
    documented impact x likelihood score (see agent/risk_model.py); never
    changes which findings exist or the BLOCKED/ALLOWED decision above."""
    lines = ["", "Risk model (impact x likelihood, most urgent first):", "-" * 72]
    lines.append(f"{'Rule':<16}{'Impact':<8}{'Likelihood':<12}{'Score':<7}{'Label'}")
    for s in scored:
        lines.append(
            f"{s.finding.rule_id:<16}{s.impact:<8}{s.likelihood:<12}{s.risk_score:<7}{s.risk_label}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("architecture", help="Path to an architecture.json file")
    parser.add_argument("--json", dest="json_out", help="Also write the full report as JSON to this path")
    parser.add_argument("--no-explain", action="store_true", help="Skip the narrative explanation layer entirely")
    parser.add_argument(
        "--risk-model",
        action="store_true",
        help="Also print the Phase 4 impact x likelihood risk table (agent/risk_model.py). "
             "Purely additive — never changes the BLOCKED/ALLOWED decision or which findings exist.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Minimum severity that blocks deployment (default: HIGH — any HIGH or CRITICAL finding blocks). "
             "CI pipelines may pass a looser threshold as an explicit, documented risk-acceptance call.",
    )
    parser.add_argument(
        "--compliance",
        action="store_true",
        help="Also print a CIS Controls v8 / NIST CSF 2.0 / PCI DSS v4.0 mapping table for each finding's "
             "control_id (agent/compliance.py, FR-8). Reference only, not a certification — purely additive, "
             "never changes the BLOCKED/ALLOWED decision or which findings exist.",
    )
    args = parser.parse_args()

    arch = Architecture.from_file(args.architecture)
    findings = run_engine(arch)
    summary = aggregate(findings, fail_on=Severity[args.fail_on])

    explanations: dict[str, str] = {}
    if not args.no_explain:
        for f in findings:
            key = f.rule_id + "|" + ",".join(f.asset_ids)
            explanations[key] = narrate_finding(f)

    report_text = render_report(arch.name, findings, summary, explanations)
    print(report_text)

    scored = None
    if args.risk_model:
        scored = score_findings(findings, arch)
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
            "architecture": arch.name,
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
        # Happens when stdout is piped into something that closes early
        # (e.g. `| head`) — not a real failure, so exit quietly rather
        # than dumping a traceback.
        sys.exit(0)
