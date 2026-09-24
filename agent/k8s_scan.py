#!/usr/bin/env python3
"""
CLI entrypoint — Phase 5's Kubernetes side, sibling to analyze.py/detect.py.

Usage:
    python3 k8s_scan.py <manifests-dir> [--json out.json] [--no-explain] [--fail-on HIGH]

Pipeline:
    kubernetes/manifests/<set>/ -> k8s_engine (deterministic findings)
                                -> explain.narrate_finding (LLM or template, per finding)
                                -> aggregate risk + BLOCKED/ALLOWED decision
                                -> human-readable report (+ optional JSON export)

Reuses explain.py's narrate_finding directly — a Kubernetes misconfiguration
is a Finding just like an architecture.json one (see k8s_engine.py's module
docstring for why that reuse is deliberate, not incidental). aggregate() is
re-implemented locally rather than imported from analyze.py, matching
detect.py's existing convention: each engine's CLI stays self-contained and
independently runnable/testable, even though the shape is deliberately
identical across all three.

Exit code is 1 when the decision is BLOCKED, 0 when ALLOWED — same
convention as analyze.py, so this can be dropped into the same CI gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from k8s_engine import ALL_RULES, K8sManifest, run_engine
from threat_engine import Severity
from explain import narrate_finding
from compliance import load_mappings, render_mapping_table, mapping_rows_for_json

DEFAULT_FAIL_ON = Severity.HIGH  # any HIGH or CRITICAL finding blocks by default


def aggregate(findings, fail_on: Severity = DEFAULT_FAIL_ON) -> dict:
    """Same shape as analyze.py's aggregate() and detect.py's
    aggregate_alerts(), deliberately — see this module's docstring."""
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


def render_report(source_name: str, findings, summary: dict, explanations: dict[str, str]) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f"KUBERNETES MANIFEST DECISION — {source_name}")
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
        lines.append(f"No findings. (Engine ran {len(ALL_RULES)} rules across the supplied manifests.)")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests_dir", help="Path to a directory of Kubernetes manifest YAML files")
    parser.add_argument("--json", dest="json_out", help="Also write the full report as JSON to this path")
    parser.add_argument("--no-explain", action="store_true", help="Skip the narrative explanation layer entirely")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Minimum severity that blocks deployment (default: HIGH — any HIGH or CRITICAL finding blocks).",
    )
    parser.add_argument(
        "--compliance",
        action="store_true",
        help="Also print a CIS Controls v8 / NIST CSF 2.0 / PCI DSS v4.0 mapping table for each finding's "
             "control_id (agent/compliance.py, FR-8). Reference only, not a certification — purely additive, "
             "never changes the BLOCKED/ALLOWED decision or which findings exist.",
    )
    args = parser.parse_args()

    manifest = K8sManifest.from_dir(args.manifests_dir)
    findings = run_engine(manifest)
    summary = aggregate(findings, fail_on=Severity[args.fail_on])

    explanations: dict[str, str] = {}
    if not args.no_explain:
        for f in findings:
            key = f.rule_id + "|" + ",".join(f.asset_ids)
            explanations[key] = narrate_finding(f)

    report_text = render_report(args.manifests_dir, findings, summary, explanations)
    print(report_text)

    compliance_rows = None
    if args.compliance:
        mappings = load_mappings()
        control_ids = [f.control_id for f in findings]
        print("")
        print(render_mapping_table(control_ids, mappings))
        compliance_rows = mapping_rows_for_json(control_ids, mappings)

    if args.json_out:
        payload = {
            "manifests_dir": args.manifests_dir,
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
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
