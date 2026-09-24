#!/usr/bin/env python3
"""
report_compliance.py — SentinelCloud v1 spec §16 development table, item 8
("Compliance/audit reporting polish"): "Turn Phase 5's mapping into a
rendered audit-style report."

REFERENCE ONLY, NOT A CERTIFICATION — same SR-6 guarantee as
agent/compliance.py, which this module builds directly on top of. This is
NOT a new engine and NOT a new gate: it runs threat_engine.py's existing
deterministic rules against one architecture.json, then re-presents the
policy/framework-mappings.yaml data (Phase 5/FR-8) as a per-framework
PASS/FAIL checklist — an audit-style READING of output two earlier phases
already produced, not a new source of findings or a new decision. The
underlying BLOCKED/ALLOWED call stays wherever it already lives
(analyze.py) — this module never makes or overrides that call, and always
exits 0: it's a report generator, not a gate. Every report this module
renders repeats the REFERENCE_ONLY_LABEL from compliance.py, unconditionally.

SCOPED ON PURPOSE, and the report says so. `agent/threat_engine.py` can
only ever emit 6 of the 15 control_ids in policy/framework-mappings.yaml
(IAM-004, NET-001, DATA-002, ZT-001, NET-003, LOG-001) — it has no way to
check a Kubernetes-manifest control (K8S-*) or a drift control (DRIFT-*),
because those aren't questions an architecture.json can answer. A naive
report that walked ALL 15 mapped controls and marked anything with no
matching finding as "PASS" would be a false claim: K8S-*/DRIFT-* controls
would read as passing when they were never assessed at all, for a
scan that never even looked at Kubernetes manifests or a drift snapshot.
compliance.control_ids_in_source(threat_engine.py) is used to compute the
REAL 6-control scope for this kind of report before any PASS/FAIL verdict
is rendered — see docs/compliance-audit-report.md for the honest
limitations this still leaves (e.g. this report has no K8s/drift
equivalent yet).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from threat_engine import Architecture, run_engine
from compliance import (
    REFERENCE_ONLY_LABEL,
    control_ids_in_source,
    load_mappings,
)

AGENT_DIR = Path(__file__).resolve().parent
THREAT_ENGINE_PATH = AGENT_DIR / "threat_engine.py"

_FRAMEWORK_DISPLAY_NAMES = {
    "cis_v8": "CIS Controls v8",
    "nist_csf_2": "NIST CSF 2.0",
    "pci_dss_v4": "PCI DSS v4.0",
}


def audit_rows(architecture_name: str, findings, mappings: dict, in_scope_control_ids: set[str]) -> list[dict]:
    """One row per in-scope control_id, PASS or FAIL against this run's
    actual findings. Deterministic and sorted (by control_id) so this is
    safe to snapshot-test — no wall-clock dependency of any kind lives in
    this function."""
    violated: dict[str, list] = {}
    for f in findings:
        violated.setdefault(f.control_id, []).append(f)

    rows = []
    for control_id in sorted(in_scope_control_ids):
        entry = mappings.get(control_id)
        findings_here = violated.get(control_id, [])
        rows.append(
            {
                "control_id": control_id,
                "status": "FAIL" if findings_here else "PASS",
                "description": entry.get("description", "") if entry else "(no mapping on file)",
                "frameworks": entry.get("frameworks", {}) if entry else {},
                "findings": [
                    {"rule_id": f.rule_id, "title": f.title, "severity": str(f.severity), "assets": f.asset_ids}
                    for f in findings_here
                ],
            }
        )
    return rows


def render_audit_report(architecture_name: str, rows: list[dict], total_mapped_controls: int, as_of: str | None = None) -> str:
    """Pure, deterministic rendering — same rows in, same markdown out,
    every time. `as_of` defaults to None (rendered literally as "not
    specified") rather than defaulting to today's date, specifically so
    this function's output is snapshot-testable without a wall-clock
    dependency; the CLI passes a real date by default, tests pass a fixed
    one."""
    lines = []
    lines.append("# Compliance Audit-Style Report " + REFERENCE_ONLY_LABEL)
    lines.append("")
    lines.append(f"**Subject:** {architecture_name}")
    lines.append(
        f"**Scope:** controls checked by `agent/threat_engine.py` only "
        f"({len(rows)} of {total_mapped_controls} controls in "
        f"`policy/framework-mappings.yaml`). Kubernetes-specific and "
        f"infrastructure-drift controls are assessed separately — see "
        f"`agent/k8s_scan.py --compliance` and `agent/drift_scan.py --compliance`."
    )
    lines.append(f"**As of:** {as_of if as_of else 'not specified'}")
    lines.append("")
    lines.append(
        "This is NOT an audit, a certification, or a claim that this "
        "architecture satisfies any of the frameworks below. It restates "
        "the SentinelCloud compliance-mapping file "
        "(`policy/framework-mappings.yaml`, FR-8) as a per-framework "
        "PASS/FAIL checklist against this run's actual findings, for "
        "engineering traceability only (SR-6)."
    )
    lines.append("")

    passed = sum(1 for r in rows if r["status"] == "PASS")
    failed = sum(1 for r in rows if r["status"] == "FAIL")
    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"- Controls in scope: {len(rows)}")
    lines.append(f"- PASS: {passed}")
    lines.append(f"- FAIL: {failed}")
    lines.append("")

    for fw_key, fw_label in _FRAMEWORK_DISPLAY_NAMES.items():
        lines.append(f"## {fw_label}")
        lines.append("")
        lines.append("| Control | Status | Title | Internal control_id |")
        lines.append("| --- | --- | --- | --- |")
        for row in rows:
            fw = row["frameworks"].get(fw_key)
            fw_control = fw["control"] if fw else "n/a"
            fw_title = fw["title"] if fw else "(no mapping on file)"
            lines.append(f"| {fw_control} | {row['status']} | {fw_title} | {row['control_id']} |")
        lines.append("")

    failing_rows = [r for r in rows if r["status"] == "FAIL"]
    lines.append("## Failing controls — detail")
    lines.append("")
    if not failing_rows:
        lines.append("None — every in-scope control passed this run.")
    else:
        for row in failing_rows:
            fw_refs = ", ".join(
                f"{_FRAMEWORK_DISPLAY_NAMES[k]} {v['control']}"
                for k, v in row["frameworks"].items()
            )
            lines.append(f"### {row['control_id']} ({fw_refs})" if fw_refs else f"### {row['control_id']}")
            lines.append("")
            lines.append(row["description"])
            lines.append("")
            for f in row["findings"]:
                lines.append(f"- [{f['severity']}] `{f['rule_id']}` — {f['title']} (assets: {', '.join(f['assets'])})")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("architecture", help="Path to an architecture.json file")
    parser.add_argument("--json", dest="json_out", help="Also write the audit rows as JSON to this path")
    parser.add_argument("--out", dest="report_out", help="Write the rendered report to this path instead of stdout")
    parser.add_argument("--as-of", dest="as_of", help="Date/label to stamp the report with (default: not specified)")
    args = parser.parse_args()

    arch = Architecture.from_file(args.architecture)
    findings = run_engine(arch)
    mappings = load_mappings()
    in_scope = control_ids_in_source(THREAT_ENGINE_PATH)
    rows = audit_rows(arch.name, findings, mappings, in_scope)
    report_text = render_audit_report(arch.name, rows, total_mapped_controls=len(mappings), as_of=args.as_of)

    if args.report_out:
        Path(args.report_out).write_text(report_text)
        print(f"(audit report written to {args.report_out})")
    else:
        print(report_text)

    if args.json_out:
        payload = {
            "architecture": arch.name,
            "as_of": args.as_of,
            "reference_only": True,
            "label": REFERENCE_ONLY_LABEL,
            "controls_in_scope": len(rows),
            "controls_total_mapped": len(mappings),
            "rows": rows,
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2))
        print(f"(audit JSON written to {args.json_out})")

    # Always 0 — a report generator, not a gate. See this module's own
    # docstring for why: the BLOCKED/ALLOWED decision belongs to
    # analyze.py alone, this never duplicates or overrides it.
    return 0


if __name__ == "__main__":
    import sys

    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
