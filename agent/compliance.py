#!/usr/bin/env python3
"""
compliance.py — FR-8 in the SentinelCloud v1 spec (§16 development table,
item 5): map each deterministic control_id to a recognized framework's own
control numbering, for engineering traceability only.

REFERENCE ONLY, NOT A CERTIFICATION (SR-6 — "No False Compliance Claims").
This module never decides BLOCKED/ALLOWED and never runs at LLM discretion —
it's a pure, deterministic lookup against policy/framework-mappings.yaml,
consumed by analyze.py's and k8s_scan.py's optional --compliance flag. Every
function that renders a mapping for a human (render_mapping_table below, and
anything built on top of it) is required to include the literal string
"reference only, not a certification" somewhere in its output — see
tests/test_compliance.py::test_render_mapping_table_includes_reference_only_label,
which checks this directly rather than trusting this docstring.

Deliberately scoped to threat_engine.py and k8s_engine.py's Finding-based
control_ids only. detection_engine.py's Alert dataclass has no control_id
field at all (see docs/phase9-siem-detection.md's "why two engines" section
for why Alert and Finding are deliberately different shapes) — a detected
alert is a retrospective claim about events that already happened, not a
design-time control that could ever have a framework mapping. There is
nothing to map an Alert to, so detect.py has no --compliance flag and never
will unless Alert grows its own, separately-justified control concept.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REFERENCE_ONLY_LABEL = "(reference only, not a certification)"

_DEFAULT_MAPPINGS_PATH = Path(__file__).resolve().parent.parent / "policy" / "framework-mappings.yaml"

_FRAMEWORK_DISPLAY_NAMES = {
    "cis_v8": "CIS Controls v8",
    "nist_csf_2": "NIST CSF 2.0",
    "pci_dss_v4": "PCI DSS v4.0",
}


def load_mappings(path: Path | str = _DEFAULT_MAPPINGS_PATH) -> dict:
    """Load policy/framework-mappings.yaml and return its `mappings` dict,
    keyed by control_id. Raises FileNotFoundError / yaml.YAMLError as-is if
    the file is missing or malformed — callers (the CLIs) are expected to
    let that surface rather than silently degrading a security report."""
    data = yaml.safe_load(Path(path).read_text())
    if not data or "mappings" not in data:
        raise ValueError(f"{path}: expected a top-level 'mappings' key")
    return data["mappings"]


def get_mapping(control_id: str, mappings: dict | None = None) -> dict | None:
    """Look up a single control_id's mapping entry. Returns None if this
    control_id has no mapping on file — callers decide how to surface that
    (analyze.py/k8s_scan.py render it as an explicit gap, not a silent
    omission; see render_mapping_table below)."""
    if mappings is None:
        mappings = load_mappings()
    return mappings.get(control_id)


def render_mapping_table(control_ids: list[str], mappings: dict | None = None) -> str:
    """Render a human-readable compliance-mapping table for a list of
    control_ids (typically the control_ids of a run's actual findings).
    Always includes the REFERENCE_ONLY_LABEL — this is the one function
    every consumer of this module is expected to call rather than
    hand-rolling their own rendering, so the label can't be forgotten at
    a second call site."""
    if mappings is None:
        mappings = load_mappings()

    lines = []
    lines.append("-" * 72)
    lines.append(f"Compliance framework mapping {REFERENCE_ONLY_LABEL}")
    lines.append(
        "Internal control_ids below are mapped to CIS Controls v8, NIST CSF 2.0,"
    )
    lines.append(
        "and PCI DSS v4.0 for engineering traceability only. This is NOT an audit,"
    )
    lines.append(
        "a certification, or a claim that any of these frameworks' requirements"
    )
    lines.append("are actually satisfied. See policy/framework-mappings.yaml.")
    lines.append("-" * 72)

    seen = []
    for cid in control_ids:
        if cid in seen:
            continue
        seen.append(cid)

    if not seen:
        lines.append("(no findings — nothing to map)")
        return "\n".join(lines)

    for cid in seen:
        entry = get_mapping(cid, mappings)
        if entry is None:
            lines.append(f"{cid}: NO MAPPING ON FILE — see policy/framework-mappings.yaml")
            lines.append("")
            continue
        lines.append(f"{cid}: {entry.get('description', '')}")
        for fw_key, fw_label in _FRAMEWORK_DISPLAY_NAMES.items():
            fw = entry["frameworks"].get(fw_key)
            if fw:
                lines.append(f"    {fw_label:<16} {fw['control']:<10} {fw['title']}")
        lines.append("")

    return "\n".join(lines).rstrip()


def control_ids_in_source(path: Path | str) -> set[str]:
    """Every literal control_id="..." in a given engine source file — the
    same regex-scan technique tests/test_compliance.py's static-scan tests
    already use to guarantee every control_id an engine can emit has a
    mapping entry. report_compliance.py (Phase 8, "compliance/audit
    reporting polish") uses this to scope an audit report to only the
    controls a given engine could possibly touch: a control that a
    particular scan never even checks should never be rendered as a false
    PASS just because no finding happened to reference it."""
    return set(re.findall(r'control_id="([^"]+)"', Path(path).read_text()))


def mapping_rows_for_json(control_ids: list[str], mappings: dict | None = None) -> list[dict]:
    """Same data as render_mapping_table, structured for a --json report
    instead of a printed table. Each row explicitly repeats the
    reference-only framing so a consumer reading the JSON in isolation
    (without the human-readable report text) still can't mistake this for
    a certification result."""
    if mappings is None:
        mappings = load_mappings()

    rows = []
    seen = []
    for cid in control_ids:
        if cid in seen:
            continue
        seen.append(cid)

    for cid in seen:
        entry = get_mapping(cid, mappings)
        row = {
            "control_id": cid,
            "reference_only": True,
            "label": REFERENCE_ONLY_LABEL,
        }
        if entry is None:
            row["mapped"] = False
            row["description"] = None
            row["frameworks"] = {}
        else:
            row["mapped"] = True
            row["description"] = entry.get("description", "")
            row["frameworks"] = entry.get("frameworks", {})
        rows.append(row)
    return rows
