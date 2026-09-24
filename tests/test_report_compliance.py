"""
Tests for agent/report_compliance.py — spec §16 table item 8 ("Compliance/
audit reporting polish"). The spec's own required test for this phase is a
"snapshot test of report output against a fixed architecture" —
test_render_audit_report_matches_committed_snapshot below is exactly that,
byte-for-byte against threat-model/audit-report-hardened.md, a real
committed artifact generated the same way report-hardened*.json are for
every other CLI in this project (by actually running the tool, not
hand-typed).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from compliance import load_mappings, control_ids_in_source
from threat_engine import Architecture, run_engine
from report_compliance import THREAT_ENGINE_PATH, audit_rows, render_audit_report

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "agent"
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"
REPORT_COMPLIANCE_PY = AGENT_DIR / "report_compliance.py"
BASELINE = THREAT_MODEL_DIR / "architecture-hardened.json"
SNAPSHOT_MD = THREAT_MODEL_DIR / "audit-report-hardened.md"


# ---------------------------------------------------------------------------
# Scoping — the whole reason this module exists rather than just walking
# every entry in framework-mappings.yaml.
# ---------------------------------------------------------------------------

def test_threat_engine_in_scope_controls_are_exactly_six():
    in_scope = control_ids_in_source(THREAT_ENGINE_PATH)
    assert in_scope == {"IAM-004", "NET-001", "DATA-002", "ZT-001", "NET-003", "LOG-001"}


def test_k8s_and_drift_controls_are_never_in_threat_engine_scope():
    """The specific false-PASS failure mode this module is designed to
    avoid: a control this report never even checked must never appear in
    its rows at all (not even as a PASS)."""
    in_scope = control_ids_in_source(THREAT_ENGINE_PATH)
    assert not any(c.startswith("K8S-") for c in in_scope)
    assert not any(c.startswith("DRIFT-") for c in in_scope)


# ---------------------------------------------------------------------------
# audit_rows() — unit tests
# ---------------------------------------------------------------------------

def test_audit_rows_marks_unviolated_control_as_pass():
    mappings = load_mappings()
    rows = audit_rows("test-arch", findings=[], mappings=mappings, in_scope_control_ids={"LOG-001"})
    assert len(rows) == 1
    assert rows[0]["status"] == "PASS"
    assert rows[0]["findings"] == []


def test_audit_rows_marks_violated_control_as_fail():
    arch = Architecture.from_file(BASELINE)
    findings = run_engine(arch)
    mappings = load_mappings()
    in_scope = control_ids_in_source(THREAT_ENGINE_PATH)
    rows = audit_rows(arch.name, findings, mappings, in_scope)
    by_id = {r["control_id"]: r for r in rows}
    assert by_id["IAM-004"]["status"] == "FAIL"
    assert by_id["NET-003"]["status"] == "FAIL"
    assert by_id["LOG-001"]["status"] == "PASS"
    assert by_id["DATA-002"]["status"] == "PASS"
    assert by_id["NET-001"]["status"] == "PASS"
    assert by_id["ZT-001"]["status"] == "PASS"
    assert len(rows) == 6


def test_audit_rows_is_sorted_by_control_id():
    mappings = load_mappings()
    rows = audit_rows("t", [], mappings, {"ZT-001", "IAM-004", "DATA-002"})
    assert [r["control_id"] for r in rows] == ["DATA-002", "IAM-004", "ZT-001"]


def test_audit_rows_groups_multiple_findings_under_the_same_control():
    """threat_engine.py's IAM-004 is reused by four rule_ids — if a run
    somehow produced two IAM-004 findings, both must show up under the
    one row, not spawn a second row for the same control."""
    from threat_engine import Finding, Severity, Stride

    def f(rule_id):
        return Finding(
            rule_id=rule_id, stride=Stride.ELEVATION_OF_PRIVILEGE, severity=Severity.MEDIUM,
            asset_ids=["x"], title=f"title for {rule_id}", threat="t", impact="i",
            control_id="IAM-004", policy="p", mitigation="m",
        )

    mappings = load_mappings()
    rows = audit_rows("t", [f("IAM-BROAD-01"), f("IAM-MISSING-01")], mappings, {"IAM-004"})
    assert len(rows) == 1
    assert rows[0]["status"] == "FAIL"
    assert len(rows[0]["findings"]) == 2


# ---------------------------------------------------------------------------
# render_audit_report() — determinism and the required label
# ---------------------------------------------------------------------------

def test_render_audit_report_is_deterministic_across_calls():
    """No wall-clock dependency anywhere in rendering — same inputs must
    produce byte-identical output every time, which is what makes the
    snapshot test below meaningful at all."""
    arch = Architecture.from_file(BASELINE)
    findings = run_engine(arch)
    mappings = load_mappings()
    in_scope = control_ids_in_source(THREAT_ENGINE_PATH)
    rows = audit_rows(arch.name, findings, mappings, in_scope)
    a = render_audit_report(arch.name, rows, total_mapped_controls=len(mappings), as_of="2026-09-18")
    b = render_audit_report(arch.name, rows, total_mapped_controls=len(mappings), as_of="2026-09-18")
    assert a == b


def test_render_audit_report_includes_reference_only_label():
    mappings = load_mappings()
    rows = audit_rows("t", [], mappings, {"LOG-001"})
    report = render_audit_report("t", rows, total_mapped_controls=len(mappings))
    assert "reference only, not a certification" in report


def test_render_audit_report_handles_missing_as_of():
    mappings = load_mappings()
    rows = audit_rows("t", [], mappings, {"LOG-001"})
    report = render_audit_report("t", rows, total_mapped_controls=len(mappings), as_of=None)
    assert "not specified" in report


def test_render_audit_report_says_none_failing_when_all_pass():
    mappings = load_mappings()
    rows = audit_rows("t", [], mappings, {"LOG-001", "NET-001"})
    report = render_audit_report("t", rows, total_mapped_controls=len(mappings))
    assert "None — every in-scope control passed this run." in report


# ---------------------------------------------------------------------------
# THE required test: snapshot test of report output against a fixed
# architecture.
# ---------------------------------------------------------------------------

def test_render_audit_report_matches_committed_snapshot():
    arch = Architecture.from_file(BASELINE)
    findings = run_engine(arch)
    mappings = load_mappings()
    in_scope = control_ids_in_source(THREAT_ENGINE_PATH)
    rows = audit_rows(arch.name, findings, mappings, in_scope)
    report = render_audit_report(arch.name, rows, total_mapped_controls=len(mappings), as_of="2026-09-18")

    expected = SNAPSHOT_MD.read_text()
    assert report == expected


# ---------------------------------------------------------------------------
# CLI-level
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPORT_COMPLIANCE_PY), *args],
        cwd=REPORT_COMPLIANCE_PY.parent,
        capture_output=True,
        text=True,
    )


def test_cli_always_exits_zero_even_with_failing_controls():
    """A report generator, not a gate — see the module's own docstring
    for why. The hardened baseline has 2 FAIL rows and this must still
    exit 0."""
    result = _run_cli(str(BASELINE), "--as-of", "2026-09-18")
    assert result.returncode == 0
    assert "FAIL: 2" in result.stdout


def test_cli_writes_report_to_file_when_requested(tmp_path):
    out_file = tmp_path / "report.md"
    result = _run_cli(str(BASELINE), "--as-of", "2026-09-18", "--out", str(out_file))
    assert result.returncode == 0
    assert out_file.exists()
    assert out_file.read_text() == SNAPSHOT_MD.read_text()


def test_cli_writes_json_report_when_requested(tmp_path):
    out_file = tmp_path / "report.json"
    result = _run_cli(str(BASELINE), "--as-of", "2026-09-18", "--json", str(out_file))
    assert result.returncode == 0
    payload = json.loads(out_file.read_text())
    assert payload["reference_only"] is True
    assert payload["controls_in_scope"] == 6
    assert payload["controls_total_mapped"] == 15
    assert len(payload["rows"]) == 6
    assert {r["control_id"] for r in payload["rows"] if r["status"] == "FAIL"} == {"IAM-004", "NET-003"}
