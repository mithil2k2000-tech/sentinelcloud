"""
Tests for drift_scan.py — the CLI/aggregation logic, sibling to
test_analyze_cli.py, test_detect_cli.py, and test_k8s_scan_cli.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from drift_scan import DEFAULT_FAIL_ON, aggregate
from threat_engine import Finding, Severity, Stride

REPO_ROOT = Path(__file__).resolve().parent.parent
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"
DRIFT_SCAN_PY = REPO_ROOT / "agent" / "drift_scan.py"

BASELINE = THREAT_MODEL_DIR / "architecture-hardened.json"
DRIFTED = THREAT_MODEL_DIR / "architecture-drifted.json"


# ---------------------------------------------------------------------------
# aggregate() — unit tests
# ---------------------------------------------------------------------------

def test_aggregate_no_findings_is_allowed():
    summary = aggregate([])
    assert summary["overall_risk"] == "NONE"
    assert summary["deployment"] == "ALLOWED"


def test_aggregate_default_fail_on_is_high():
    assert DEFAULT_FAIL_ON == Severity.HIGH


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="DRIFT-TEST-01",
        stride=Stride.TAMPERING,
        severity=severity,
        asset_ids=["asset"],
        title="test drift finding",
        threat="t",
        impact="i",
        control_id="C-1",
        policy="p",
        mitigation="m",
    )


@pytest.mark.parametrize(
    "finding_severity,fail_on,expected_deployment",
    [
        (Severity.HIGH, Severity.HIGH, "BLOCKED"),
        (Severity.CRITICAL, Severity.HIGH, "BLOCKED"),
        (Severity.MEDIUM, Severity.HIGH, "ALLOWED"),
        (Severity.HIGH, Severity.CRITICAL, "ALLOWED"),
        (Severity.CRITICAL, Severity.CRITICAL, "BLOCKED"),
    ],
)
def test_aggregate_fail_on_boundary(finding_severity, fail_on, expected_deployment):
    summary = aggregate([_finding(finding_severity)], fail_on=fail_on)
    assert summary["deployment"] == expected_deployment
    assert summary["fail_on"] == str(fail_on)


# ---------------------------------------------------------------------------
# CLI-level — exit codes, the actual gate behavior a CI/manual run depends on
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DRIFT_SCAN_PY), *args],
        cwd=DRIFT_SCAN_PY.parent,
        capture_output=True,
        text=True,
    )


def test_cli_exit_code_1_when_drift_blocks():
    result = _run_cli(str(BASELINE), str(DRIFTED), "--no-explain")
    assert result.returncode == 1
    assert "BLOCKED" in result.stdout


def test_cli_exit_code_0_when_no_drift():
    result = _run_cli(str(BASELINE), str(BASELINE), "--no-explain")
    assert result.returncode == 0
    assert "ALLOWED" in result.stdout
    assert "No drift detected" in result.stdout


def test_cli_writes_json_report_when_requested(tmp_path):
    out_file = tmp_path / "report.json"
    result = _run_cli(str(BASELINE), str(DRIFTED), "--no-explain", "--json", str(out_file))
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["baseline"]
    assert payload["current"]
    assert "findings" in payload
    assert len(payload["findings"]) == 7
    assert payload["summary"]["deployment"] in ("BLOCKED", "ALLOWED")
    assert result.returncode == 1


def test_cli_fail_on_critical_still_blocks_on_the_two_critical_drift_findings():
    result = _run_cli(str(BASELINE), str(DRIFTED), "--no-explain", "--fail-on", "CRITICAL")
    assert result.returncode == 1
    assert "BLOCKED" in result.stdout
    assert "CRITICAL: 2" in result.stdout


def test_cli_compliance_flag_prints_reference_only_label_and_preserves_decision():
    base = _run_cli(str(BASELINE), str(DRIFTED), "--no-explain")
    with_flag = _run_cli(str(BASELINE), str(DRIFTED), "--no-explain", "--compliance")
    assert with_flag.returncode == base.returncode
    assert "reference only, not a certification" in with_flag.stdout
    assert "reference only, not a certification" not in base.stdout


def test_cli_compliance_json_includes_compliance_array_and_the_new_drift_control(tmp_path):
    out_file = tmp_path / "report.json"
    _run_cli(str(BASELINE), str(DRIFTED), "--no-explain", "--compliance", "--json", str(out_file))
    payload = json.loads(out_file.read_text())
    assert "compliance" in payload
    control_ids = {row["control_id"] for row in payload["compliance"]}
    assert "DRIFT-001" in control_ids  # the asset-added/removed findings
    assert all(row["mapped"] for row in payload["compliance"])  # every control_id this run emits is mapped
    assert all(row["reference_only"] is True for row in payload["compliance"])


def test_cli_risk_model_flag_is_purely_additive():
    base = _run_cli(str(BASELINE), str(DRIFTED), "--no-explain")
    with_flag = _run_cli(str(BASELINE), str(DRIFTED), "--no-explain", "--risk-model")
    assert with_flag.returncode == base.returncode
    assert "Risk model" in with_flag.stdout
    assert "Risk model" not in base.stdout


def test_cli_never_writes_to_its_input_files(tmp_path):
    """Directly exercises the 'never auto-remediate' guarantee in
    drift.py's/drift_scan.py's own docstrings: running the CLI must not
    modify either input file, under any flag combination."""
    baseline_copy = tmp_path / "baseline.json"
    current_copy = tmp_path / "current.json"
    baseline_copy.write_text(BASELINE.read_text())
    current_copy.write_text(DRIFTED.read_text())
    before_baseline = baseline_copy.read_text()
    before_current = current_copy.read_text()

    _run_cli(str(baseline_copy), str(current_copy), "--no-explain", "--compliance", "--risk-model")

    assert baseline_copy.read_text() == before_baseline
    assert current_copy.read_text() == before_current
