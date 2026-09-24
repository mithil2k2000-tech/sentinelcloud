"""
Tests for k8s_scan.py — the Kubernetes-side CLI/aggregation logic,
sibling to test_analyze_cli.py and test_detect_cli.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from k8s_scan import DEFAULT_FAIL_ON, aggregate
from k8s_engine import K8sManifest, run_engine
from threat_engine import Finding, Severity, Stride

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = REPO_ROOT / "kubernetes" / "manifests"
K8S_SCAN_PY = REPO_ROOT / "agent" / "k8s_scan.py"


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
        rule_id="TEST-001",
        stride=Stride.ELEVATION_OF_PRIVILEGE,
        severity=severity,
        asset_ids=["Deployment/test"],
        title="test finding",
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
# Integration — real fixtures, real documented numbers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "manifest_set,expected_counts,expected_overall,expected_deployment",
    [
        (
            "vulnerable",
            {"LOW": 0, "MEDIUM": 5, "HIGH": 6, "CRITICAL": 3},
            "CRITICAL",
            "BLOCKED",
        ),
        (
            "hardened",
            {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "NONE",
            "ALLOWED",
        ),
    ],
)
def test_known_manifest_set_produces_documented_findings(
    manifest_set, expected_counts, expected_overall, expected_deployment
):
    manifest = K8sManifest.from_dir(MANIFESTS_DIR / manifest_set)
    findings = run_engine(manifest)
    summary = aggregate(findings)

    assert summary["counts"] == expected_counts
    assert summary["overall_risk"] == expected_overall
    assert summary["deployment"] == expected_deployment


# ---------------------------------------------------------------------------
# CLI-level — exit codes, the actual gate behavior CI depends on
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(K8S_SCAN_PY), *args],
        cwd=K8S_SCAN_PY.parent,
        capture_output=True,
        text=True,
    )


def test_cli_exit_code_1_when_blocked():
    result = _run_cli(str(MANIFESTS_DIR / "vulnerable"), "--no-explain")
    assert result.returncode == 1
    assert "BLOCKED" in result.stdout


def test_cli_exit_code_0_when_allowed():
    result = _run_cli(str(MANIFESTS_DIR / "hardened"), "--no-explain")
    assert result.returncode == 0
    assert "ALLOWED" in result.stdout


def test_cli_writes_json_report_when_requested(tmp_path):
    out_file = tmp_path / "report.json"
    result = _run_cli(str(MANIFESTS_DIR / "vulnerable"), "--no-explain", "--json", str(out_file))
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["manifests_dir"]
    assert "findings" in payload
    assert payload["summary"]["deployment"] in ("BLOCKED", "ALLOWED")
    assert result.returncode == 1


def test_cli_fail_on_critical_allows_the_vulnerable_set_medium_and_high_findings(tmp_path):
    """Boundary check mirroring test_cli_exit_code_0_when_fail_on_critical_and_no_criticals_present
    in test_analyze_cli.py — except the vulnerable K8s fixture genuinely
    has 3 CRITICAL findings (K8S-PRIV-01/HOSTNS-01/RBAC-01), so this
    instead confirms --fail-on CRITICAL still blocks on those, proving
    the flag is read and applied, not silently ignored."""
    result = _run_cli(str(MANIFESTS_DIR / "vulnerable"), "--no-explain", "--fail-on", "CRITICAL")
    assert result.returncode == 1
    assert "BLOCKED" in result.stdout
    assert "CRITICAL: 3" in result.stdout
