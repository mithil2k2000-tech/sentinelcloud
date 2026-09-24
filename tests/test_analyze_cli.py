"""
Tests for analyze.py — the aggregation/decision logic (v1 spec §17.1, §17.4).

Two kinds of test here:
  1. Unit tests on aggregate() itself, including the fail-on boundary case
     (a finding's severity exactly equal to the threshold must block).
  2. Integration tests against the four real architecture fixtures,
     asserting the *specific* finding counts documented in the v1 spec
     (§10, §19) and the existing docs/phase1-*.md files — so a future
     change that silently loosens a rule and drops a finding is caught
     here, not just noticed by inspection.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from analyze import DEFAULT_FAIL_ON, aggregate
from threat_engine import Architecture, Finding, Severity, Stride, run_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "threat-model"
ANALYZE_PY = REPO_ROOT / "agent" / "analyze.py"


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="TEST-001",
        stride=Stride.SPOOFING,
        severity=severity,
        asset_ids=["x"],
        title="test finding",
        threat="t",
        impact="i",
        control_id="C-1",
        policy="p",
        mitigation="m",
    )


# ---------------------------------------------------------------------------
# aggregate() — unit tests
# ---------------------------------------------------------------------------

def test_aggregate_no_findings_is_allowed():
    summary = aggregate([])
    assert summary["overall_risk"] == "NONE"
    assert summary["deployment"] == "ALLOWED"


def test_aggregate_default_fail_on_is_high():
    assert DEFAULT_FAIL_ON == Severity.HIGH


@pytest.mark.parametrize(
    "finding_severity,fail_on,expected_deployment",
    [
        (Severity.HIGH, Severity.HIGH, "BLOCKED"),      # exactly at the threshold: must block
        (Severity.CRITICAL, Severity.HIGH, "BLOCKED"),  # above the threshold: must block
        (Severity.MEDIUM, Severity.HIGH, "ALLOWED"),    # below the threshold: must not block
        (Severity.HIGH, Severity.CRITICAL, "ALLOWED"),  # looser threshold: HIGH no longer blocks
        (Severity.CRITICAL, Severity.CRITICAL, "BLOCKED"),
    ],
)
def test_aggregate_fail_on_boundary(finding_severity, fail_on, expected_deployment):
    summary = aggregate([_finding(finding_severity)], fail_on=fail_on)
    assert summary["deployment"] == expected_deployment
    assert summary["fail_on"] == str(fail_on)


def test_aggregate_overall_risk_is_the_maximum_severity_present():
    summary = aggregate([_finding(Severity.LOW), _finding(Severity.MEDIUM)])
    assert summary["overall_risk"] == "MEDIUM"


def test_aggregate_counts_every_severity_bucket():
    findings = [_finding(Severity.HIGH), _finding(Severity.HIGH), _finding(Severity.LOW)]
    summary = aggregate(findings)
    assert summary["counts"]["HIGH"] == 2
    assert summary["counts"]["LOW"] == 1
    assert summary["counts"]["CRITICAL"] == 0


# ---------------------------------------------------------------------------
# Integration — real fixtures, real documented numbers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_name,expected_counts,expected_overall,expected_deployment",
    [
        (
            "architecture-proposed.json",
            {"LOW": 0, "MEDIUM": 4, "HIGH": 3, "CRITICAL": 6},
            "CRITICAL",
            "BLOCKED",
        ),
        (
            # Phase 9 closed RR-01 (no centralized logging) for all three
            # clouds by wiring real logging infrastructure (modules/logging)
            # and flipping architecture-hardened*.json's "logging.enabled"
            # to true — LOG-001 (HIGH) no longer fires anywhere. Azure had
            # no other HIGH finding, so it flipped from BLOCKED to ALLOWED
            # under the default (HIGH) threshold there; GCP/AWS still had
            # one real HIGH left (AUTHN-FLOW-01, api-gateway -> service
            # traffic with no application-layer auth) and stayed BLOCKED.
            #
            # Phase 4 (Zero Trust / mTLS) then closed that remaining HIGH
            # for GCP/AWS too: a mesh-wide STRICT Istio PeerAuthentication
            # (modules/mesh) makes every api-gateway -> service flow
            # mutually authenticated (flips flows[].authenticated to true
            # in the architecture JSON), and a scoped account-service IAM
            # identity (modules/iam + modules/secrets) closes the
            # remaining IAM-MISSING-01 findings for account-service on all
            # three clouds. Net effect: all three clouds are now ALLOWED
            # at the default HIGH threshold — only the two known,
            # already-tracked MEDIUM findings remain (payment-service IAM
            # scope on Azure; no WAF on api-gateway, everywhere). This is
            # the register's own intended trip-wire: a closed finding
            # changes these numbers, and the test is updated to match the
            # new reality, not silently left stale. See
            # threat-model/residual-risk-register.md (Closed) and
            # docs/phase4-zero-trust.md.
            "architecture-hardened.json",
            {"LOW": 0, "MEDIUM": 2, "HIGH": 0, "CRITICAL": 0},
            "MEDIUM",
            "ALLOWED",
        ),
        (
            "architecture-hardened-gcp.json",
            {"LOW": 0, "MEDIUM": 1, "HIGH": 0, "CRITICAL": 0},
            "MEDIUM",
            "ALLOWED",
        ),
        (
            "architecture-hardened-aws.json",
            {"LOW": 0, "MEDIUM": 1, "HIGH": 0, "CRITICAL": 0},
            "MEDIUM",
            "ALLOWED",
        ),
    ],
)
def test_known_architecture_produces_documented_findings(
    fixture_name, expected_counts, expected_overall, expected_deployment
):
    arch = Architecture.from_file(FIXTURES / fixture_name)
    findings = run_engine(arch)
    summary = aggregate(findings)

    assert summary["counts"] == expected_counts
    assert summary["overall_risk"] == expected_overall
    assert summary["deployment"] == expected_deployment


def test_hardened_architectures_have_strictly_fewer_criticals_than_proposed():
    """The concrete, numeric version of "hardening actually helped" —
    demonstration Scenario 1 in the v1 spec (§19), asserted as a test
    rather than only shown in a demo."""
    proposed = aggregate(run_engine(Architecture.from_file(FIXTURES / "architecture-proposed.json")))
    for hardened_file in [
        "architecture-hardened.json",
        "architecture-hardened-gcp.json",
        "architecture-hardened-aws.json",
    ]:
        hardened = aggregate(run_engine(Architecture.from_file(FIXTURES / hardened_file)))
        assert hardened["counts"]["CRITICAL"] < proposed["counts"]["CRITICAL"]


# ---------------------------------------------------------------------------
# CLI-level — exit codes, the actual gate behavior CI depends on
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ANALYZE_PY), *args],
        cwd=ANALYZE_PY.parent,
        capture_output=True,
        text=True,
    )


def test_cli_exit_code_1_when_blocked():
    result = _run_cli(str(FIXTURES / "architecture-proposed.json"), "--no-explain")
    assert result.returncode == 1
    assert "BLOCKED" in result.stdout


def test_cli_exit_code_0_when_fail_on_critical_and_no_criticals_present():
    result = _run_cli(
        str(FIXTURES / "architecture-hardened.json"), "--no-explain", "--fail-on", "CRITICAL"
    )
    assert result.returncode == 0
    assert "ALLOWED" in result.stdout


def test_cli_risk_model_flag_is_purely_additive(tmp_path):
    """--risk-model must not change the decision, exit code, or the base
    findings list — only add extra output/JSON content."""
    out_plain = tmp_path / "plain.json"
    out_risk = tmp_path / "risk.json"

    result_plain = _run_cli(
        str(FIXTURES / "architecture-hardened.json"), "--no-explain", "--json", str(out_plain)
    )
    result_risk = _run_cli(
        str(FIXTURES / "architecture-hardened.json"), "--no-explain", "--risk-model", "--json", str(out_risk)
    )

    assert result_plain.returncode == result_risk.returncode

    plain_payload = json.loads(out_plain.read_text())
    risk_payload = json.loads(out_risk.read_text())

    assert plain_payload["summary"] == risk_payload["summary"]
    assert plain_payload["findings"] == risk_payload["findings"]
    assert "risk_model" not in plain_payload
    assert "risk_model" in risk_payload
    assert len(risk_payload["risk_model"]) == len(risk_payload["findings"])
    assert "Risk model (impact x likelihood" in result_risk.stdout


def test_cli_writes_json_report_when_requested(tmp_path):
    out_file = tmp_path / "report.json"
    result = _run_cli(
        str(FIXTURES / "architecture-hardened.json"), "--no-explain", "--json", str(out_file)
    )
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["architecture"]
    assert "findings" in payload
    assert payload["summary"]["deployment"] in ("BLOCKED", "ALLOWED")
    assert result.returncode in (0, 1)
