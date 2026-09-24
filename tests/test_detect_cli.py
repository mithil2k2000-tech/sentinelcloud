"""
Tests for detect.py — the detection-side CLI/aggregation logic, sibling
to test_analyze_cli.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from detect import DEFAULT_FAIL_ON, aggregate_alerts
from detection_engine import Severity, run_detection

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "threat-model" / "logs"
DETECT_PY = REPO_ROOT / "agent" / "detect.py"
LOGGING_DIR = REPO_ROOT / "logging"
sys.path.insert(0, str(LOGGING_DIR))


# ---------------------------------------------------------------------------
# aggregate_alerts() — unit tests
# ---------------------------------------------------------------------------

def test_aggregate_no_alerts_is_clear():
    summary = aggregate_alerts([])
    assert summary["overall_risk"] == "NONE"
    assert summary["status"] == "CLEAR"


def test_aggregate_default_fail_on_is_high():
    assert DEFAULT_FAIL_ON == Severity.HIGH


def _alert(severity: Severity):
    from detection_engine import Alert
    from threat_engine import Stride

    return Alert(
        rule_id="TEST-001",
        stride=Stride.SPOOFING,
        severity=severity,
        event_ids=["e1"],
        title="test alert",
        behavior="b",
        impact="i",
        recommended_action="r",
    )


@pytest.mark.parametrize(
    "alert_severity,fail_on,expected_status",
    [
        (Severity.HIGH, Severity.HIGH, "INCIDENT"),
        (Severity.CRITICAL, Severity.HIGH, "INCIDENT"),
        (Severity.MEDIUM, Severity.HIGH, "CLEAR"),
        (Severity.HIGH, Severity.CRITICAL, "CLEAR"),
        (Severity.CRITICAL, Severity.CRITICAL, "INCIDENT"),
    ],
)
def test_aggregate_fail_on_boundary(alert_severity, fail_on, expected_status):
    summary = aggregate_alerts([_alert(alert_severity)], fail_on=fail_on)
    assert summary["status"] == expected_status
    assert summary["fail_on"] == str(fail_on)


# ---------------------------------------------------------------------------
# Integration — real fixtures
# ---------------------------------------------------------------------------

def test_normal_log_fixture_is_clear():
    from detection_engine import load_events

    alerts = run_detection(load_events(LOGS_DIR / "logs-normal.json"))
    summary = aggregate_alerts(alerts)
    assert summary["status"] == "CLEAR"


def test_multi_stage_incident_fixture_is_incident():
    from detection_engine import load_events

    alerts = run_detection(load_events(LOGS_DIR / "logs-multi-stage-incident.json"))
    summary = aggregate_alerts(alerts)
    assert summary["status"] == "INCIDENT"
    assert summary["overall_risk"] == "CRITICAL"


# ---------------------------------------------------------------------------
# CLI-level — exit codes
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT_PY), *args],
        cwd=DETECT_PY.parent,
        capture_output=True,
        text=True,
    )


def test_cli_exit_code_1_when_incident():
    result = _run_cli(str(LOGS_DIR / "logs-multi-stage-incident.json"))
    assert result.returncode == 1
    assert "INCIDENT" in result.stdout


def test_cli_exit_code_0_when_clear():
    result = _run_cli(str(LOGS_DIR / "logs-normal.json"))
    assert result.returncode == 0
    assert "CLEAR" in result.stdout


def test_cli_triage_flag_is_purely_additive(tmp_path):
    """--triage must not change the decision, exit code, or the base
    alerts list — only add extra output/JSON content. Mirrors
    test_cli_risk_model_flag_is_purely_additive in test_analyze_cli.py."""
    out_plain = tmp_path / "plain.json"
    out_triage = tmp_path / "triage.json"

    result_plain = _run_cli(str(LOGS_DIR / "logs-multi-stage-incident.json"), "--json", str(out_plain))
    result_triage = _run_cli(
        str(LOGS_DIR / "logs-multi-stage-incident.json"), "--triage", "--json", str(out_triage)
    )

    assert result_plain.returncode == result_triage.returncode

    plain_payload = json.loads(out_plain.read_text())
    triage_payload = json.loads(out_triage.read_text())

    assert plain_payload["summary"] == triage_payload["summary"]
    assert plain_payload["alerts"] == triage_payload["alerts"]


def test_cli_writes_json_report_when_requested(tmp_path):
    out_file = tmp_path / "report.json"
    result = _run_cli(str(LOGS_DIR / "logs-brute-force.json"), "--json", str(out_file))
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert payload["source"]
    assert "alerts" in payload
    assert payload["summary"]["status"] in ("INCIDENT", "CLEAR")
    assert result.returncode in (0, 1)


# ---------------------------------------------------------------------------
# --store — spec §16 table item 9 (centralized logging). Same
# purely-additive contract as --triage/--risk-model/--compliance: it must
# never change the decision, only capture events into the local log store
# on the side.
# ---------------------------------------------------------------------------

def test_cli_store_flag_is_purely_additive(tmp_path):
    db_path = tmp_path / "events.sqlite"
    out_plain = tmp_path / "plain.json"
    out_stored = tmp_path / "stored.json"

    result_plain = _run_cli(str(LOGS_DIR / "logs-multi-stage-incident.json"), "--json", str(out_plain))
    result_stored = _run_cli(
        str(LOGS_DIR / "logs-multi-stage-incident.json"),
        "--store", str(db_path), "--json", str(out_stored),
    )

    assert result_plain.returncode == result_stored.returncode

    plain_payload = json.loads(out_plain.read_text())
    stored_payload = json.loads(out_stored.read_text())
    assert plain_payload["summary"] == stored_payload["summary"]
    assert plain_payload["alerts"] == stored_payload["alerts"]


def test_cli_store_flag_actually_captures_events_queryable_afterward(tmp_path):
    from log_store import LogStore

    db_path = tmp_path / "events.sqlite"
    result = _run_cli(str(LOGS_DIR / "logs-multi-stage-incident.json"), "--store", str(db_path))
    assert result.returncode == 1  # this fixture is an INCIDENT — --store doesn't suppress that
    assert "captured 9 event(s)" in result.stdout

    store = LogStore(db_path)
    assert store.count() == 9
    rows = store.query(principal="k.doran", event_type="logging_disabled")
    assert len(rows) == 1
    assert rows[0]["target"] == "log-workspace"
    store.close()


def test_cli_without_store_flag_creates_no_file(tmp_path):
    db_path = tmp_path / "events.sqlite"
    _run_cli(str(LOGS_DIR / "logs-normal.json"))
    assert not db_path.exists()
