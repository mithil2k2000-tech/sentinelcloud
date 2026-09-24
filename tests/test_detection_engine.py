"""
Tests for the Phase 9 detection engine (v1 spec §16, §17.1).

Same two-tier shape as test_threat_engine.py: small synthetic event lists
that isolate exactly one rule's trigger condition (positive and negative),
plus integration tests against the real fixtures in threat-model/logs/
asserting the exact alert counts documented in threat-model/logs/SCHEMA.md
— so a future change that silently loosens a rule is caught here, not
just noticed by inspection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detection_engine import (
    LogEvent,
    load_events,
    rule_audit_logging_tampered,
    rule_brute_force,
    rule_data_exfiltration_volume,
    rule_impossible_travel,
    rule_privilege_escalation_after_hours,
    run_detection,
)
from threat_engine import Severity

LOGS_DIR = Path(__file__).resolve().parent.parent / "threat-model" / "logs"


def _event(**kwargs) -> LogEvent:
    defaults = dict(
        event_id="evt-x",
        timestamp="2026-09-16T12:00:00Z",  # daytime UTC, not after-hours
        event_type="auth",
        principal="p",
        source_ip="10.0.0.1",
        target="api-gateway",
        outcome="success",
    )
    defaults.update(kwargs)
    return LogEvent(**defaults)


# ---------------------------------------------------------------------------
# rule_brute_force — DET-BRUTEFORCE-01
# ---------------------------------------------------------------------------

def test_brute_force_fires_at_threshold_failures():
    events = [
        _event(event_id=f"e{i}", timestamp=f"2026-09-16T12:00:0{i}Z", outcome="failure")
        for i in range(5)
    ]
    alerts = list(rule_brute_force(events))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH  # no success afterward


def test_brute_force_does_not_fire_below_threshold():
    events = [
        _event(event_id=f"e{i}", timestamp=f"2026-09-16T12:00:0{i}Z", outcome="failure")
        for i in range(4)
    ]
    assert list(rule_brute_force(events)) == []


def test_brute_force_escalates_to_critical_when_a_success_follows():
    events = [
        _event(event_id=f"e{i}", timestamp=f"2026-09-16T12:00:0{i}Z", outcome="failure")
        for i in range(5)
    ] + [_event(event_id="e-success", timestamp="2026-09-16T12:00:10Z", outcome="success")]
    alerts = list(rule_brute_force(events))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_brute_force_ignores_non_auth_events():
    events = [
        _event(event_id=f"e{i}", timestamp=f"2026-09-16T12:00:0{i}Z", event_type="data_transfer", outcome="failure")
        for i in range(6)
    ]
    assert list(rule_brute_force(events)) == []


def test_brute_force_does_not_conflate_different_source_ips():
    """5 failures split across two different source IPs for the same
    principal must NOT fire — each IP alone is below threshold. Proves
    the rule keys on (principal, source_ip), not principal alone."""
    events = [
        _event(event_id=f"e{i}", timestamp=f"2026-09-16T12:00:0{i}Z", source_ip="10.0.0.1", outcome="failure")
        for i in range(3)
    ] + [
        _event(event_id=f"f{i}", timestamp=f"2026-09-16T12:00:1{i}Z", source_ip="10.0.0.2", outcome="failure")
        for i in range(2)
    ]
    assert list(rule_brute_force(events)) == []


# ---------------------------------------------------------------------------
# rule_impossible_travel — DET-TRAVEL-01
# ---------------------------------------------------------------------------

def test_impossible_travel_fires_for_two_regions_within_window():
    events = [
        _event(event_id="e1", timestamp="2026-09-16T08:00:00Z", region="uk-london"),
        _event(event_id="e2", timestamp="2026-09-16T08:20:00Z", region="sg-singapore"),
    ]
    alerts = list(rule_impossible_travel(events))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_impossible_travel_does_not_fire_for_same_region():
    events = [
        _event(event_id="e1", timestamp="2026-09-16T08:00:00Z", region="uk-london"),
        _event(event_id="e2", timestamp="2026-09-16T08:20:00Z", region="uk-london"),
    ]
    assert list(rule_impossible_travel(events)) == []


def test_impossible_travel_does_not_fire_outside_window():
    """Two different regions, but far enough apart in time that ordinary
    travel could actually explain it — must not fire."""
    events = [
        _event(event_id="e1", timestamp="2026-09-16T08:00:00Z", region="uk-london"),
        _event(event_id="e2", timestamp="2026-09-16T20:00:00Z", region="sg-singapore"),
    ]
    assert list(rule_impossible_travel(events)) == []


def test_impossible_travel_ignores_failed_logins():
    events = [
        _event(event_id="e1", timestamp="2026-09-16T08:00:00Z", region="uk-london", outcome="failure"),
        _event(event_id="e2", timestamp="2026-09-16T08:20:00Z", region="sg-singapore", outcome="failure"),
    ]
    assert list(rule_impossible_travel(events)) == []


# ---------------------------------------------------------------------------
# rule_privilege_escalation_after_hours — DET-PRIVESC-01
# ---------------------------------------------------------------------------

def test_privesc_fires_after_hours_on_sensitive_target():
    events = [_event(event_type="iam_change", timestamp="2026-09-16T23:00:00Z", target="secrets-manager-role")]
    alerts = list(rule_privilege_escalation_after_hours(events))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_privesc_does_not_fire_during_business_hours():
    events = [_event(event_type="iam_change", timestamp="2026-09-16T11:00:00Z", target="secrets-manager-role")]
    assert list(rule_privilege_escalation_after_hours(events)) == []


def test_privesc_does_not_fire_for_non_sensitive_target_even_after_hours():
    events = [_event(event_type="iam_change", timestamp="2026-09-16T23:00:00Z", target="notification-service-role")]
    assert list(rule_privilege_escalation_after_hours(events)) == []


def test_privesc_does_not_fire_for_failed_change():
    events = [_event(event_type="iam_change", timestamp="2026-09-16T23:00:00Z", target="secrets-manager-role", outcome="failure")]
    assert list(rule_privilege_escalation_after_hours(events)) == []


# ---------------------------------------------------------------------------
# rule_data_exfiltration_volume — DET-EXFIL-01
# ---------------------------------------------------------------------------

def test_exfiltration_fires_above_threshold():
    events = [_event(event_type="data_transfer", bytes_transferred=600_000_000)]
    alerts = list(rule_data_exfiltration_volume(events))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_exfiltration_does_not_fire_below_threshold():
    events = [_event(event_type="data_transfer", bytes_transferred=4_000_000)]
    assert list(rule_data_exfiltration_volume(events)) == []


def test_exfiltration_ignores_failed_transfers():
    events = [_event(event_type="data_transfer", bytes_transferred=600_000_000, outcome="failure")]
    assert list(rule_data_exfiltration_volume(events)) == []


# ---------------------------------------------------------------------------
# rule_audit_logging_tampered — DET-LOGTAMPER-01
# ---------------------------------------------------------------------------

def test_log_tampering_fires_for_logging_disabled():
    events = [_event(event_type="logging_disabled", target="log-workspace")]
    alerts = list(rule_audit_logging_tampered(events))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_log_tampering_fires_for_log_deleted():
    events = [_event(event_type="log_deleted", target="log-workspace")]
    alerts = list(rule_audit_logging_tampered(events))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_log_tampering_ignores_unrelated_events():
    events = [_event(event_type="auth")]
    assert list(rule_audit_logging_tampered(events)) == []


# ---------------------------------------------------------------------------
# Integration — real fixtures, real documented numbers (threat-model/logs/SCHEMA.md)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_name,expected_rule_ids,expected_overall",
    [
        ("logs-normal.json", [], "NONE"),
        ("logs-brute-force.json", ["DET-BRUTEFORCE-01"], "HIGH"),
        ("logs-credential-stuffing-success.json", ["DET-BRUTEFORCE-01"], "CRITICAL"),
        ("logs-impossible-travel.json", ["DET-TRAVEL-01"], "CRITICAL"),
        ("logs-privilege-escalation.json", ["DET-PRIVESC-01"], "HIGH"),
        ("logs-data-exfiltration.json", ["DET-EXFIL-01"], "CRITICAL"),
        ("logs-log-tampering.json", ["DET-LOGTAMPER-01"], "CRITICAL"),
        (
            "logs-multi-stage-incident.json",
            ["DET-BRUTEFORCE-01", "DET-EXFIL-01", "DET-LOGTAMPER-01", "DET-PRIVESC-01"],
            "CRITICAL",
        ),
    ],
)
def test_known_log_fixture_produces_documented_alerts(fixture_name, expected_rule_ids, expected_overall):
    events = load_events(LOGS_DIR / fixture_name)
    alerts = run_detection(events)
    assert sorted(a.rule_id for a in alerts) == sorted(expected_rule_ids)
    if not alerts:
        overall = "NONE"
    else:
        overall = max((a.severity for a in alerts), key=lambda s: s.value).name
    assert overall == expected_overall


def test_multi_stage_incident_alerts_all_share_the_same_principal_and_source():
    """The correlation-value point of the combined demo fixture: every
    alert traces back to the same attacker, across four different
    detection rules — not four unrelated events."""
    events = load_events(LOGS_DIR / "logs-multi-stage-incident.json")
    alerts = run_detection(events)
    assert len(alerts) == 4
    involved_event_ids = {eid for a in alerts for eid in a.event_ids}
    involved_events = [e for e in events if e.event_id in involved_event_ids]
    assert {e.principal for e in involved_events} == {"k.doran"}
    assert {e.source_ip for e in involved_events} == {"185.220.101.4"}


def test_run_detection_sorts_by_severity_descending():
    events = load_events(LOGS_DIR / "logs-multi-stage-incident.json")
    alerts = run_detection(events)
    severities = [a.severity.value for a in alerts]
    assert severities == sorted(severities, reverse=True)
