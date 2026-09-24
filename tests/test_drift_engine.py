"""
Per-rule positive/negative tests for agent/drift.py (Phase 7 / FR-9),
mirroring test_threat_engine.py's and test_k8s_engine.py's structure:
small synthetic Architecture fixtures per rule, plus a real-fixture
integration test with documented, verified-by-actual-run counts.
"""

from __future__ import annotations

from pathlib import Path

from threat_engine import Architecture, Severity
from drift import (
    ALL_RULES,
    rule_asset_added,
    rule_asset_removed,
    rule_encryption_drift,
    rule_flow_authentication_drift,
    rule_identity_binding_drift,
    rule_logging_disabled_drift,
    rule_public_access_drift,
    rule_waf_drift,
    run_engine,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _arch(**overrides) -> Architecture:
    base = {
        "name": "test",
        "assets": [],
        "trust_boundaries": [],
        "flows": [],
        "identity_bindings": [],
        "logging": {"enabled": True, "destination": "log-workspace"},
    }
    base.update(overrides)
    return Architecture(base)


# ---------------------------------------------------------------------------
# rule_public_access_drift
# ---------------------------------------------------------------------------

def test_public_access_drift_fires_when_baseline_closed_and_current_open():
    baseline = _arch(assets=[{"id": "db", "type": "storage", "sensitivity": "critical", "public_network_access": False}])
    current = _arch(assets=[{"id": "db", "type": "storage", "sensitivity": "critical", "public_network_access": True}])
    findings = list(rule_public_access_drift(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].control_id == "NET-001"


def test_public_access_drift_does_not_fire_when_unchanged():
    baseline = _arch(assets=[{"id": "db", "type": "storage", "sensitivity": "critical", "public_network_access": True}])
    current = _arch(assets=[{"id": "db", "type": "storage", "sensitivity": "critical", "public_network_access": True}])
    assert list(rule_public_access_drift(baseline, current)) == []


def test_public_access_drift_does_not_fire_when_baseline_already_open():
    """Only a genuine baseline->open TRANSITION is drift — an asset that
    was already publicly exposed in the baseline isn't newly drifted just
    because it's still exposed (that's threat_engine.py's NET-PUBLIC-01's
    job, a design-time question, not this rule's)."""
    baseline = _arch(assets=[{"id": "db", "type": "storage", "sensitivity": "critical", "public_network_access": True}])
    current = _arch(assets=[{"id": "db", "type": "storage", "sensitivity": "critical", "public_network_access": True}])
    assert list(rule_public_access_drift(baseline, current)) == []


def test_public_access_drift_ignores_non_sensitive_types():
    baseline = _arch(assets=[{"id": "vm", "type": "compute", "sensitivity": "critical", "public_network_access": False}])
    current = _arch(assets=[{"id": "vm", "type": "compute", "sensitivity": "critical", "public_network_access": True}])
    assert list(rule_public_access_drift(baseline, current)) == []


# ---------------------------------------------------------------------------
# rule_encryption_drift
# ---------------------------------------------------------------------------

def test_encryption_drift_fires_when_disabled():
    baseline = _arch(assets=[{"id": "db", "type": "database", "sensitivity": "high", "encrypted_at_rest": True}])
    current = _arch(assets=[{"id": "db", "type": "database", "sensitivity": "high", "encrypted_at_rest": False}])
    findings = list(rule_encryption_drift(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].control_id == "DATA-002"


def test_encryption_drift_does_not_fire_for_low_sensitivity():
    baseline = _arch(assets=[{"id": "db", "type": "database", "sensitivity": "low", "encrypted_at_rest": True}])
    current = _arch(assets=[{"id": "db", "type": "database", "sensitivity": "low", "encrypted_at_rest": False}])
    assert list(rule_encryption_drift(baseline, current)) == []


# ---------------------------------------------------------------------------
# rule_logging_disabled_drift
# ---------------------------------------------------------------------------

def test_logging_drift_fires_when_disabled():
    baseline = _arch(logging={"enabled": True})
    current = _arch(logging={"enabled": False})
    findings = list(rule_logging_disabled_drift(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].control_id == "LOG-001"


def test_logging_drift_does_not_fire_when_stays_enabled():
    baseline = _arch(logging={"enabled": True})
    current = _arch(logging={"enabled": True})
    assert list(rule_logging_disabled_drift(baseline, current)) == []


def test_logging_drift_does_not_fire_when_already_disabled():
    baseline = _arch(logging={"enabled": False})
    current = _arch(logging={"enabled": False})
    assert list(rule_logging_disabled_drift(baseline, current)) == []


# ---------------------------------------------------------------------------
# rule_identity_binding_drift
# ---------------------------------------------------------------------------

def test_identity_binding_drift_fires_critical_when_broadened_to_owner():
    baseline = _arch(identity_bindings=[{"principal": "svc", "role": "custom-role", "scope": "resource"}])
    current = _arch(identity_bindings=[{"principal": "svc", "role": "Owner", "scope": "subscription"}])
    findings = list(rule_identity_binding_drift(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].control_id == "IAM-004"


def test_identity_binding_drift_fires_medium_for_a_narrower_change():
    baseline = _arch(identity_bindings=[{"principal": "svc", "role": "custom-role-a", "scope": "resource"}])
    current = _arch(identity_bindings=[{"principal": "svc", "role": "custom-role-b", "scope": "resource"}])
    findings = list(rule_identity_binding_drift(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_identity_binding_drift_does_not_fire_when_unchanged():
    baseline = _arch(identity_bindings=[{"principal": "svc", "role": "custom-role", "scope": "resource"}])
    current = _arch(identity_bindings=[{"principal": "svc", "role": "custom-role", "scope": "resource"}])
    assert list(rule_identity_binding_drift(baseline, current)) == []


# ---------------------------------------------------------------------------
# rule_flow_authentication_drift
# ---------------------------------------------------------------------------

def test_flow_authn_drift_fires_when_authentication_drops():
    assets = [{"id": "gw", "type": "gateway", "sensitivity": "medium"}, {"id": "svc", "type": "compute", "sensitivity": "critical"}]
    baseline = _arch(assets=assets, flows=[{"from": "gw", "to": "svc", "authenticated": True}])
    current = _arch(assets=assets, flows=[{"from": "gw", "to": "svc", "authenticated": False}])
    findings = list(rule_flow_authentication_drift(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH  # critical-sensitivity destination
    assert findings[0].control_id == "ZT-001"


def test_flow_authn_drift_does_not_fire_for_low_sensitivity_destination():
    assets = [{"id": "gw", "type": "gateway", "sensitivity": "medium"}, {"id": "svc", "type": "compute", "sensitivity": "low"}]
    baseline = _arch(assets=assets, flows=[{"from": "gw", "to": "svc", "authenticated": True}])
    current = _arch(assets=assets, flows=[{"from": "gw", "to": "svc", "authenticated": False}])
    assert list(rule_flow_authentication_drift(baseline, current)) == []


def test_flow_authn_drift_ignores_a_flow_removed_entirely():
    """A flow that disappears entirely is a structural change (covered by
    an asset-removal, if the destination asset is also gone), not an
    authentication regression on a flow that still exists."""
    assets = [{"id": "gw", "type": "gateway", "sensitivity": "medium"}, {"id": "svc", "type": "compute", "sensitivity": "critical"}]
    baseline = _arch(assets=assets, flows=[{"from": "gw", "to": "svc", "authenticated": True}])
    current = _arch(assets=assets, flows=[])
    assert list(rule_flow_authentication_drift(baseline, current)) == []


# ---------------------------------------------------------------------------
# rule_waf_drift
# ---------------------------------------------------------------------------

def test_waf_drift_fires_when_disabled():
    baseline = _arch(assets=[{"id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": True}])
    current = _arch(assets=[{"id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": False}])
    findings = list(rule_waf_drift(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].control_id == "NET-003"


def test_waf_drift_does_not_fire_when_already_disabled():
    baseline = _arch(assets=[{"id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": False}])
    current = _arch(assets=[{"id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": False}])
    assert list(rule_waf_drift(baseline, current)) == []


# ---------------------------------------------------------------------------
# rule_asset_added / rule_asset_removed — the "no error means no drift"
# anti-pattern rules.
# ---------------------------------------------------------------------------

def test_asset_added_fires_high_when_internet_facing():
    baseline = _arch(assets=[])
    current = _arch(assets=[{"id": "shadow-api", "type": "api", "internet_facing": True}])
    findings = list(rule_asset_added(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].control_id == "DRIFT-001"


def test_asset_added_fires_medium_when_not_sensitive_or_exposed():
    baseline = _arch(assets=[])
    current = _arch(assets=[{"id": "internal-tool", "type": "compute"}])
    findings = list(rule_asset_added(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_asset_added_does_not_fire_for_a_preexisting_asset():
    baseline = _arch(assets=[{"id": "svc", "type": "compute"}])
    current = _arch(assets=[{"id": "svc", "type": "compute"}])
    assert list(rule_asset_added(baseline, current)) == []


def test_asset_removed_fires_medium():
    baseline = _arch(assets=[{"id": "svc", "type": "compute"}])
    current = _arch(assets=[])
    findings = list(rule_asset_removed(baseline, current))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].control_id == "DRIFT-001"


def test_asset_removed_does_not_fire_for_a_still_present_asset():
    baseline = _arch(assets=[{"id": "svc", "type": "compute"}])
    current = _arch(assets=[{"id": "svc", "type": "compute"}])
    assert list(rule_asset_removed(baseline, current)) == []


def test_identical_snapshots_produce_no_findings_from_any_rule():
    """The exact 'no drift' half of the spec's own required test — every
    rule, not just one, against genuinely identical input."""
    arch_dict = {
        "name": "identical",
        "assets": [
            {"id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": True, "sensitivity": "medium"},
            {"id": "db", "type": "database", "sensitivity": "critical", "encrypted_at_rest": True, "public_network_access": False},
        ],
        "flows": [{"from": "gw", "to": "db", "authenticated": True}],
        "identity_bindings": [{"principal": "gw", "role": "custom", "scope": "resource"}],
        "logging": {"enabled": True},
    }
    baseline = Architecture(dict(arch_dict))
    current = Architecture(dict(arch_dict))
    assert run_engine(baseline, current) == []


# ---------------------------------------------------------------------------
# Integration — real fixtures, real documented numbers (the spec's own
# required test: "two differing architecture-JSON snapshots produce a
# drift finding, and identical snapshots produce none").
# ---------------------------------------------------------------------------

def test_real_drifted_fixture_produces_documented_findings():
    baseline = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-hardened.json")
    current = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-drifted.json")
    findings = run_engine(baseline, current)
    assert len(findings) == 7
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    assert counts[Severity.CRITICAL] == 2
    assert counts[Severity.HIGH] == 3
    assert counts[Severity.MEDIUM] == 2
    assert counts[Severity.LOW] == 0
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {
        "DRIFT-PUBLIC-NET-01",
        "DRIFT-DATA-ENC-01",
        "DRIFT-LOG-01",
        "DRIFT-IAM-01",
        "DRIFT-ZT-01",
        "DRIFT-ASSET-ADDED-01",
        "DRIFT-ASSET-REMOVED-01",
    }


def test_real_identical_snapshots_produce_zero_findings():
    baseline = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-hardened.json")
    current = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-hardened.json")
    assert run_engine(baseline, current) == []


def test_run_engine_sorts_most_severe_first():
    baseline = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-hardened.json")
    current = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-drifted.json")
    findings = run_engine(baseline, current)
    severities = [f.severity.value for f in findings]
    assert severities == sorted(severities, reverse=True)


def test_all_rules_list_matches_every_rule_actually_defined():
    assert len(ALL_RULES) == 8
