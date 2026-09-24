"""
Unit tests for the deterministic STRIDE engine (v1 spec §17.1).

Each rule gets a positive case (a minimal architecture crafted to trigger
it) and a negative case (a minimal architecture that should NOT trigger
it) — not just a run against the four full architecture files, which
would only prove "the rule fires on architectures we already know
trigger it" rather than "the rule's actual condition is what we think
it is". Fixtures are minimal dicts built directly against the schema in
threat-model/SCHEMA.md, not loaded from disk, so each test is
self-contained and its intent is visible in the test itself.
"""

from __future__ import annotations

from threat_engine import (
    Architecture,
    Severity,
    Stride,
    rule_broad_role_scope,
    rule_flat_trust_boundary,
    rule_logging_disabled,
    rule_missing_identity,
    rule_no_waf,
    rule_public_network_access,
    rule_unauthenticated_flow,
    rule_unencrypted_at_rest,
)


def arch(**overrides) -> Architecture:
    """A minimal, otherwise-empty architecture dict, with overrides merged
    in. Tests only need to specify the fields relevant to the rule under
    test — everything else defaults to empty/absent."""
    data = {
        "name": "test-fixture",
        "assets": [],
        "trust_boundaries": [],
        "flows": [],
        "identity_bindings": [],
        "logging": {"enabled": True},  # default to "not the logging finding" unless testing it
    }
    data.update(overrides)
    return Architecture(data)


# ---------------------------------------------------------------------------
# rule_broad_role_scope — IAM-BROAD-01 (subscription-wide Owner/Contributor)
#                          and IAM-BROAD-02 (resource-group scope on a
#                          high/critical-sensitivity principal)
# ---------------------------------------------------------------------------

def test_broad_role_subscription_owner_fires_critical():
    a = arch(
        assets=[{"id": "svc", "type": "compute", "sensitivity": "high"}],
        identity_bindings=[{"principal": "svc", "role": "Owner", "scope": "subscription"}],
    )
    findings = list(rule_broad_role_scope(a))
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-BROAD-01"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].stride == Stride.ELEVATION_OF_PRIVILEGE


def test_broad_role_resource_group_on_high_sensitivity_fires_medium():
    a = arch(
        assets=[{"id": "svc", "type": "compute", "sensitivity": "high"}],
        identity_bindings=[{"principal": "svc", "role": "custom-role", "scope": "resource-group"}],
    )
    findings = list(rule_broad_role_scope(a))
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-BROAD-02"
    assert findings[0].severity == Severity.MEDIUM


def test_broad_role_scoped_to_resource_does_not_fire():
    a = arch(
        assets=[{"id": "svc", "type": "compute", "sensitivity": "high"}],
        identity_bindings=[{"principal": "svc", "role": "custom-role", "scope": "resource"}],
    )
    assert list(rule_broad_role_scope(a)) == []


def test_broad_role_with_no_role_does_not_fire():
    a = arch(
        assets=[{"id": "svc", "type": "compute", "sensitivity": "high"}],
        identity_bindings=[{"principal": "svc", "role": None, "scope": None}],
    )
    assert list(rule_broad_role_scope(a)) == []


# ---------------------------------------------------------------------------
# rule_missing_identity — IAM-MISSING-01
# ---------------------------------------------------------------------------

def test_missing_identity_fires_for_compute_touching_sensitive_data():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "db", "type": "database"},
        ],
        flows=[{"from": "svc", "to": "db", "authenticated": True}],
        identity_bindings=[],  # no binding at all for svc
    )
    findings = list(rule_missing_identity(a))
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-MISSING-01"
    assert findings[0].asset_ids == ["svc"]


def test_missing_identity_does_not_fire_when_bound():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "db", "type": "database"},
        ],
        flows=[{"from": "svc", "to": "db", "authenticated": True}],
        identity_bindings=[{"principal": "svc", "role": "custom-role", "scope": "resource"}],
    )
    assert list(rule_missing_identity(a)) == []


def test_missing_identity_does_not_fire_when_not_touching_sensitive_data():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "other-svc", "type": "compute"},
        ],
        flows=[{"from": "svc", "to": "other-svc", "authenticated": True}],
        identity_bindings=[],
    )
    assert list(rule_missing_identity(a)) == []


# ---------------------------------------------------------------------------
# rule_public_network_access — NET-PUBLIC-01 / NET-PUBLIC-02
# ---------------------------------------------------------------------------

def test_public_network_access_fires_critical():
    a = arch(assets=[{"id": "store", "type": "storage", "public_network_access": True}])
    findings = list(rule_public_network_access(a))
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-PUBLIC-01"
    assert findings[0].severity == Severity.CRITICAL


def test_public_blob_access_fires_critical():
    a = arch(assets=[{"id": "store", "type": "storage", "allow_public_blob": True}])
    findings = list(rule_public_network_access(a))
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-PUBLIC-02"


def test_private_storage_does_not_fire():
    a = arch(assets=[{
        "id": "store", "type": "storage",
        "public_network_access": False, "allow_public_blob": False,
    }])
    assert list(rule_public_network_access(a)) == []


# ---------------------------------------------------------------------------
# rule_unencrypted_at_rest — DATA-ENC-01
# ---------------------------------------------------------------------------

def test_unencrypted_high_sensitivity_storage_fires_high():
    a = arch(assets=[{
        "id": "store", "type": "storage", "sensitivity": "critical",
        "encrypted_at_rest": False,
    }])
    findings = list(rule_unencrypted_at_rest(a))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_encrypted_storage_does_not_fire():
    a = arch(assets=[{
        "id": "store", "type": "storage", "sensitivity": "critical",
        "encrypted_at_rest": True,
    }])
    assert list(rule_unencrypted_at_rest(a)) == []


def test_low_sensitivity_unencrypted_does_not_fire():
    # The rule only cares about high/critical sensitivity data — a low
    # sensitivity asset left unencrypted is a real but lower-priority gap
    # this rule deliberately does not flag (documented behavior, not a bug).
    a = arch(assets=[{
        "id": "store", "type": "storage", "sensitivity": "low",
        "encrypted_at_rest": False,
    }])
    assert list(rule_unencrypted_at_rest(a)) == []


# ---------------------------------------------------------------------------
# rule_flat_trust_boundary — NET-SEGMENT-01
# ---------------------------------------------------------------------------

def test_compute_and_sensitive_data_in_same_boundary_fires():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "db", "type": "database", "sensitivity": "critical"},
        ],
        trust_boundaries=[{"id": "flat", "contains": ["svc", "db"]}],
    )
    findings = list(rule_flat_trust_boundary(a))
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-SEGMENT-01"
    assert findings[0].severity == Severity.CRITICAL


def test_compute_and_sensitive_data_in_separate_boundaries_does_not_fire():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "db", "type": "database", "sensitivity": "critical"},
        ],
        trust_boundaries=[
            {"id": "compute-tier", "contains": ["svc"]},
            {"id": "data-tier", "contains": ["db"]},
        ],
    )
    assert list(rule_flat_trust_boundary(a)) == []


# ---------------------------------------------------------------------------
# rule_unauthenticated_flow — AUTHN-FLOW-01
# ---------------------------------------------------------------------------

def test_unauthenticated_flow_into_critical_asset_fires_high():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "secrets", "type": "secret-store", "sensitivity": "critical"},
        ],
        flows=[{"from": "svc", "to": "secrets", "authenticated": False}],
    )
    findings = list(rule_unauthenticated_flow(a))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_unauthenticated_flow_into_high_asset_fires_medium():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "db", "type": "database", "sensitivity": "high"},
        ],
        flows=[{"from": "svc", "to": "db", "authenticated": False}],
    )
    findings = list(rule_unauthenticated_flow(a))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_authenticated_flow_does_not_fire():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "secrets", "type": "secret-store", "sensitivity": "critical"},
        ],
        flows=[{"from": "svc", "to": "secrets", "authenticated": True}],
    )
    assert list(rule_unauthenticated_flow(a)) == []


def test_unauthenticated_flow_into_low_sensitivity_asset_does_not_fire():
    a = arch(
        assets=[
            {"id": "svc", "type": "compute"},
            {"id": "queue", "type": "queue", "sensitivity": "low"},
        ],
        flows=[{"from": "svc", "to": "queue", "authenticated": False}],
    )
    assert list(rule_unauthenticated_flow(a)) == []


# ---------------------------------------------------------------------------
# rule_no_waf — NET-WAF-01
# ---------------------------------------------------------------------------

def test_internet_facing_gateway_without_waf_fires():
    a = arch(assets=[{
        "id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": False,
    }])
    findings = list(rule_no_waf(a))
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-WAF-01"


def test_internet_facing_gateway_with_waf_does_not_fire():
    a = arch(assets=[{
        "id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": True,
    }])
    assert list(rule_no_waf(a)) == []


def test_internal_gateway_without_waf_does_not_fire():
    a = arch(assets=[{
        "id": "gw", "type": "gateway", "internet_facing": False, "waf_enabled": False,
    }])
    assert list(rule_no_waf(a)) == []


# ---------------------------------------------------------------------------
# rule_logging_disabled — LOG-001
# ---------------------------------------------------------------------------

def test_logging_disabled_fires():
    a = arch(logging={"enabled": False})
    findings = list(rule_logging_disabled(a))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_logging_enabled_does_not_fire():
    a = arch(logging={"enabled": True})
    assert list(rule_logging_disabled(a)) == []


# ---------------------------------------------------------------------------
# run_engine — ordering guarantee (most severe first), used by every
# downstream report/CLI, so it's tested once at this level rather than
# re-verified in every consumer.
# ---------------------------------------------------------------------------

def test_run_engine_sorts_most_severe_first():
    from threat_engine import run_engine

    a = arch(
        assets=[
            {"id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": False},  # MEDIUM
            {"id": "store", "type": "storage", "public_network_access": True},  # CRITICAL
        ],
        logging={"enabled": False},  # HIGH
    )
    findings = run_engine(a)
    severities = [f.severity.value for f in findings]
    assert severities == sorted(severities, reverse=True)
    assert findings[0].severity == Severity.CRITICAL
