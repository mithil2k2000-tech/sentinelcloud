"""
Tests for the Phase 4 risk model (v1 spec §11, §17.1).

The central claim risk_model.py exists to prove: two findings from the
SAME rule, at the SAME fixed Severity, can end up with different real
risk once the sensitivity of what they actually touch is factored in —
something threat_engine.py's Severity enum alone can't express for rules
that don't already branch on sensitivity (rule_missing_identity is a real
example of exactly this gap).
"""

from __future__ import annotations

from threat_engine import Architecture, run_engine
from risk_model import (
    impact_score,
    likelihood_score,
    risk_label,
    score_finding,
    score_findings,
)

FIXTURE = (
    __import__("pathlib").Path(__file__).resolve().parent.parent
    / "threat-model" / "architecture-hardened-aws.json"
)


def _arch_with_two_unbound_services(second_sensitivity: str):
    """A minimal architecture with two compute services, neither with an
    identity binding, one touching a `critical` store and the other
    touching a store of `second_sensitivity` — isolates exactly the
    variable this test cares about."""
    return Architecture({
        "name": "differentiation-fixture",
        "assets": [
            {"id": "account-service", "type": "compute"},
            {"id": "notification-service", "type": "compute"},
            {"id": "secrets", "type": "secret-store", "sensitivity": "critical"},
            {"id": "reporting-db", "type": "database", "sensitivity": second_sensitivity},
        ],
        "trust_boundaries": [],
        "flows": [
            {"from": "account-service", "to": "secrets", "authenticated": True},
            {"from": "notification-service", "to": "reporting-db", "authenticated": True},
        ],
        "identity_bindings": [],
        "logging": {"enabled": True},
    })


# ---------------------------------------------------------------------------
# The headline differentiation the v1 spec calls for (§10, §11).
# ---------------------------------------------------------------------------

def test_account_vs_notification_service_same_severity_different_risk():
    """Both services trigger the SAME rule (IAM-MISSING-01) at the SAME
    fixed MEDIUM severity — threat_engine.py has no way to tell them
    apart. risk_model.py must: account-service (touches `critical` data)
    gets strictly higher impact and risk_score than notification-service
    (touches merely `low` data), even though their raw Severity is
    identical."""
    arch = _arch_with_two_unbound_services(second_sensitivity="low")
    findings = run_engine(arch)

    by_asset = {f.asset_ids[0]: f for f in findings if f.rule_id == "IAM-MISSING-01"}
    assert set(by_asset.keys()) == {"account-service", "notification-service"}
    # Confirm the premise: the engine itself does NOT differentiate them.
    assert by_asset["account-service"].severity == by_asset["notification-service"].severity

    account_scored = score_finding(by_asset["account-service"], arch)
    notification_scored = score_finding(by_asset["notification-service"], arch)

    assert account_scored.impact > notification_scored.impact
    assert account_scored.risk_score > notification_scored.risk_score


def test_differentiation_collapses_when_both_touch_equally_sensitive_data():
    """Sanity check on the above: if both services touch equally
    sensitive data, the risk model should NOT invent a difference that
    isn't there — impact should be equal."""
    arch = _arch_with_two_unbound_services(second_sensitivity="critical")
    findings = run_engine(arch)
    by_asset = {f.asset_ids[0]: f for f in findings if f.rule_id == "IAM-MISSING-01"}

    account_scored = score_finding(by_asset["account-service"], arch)
    notification_scored = score_finding(by_asset["notification-service"], arch)
    assert account_scored.impact == notification_scored.impact


# ---------------------------------------------------------------------------
# impact_score
# ---------------------------------------------------------------------------

def test_impact_never_drops_below_the_rules_own_severity():
    """A CRITICAL finding stays CRITICAL-equivalent impact even if it
    happens to touch a low-sensitivity asset — sensitivity can only pull
    impact UP, never down, below what the rule already said."""
    arch = Architecture({
        "name": "t", "assets": [{"id": "x", "type": "storage", "sensitivity": "low", "public_network_access": True}],
        "trust_boundaries": [], "flows": [], "identity_bindings": [], "logging": {"enabled": True},
    })
    findings = run_engine(arch)
    critical_finding = next(f for f in findings if f.rule_id == "NET-PUBLIC-01")
    assert critical_finding.severity.value == 4  # CRITICAL
    assert impact_score(critical_finding, arch) == 4


# ---------------------------------------------------------------------------
# likelihood_score
# ---------------------------------------------------------------------------

def test_likelihood_high_for_internet_facing_asset():
    arch = Architecture({
        "name": "t",
        "assets": [{"id": "gw", "type": "gateway", "internet_facing": True, "waf_enabled": False}],
        "trust_boundaries": [], "flows": [], "identity_bindings": [], "logging": {"enabled": True},
    })
    findings = run_engine(arch)
    waf_finding = next(f for f in findings if f.rule_id == "NET-WAF-01")
    assert likelihood_score(waf_finding, arch) == 3


def test_likelihood_high_for_unauthenticated_one_hop_from_edge():
    arch = Architecture({
        "name": "t",
        "assets": [
            {"id": "gw", "type": "gateway", "internet_facing": True},
            {"id": "svc", "type": "compute", "sensitivity": "critical"},
        ],
        "trust_boundaries": [],
        "flows": [
            {"from": "gw", "to": "svc", "authenticated": False},
        ],
        "identity_bindings": [{"principal": "svc", "role": "r", "scope": "resource"}],
        "logging": {"enabled": True},
    })
    findings = run_engine(arch)
    unauth_finding = next(f for f in findings if f.rule_id == "AUTHN-FLOW-01" and "gw" in f.asset_ids)
    assert likelihood_score(unauth_finding, arch) == 3


def test_likelihood_lower_for_internal_only_asset():
    arch = Architecture({
        "name": "t",
        "assets": [
            {"id": "svc", "type": "compute"},
            {"id": "secrets", "type": "secret-store", "sensitivity": "critical"},
        ],
        "trust_boundaries": [],
        "flows": [{"from": "svc", "to": "secrets", "authenticated": False}],
        "identity_bindings": [],
        "logging": {"enabled": True},
    })
    findings = run_engine(arch)
    unauth_finding = next(f for f in findings if f.rule_id == "AUTHN-FLOW-01")
    # Neither svc nor secrets is internet-facing or edge-adjacent.
    assert likelihood_score(unauth_finding, arch) == 1


# ---------------------------------------------------------------------------
# risk_label thresholds
# ---------------------------------------------------------------------------

def test_risk_label_boundaries():
    assert risk_label(12) == "CRITICAL"
    assert risk_label(10) == "CRITICAL"
    assert risk_label(9) == "HIGH"
    assert risk_label(6) == "HIGH"
    assert risk_label(5) == "MEDIUM"
    assert risk_label(3) == "MEDIUM"
    assert risk_label(2) == "LOW"
    assert risk_label(0) == "LOW"


# ---------------------------------------------------------------------------
# score_findings — ordering, and grounding against a real fixture.
# ---------------------------------------------------------------------------

def test_score_findings_sorts_by_risk_score_descending():
    arch = _arch_with_two_unbound_services(second_sensitivity="low")
    findings = run_engine(arch)
    scored = score_findings(findings, arch)
    scores = [s.risk_score for s in scored]
    assert scores == sorted(scores, reverse=True)


def test_score_findings_ranks_authn_flow_to_critical_asset_high():
    """The property this test used to ground against real AWS data (see
    the note on the test below): an unauthenticated flow into a
    `critical`-sensitivity asset (AUTHN-FLOW-01, HIGH) should rank at or
    near the top of the risk-scored list, ahead of a lower-sensitivity
    finding like a missing WAF (NET-WAF-01, MEDIUM). Phase 4 (Zero Trust)
    fixed the real flow this was originally grounded on, so the property
    itself is now checked with a small synthetic fixture instead — the
    same pattern already used above for the account-service vs.
    notification-service differentiation check."""
    arch = Architecture({
        "name": "authn-flow-severity-fixture",
        "assets": [
            {"id": "api-gateway", "type": "gateway", "internet_facing": True, "waf_enabled": False},
            {"id": "account-service", "type": "compute"},
            {"id": "secrets", "type": "secret-store", "sensitivity": "critical"},
        ],
        "trust_boundaries": [],
        "flows": [
            # api-gateway -> account-service unauthenticated too, so
            # likelihood_score's exposure chain (internet-facing ->
            # reachable-via-unauthenticated-hop) is modeled the same way
            # it was on the real, pre-Phase-4 AWS/GCP fixtures this test
            # used to run against — otherwise account-service reads as
            # "internal" here and the comparison isn't representative.
            {"from": "api-gateway", "to": "account-service", "authenticated": False},
            {"from": "account-service", "to": "secrets", "authenticated": False},
        ],
        "identity_bindings": [],
        "logging": {"enabled": True},
    })
    findings = run_engine(arch)
    scored = score_findings(findings, arch)

    assert len(scored) == len(findings)
    top_rule_ids = {s.finding.rule_id for s in scored[: max(1, len(scored) // 2)]}
    assert "AUTHN-FLOW-01" in top_rule_ids


def test_score_findings_against_real_aws_architecture():
    """Grounding check against real, non-synthetic data.

    Before Phase 4 (Zero Trust), this fixture had an unauthenticated
    account-service -> secrets-manager flow into a `critical` asset,
    which fired AUTHN-FLOW-01 at HIGH — the scenario the test above now
    covers synthetically. Phase 4 made that flow mutually authenticated
    (mesh-wide STRICT Istio PeerAuthentication, modules/mesh) and gave
    account-service its own scoped IAM identity, so AUTHN-FLOW-01 no
    longer fires here at all: this is a real, intended consequence of
    the fix, not a test left stale. The only finding remaining on this
    fixture is the already-tracked NET-WAF-01 (MEDIUM) — see
    threat-model/residual-risk-register.md and docs/phase4-zero-trust.md.
    """
    arch = Architecture.from_file(FIXTURE)
    findings = run_engine(arch)
    scored = score_findings(findings, arch)

    assert len(scored) == len(findings)
    rule_ids = {s.finding.rule_id for s in scored}
    assert rule_ids == {"NET-WAF-01"}
    assert "AUTHN-FLOW-01" not in rule_ids
