"""
Risk model — Phase 4 of the SentinelCloud v1 spec (§11, §16).

threat_engine.py's Severity is a fixed property of the *rule* — every
IAM-MISSING-01 finding is MEDIUM, whether the workload it's about touches
a `low`-sensitivity queue or a `critical`-sensitivity secrets store. That's
a real, documented gap (v1 spec §11): it can't express "the same missing
control is worse here than there" for rules that don't already branch on
sensitivity themselves (rule_unauthenticated_flow already does; most
others don't).

This module adds a second, independent dimension on top of the engine's
output — never a replacement for it. It does not touch threat_engine.py,
does not change what counts as a finding, and does not change
analyze.py's default BLOCKED/ALLOWED decision (SR-4/SR-4a stay intact:
this is purely descriptive extra context, opt-in via
`analyze.py --risk-model`). What it adds: for each finding, an `impact`
score that factors in the real sensitivity of the assets it touches, and
a `likelihood` score that factors in how structurally exposed those
assets are — combined into `risk_score` and a human-facing risk label.

The derivation is deliberately simple and fully spelled out below (v1
spec §11: "a documented function... published in the repo, not a black
box") rather than a opaque formula — the goal is to demonstrate that the
*reasoning* is sound and inspectable, not to produce actuarial precision
a synthetic project has no legitimate data to support.
"""

from __future__ import annotations

from dataclasses import dataclass

from threat_engine import Architecture, Finding

# --------------------------------------------------------------------------
# Impact — how bad this finding is, given what it actually touches.
# --------------------------------------------------------------------------

SENSITIVITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _touched_sensitivity_weights(finding: Finding, arch: Architecture) -> list[int]:
    """Every asset the finding names directly, PLUS every asset those
    assets flow into. Several rules (rule_missing_identity in particular)
    only record the workload itself in asset_ids, not the sensitive data
    it reaches — a missing identity on a workload that touches nothing
    sensitive and one that touches a critical secrets store both show up
    identically as `asset_ids=[workload]` otherwise. Following one hop of
    outgoing flow is what actually recovers "what data is this finding
    really about"."""
    weights = []
    for a in finding.asset_ids:
        asset = arch.assets.get(a, {})
        weights.append(SENSITIVITY_WEIGHT.get(asset.get("sensitivity", "low"), 1))
        for f in arch.flows_from(a):
            dest = arch.assets.get(f["to"], {})
            weights.append(SENSITIVITY_WEIGHT.get(dest.get("sensitivity", "low"), 1))
    return weights or [1]


def impact_score(finding: Finding, arch: Architecture) -> int:
    """1-4. At least as high as the rule's own severity (a CRITICAL
    finding is never downgraded because the asset happens to be low
    sensitivity), but elevated to match the most sensitive asset the
    finding actually touches — this is what lets two MEDIUM findings from
    the same rule end up with different real-world impact when one
    touches a `critical` secrets store and the other touches a `low`
    queue, which the fixed-severity engine alone can't express."""
    base = finding.severity.value
    sensitivity_ceiling = max(_touched_sensitivity_weights(finding, arch))
    return max(base, sensitivity_ceiling)


# --------------------------------------------------------------------------
# Likelihood — how structurally reachable the touched assets are.
# --------------------------------------------------------------------------


def _exposure(asset_id: str, arch: Architecture) -> int:
    """1-3. 3 if the asset is itself internet-facing, or reachable from an
    internet-facing asset via a flow with no application-layer
    authentication (as exposed as being on the edge itself); 2 if
    reachable from the edge but only via an authenticated hop; 1
    (internal, not directly edge-adjacent) otherwise."""
    asset = arch.assets.get(asset_id, {})
    if asset.get("internet_facing"):
        return 3
    for f in arch.flows_into(asset_id):
        src = arch.assets.get(f["from"], {})
        if src.get("internet_facing"):
            return 3 if not f.get("authenticated") else 2
    return 1


def likelihood_score(finding: Finding, arch: Architecture) -> int:
    """1-3. The highest exposure among every asset the finding touches —
    a finding is only as safe as its most exposed asset."""
    if not finding.asset_ids:
        return 1
    return max(_exposure(a, arch) for a in finding.asset_ids)


# --------------------------------------------------------------------------
# Combined risk score and label.
# --------------------------------------------------------------------------

# impact (1-4) x likelihood (1-3) -> 1-12. Thresholds below are the whole
# derivation — nothing else feeds the label. CRITICAL is reserved for the
# 10-12 band (impact and likelihood both at or near their ceiling) so it
# keeps meaning "never acceptable, even temporarily" (v1 spec §6, §21)
# rather than becoming the catch-all bucket for anything edge-adjacent —
# an earlier draft used a >=9 cutoff and almost every finding in the real
# AWS fixture landed on CRITICAL, which defeated the point of adding a
# second dimension at all. This split was tuned against that real output,
# not picked in the abstract.
RISK_LABEL_THRESHOLDS = (
    (10, "CRITICAL"),
    (6, "HIGH"),
    (3, "MEDIUM"),
    (0, "LOW"),
)


def risk_label(risk_score: int) -> str:
    for threshold, label in RISK_LABEL_THRESHOLDS:
        if risk_score >= threshold:
            return label
    return "LOW"  # unreachable given the 0 floor above; kept for clarity


@dataclass
class ScoredFinding:
    finding: Finding
    impact: int
    likelihood: int
    risk_score: int
    risk_label: str

    def to_dict(self) -> dict:
        d = self.finding.to_dict()
        d["risk_model"] = {
            "impact": self.impact,
            "likelihood": self.likelihood,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
        }
        return d


def score_finding(finding: Finding, arch: Architecture) -> ScoredFinding:
    impact = impact_score(finding, arch)
    likelihood = likelihood_score(finding, arch)
    score = impact * likelihood
    return ScoredFinding(
        finding=finding,
        impact=impact,
        likelihood=likelihood,
        risk_score=score,
        risk_label=risk_label(score),
    )


def score_findings(findings: list[Finding], arch: Architecture) -> list[ScoredFinding]:
    """Score every finding and return them sorted by risk_score, most
    urgent first (ties broken by the engine's own severity ordering,
    since the input list is already severity-sorted by run_engine)."""
    scored = [score_finding(f, arch) for f in findings]
    scored.sort(key=lambda s: s.risk_score, reverse=True)
    return scored
