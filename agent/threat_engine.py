"""
Deterministic STRIDE threat engine.

This is the "deterministic security controls for enforcement" half of the
roadmap's core principle (LLM reasons and explains; rules decide). Every
finding this module produces comes from an explicit, inspectable rule — no
model call, no ambiguity, same input always gives the same output. That's
what makes it safe to gate a deployment on.

The LLM only gets involved afterward, in explain.py, to turn these findings
into prose a human can read quickly — it never gets to invent or suppress a
finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


class Stride(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class Finding:
    rule_id: str
    stride: Stride
    severity: Severity
    asset_ids: list[str]
    title: str
    threat: str
    impact: str
    control_id: str
    policy: str
    mitigation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.stride.value,
            "severity": str(self.severity),
            "assets": self.asset_ids,
            "finding": self.title,
            "threat": self.threat,
            "impact": self.impact,
            "control": self.control_id,
            "policy": self.policy,
            "mitigation": self.mitigation,
            "status": "FAIL",
        }


SENSITIVE_TYPES = {"database", "storage", "secret-store"}
HIGH_SENSITIVITY = {"high", "critical"}


class Architecture:
    """Thin wrapper around the architecture.json graph with convenience lookups."""

    def __init__(self, data: dict):
        self.name: str = data.get("name", "unnamed architecture")
        self.assets: dict[str, dict] = {a["id"]: a for a in data.get("assets", [])}
        self.trust_boundaries: list[dict] = data.get("trust_boundaries", [])
        self.flows: list[dict] = data.get("flows", [])
        self.identity_bindings: dict[str, dict] = {
            b["principal"]: b for b in data.get("identity_bindings", [])
        }
        self.logging: dict = data.get("logging", {"enabled": False})

    @classmethod
    def from_file(cls, path: str | Path) -> "Architecture":
        with open(path) as fh:
            return cls(json.load(fh))

    def boundary_of(self, asset_id: str) -> str | None:
        for tb in self.trust_boundaries:
            if asset_id in tb.get("contains", []):
                return tb["id"]
        return None

    def flows_into(self, asset_id: str) -> list[dict]:
        return [f for f in self.flows if f["to"] == asset_id]

    def flows_from(self, asset_id: str) -> list[dict]:
        return [f for f in self.flows if f["from"] == asset_id]


# --------------------------------------------------------------------------
# Rules — each takes the Architecture and yields zero or more Findings.
# --------------------------------------------------------------------------

def rule_broad_role_scope(arch: Architecture):
    for principal, binding in arch.identity_bindings.items():
        role, scope = binding.get("role"), binding.get("scope")
        if not role:
            continue
        if role in ("Contributor", "Owner") and scope == "subscription":
            yield Finding(
                rule_id="IAM-BROAD-01",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.CRITICAL,
                asset_ids=[principal],
                title=f"{principal} → subscription-wide {role} role",
                threat=(
                    f"A compromised {principal} container/process could use its "
                    f"{role} role to read, modify, or delete ANY resource in the "
                    f"subscription — not just the ones it actually needs."
                ),
                impact="Full subscription compromise from a single workload breach.",
                control_id="IAM-004",
                policy=f"{principal} may hold only a purpose-scoped custom role, never Owner/Contributor.",
                mitigation=(
                    f"Replace with a custom role scoped to exactly the resource(s) "
                    f"{principal} needs (see modules/iam's custom role_definition pattern)."
                ),
            )
        elif scope == "resource-group" and arch.assets.get(principal, {}).get("sensitivity") in HIGH_SENSITIVITY:
            yield Finding(
                rule_id="IAM-BROAD-02",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.MEDIUM,
                asset_ids=[principal],
                title=f"{principal} role scoped to resource group, not a specific resource",
                threat=(
                    f"{principal} can reach every resource in the group, not just "
                    "the one data store it's meant to talk to."
                ),
                impact="Broader blast radius than necessary if this identity is compromised.",
                control_id="IAM-004",
                policy=f"{principal}'s role should be scoped to the specific resource it needs.",
                mitigation="Narrow assignable_scopes to the specific resource ID once it exists.",
            )


def rule_missing_identity(arch: Architecture):
    for asset_id, asset in arch.assets.items():
        if asset.get("type") != "compute":
            continue
        touches_sensitive_data = any(
            arch.assets.get(f["to"], {}).get("type") in SENSITIVE_TYPES
            for f in arch.flows_from(asset_id)
        )
        if not touches_sensitive_data:
            continue
        binding = arch.identity_bindings.get(asset_id)
        if binding is None or not binding.get("role"):
            yield Finding(
                rule_id="IAM-MISSING-01",
                stride=Stride.SPOOFING,
                severity=Severity.MEDIUM,
                asset_ids=[asset_id],
                title=f"{asset_id} has no dedicated identity/role",
                threat=(
                    f"{asset_id} reaches sensitive data with no assigned identity. "
                    "In practice this gets worked around with a shared service "
                    "account, an ambient credential, or a manually-granted broad "
                    "role — all worse than a scoped one from the start."
                ),
                impact="No way to attribute or limit this workload's access; likely over-privileged in practice.",
                control_id="IAM-004",
                policy=f"{asset_id} must have its own purpose-scoped identity before going live.",
                mitigation=f"Create a dedicated app registration/service principal and custom role for {asset_id}, matching payment-service's pattern.",
            )


def rule_public_network_access(arch: Architecture):
    for asset_id, asset in arch.assets.items():
        if asset.get("type") not in SENSITIVE_TYPES:
            continue
        if asset.get("public_network_access"):
            yield Finding(
                rule_id="NET-PUBLIC-01",
                stride=Stride.INFO_DISCLOSURE,
                severity=Severity.CRITICAL,
                asset_ids=[asset_id],
                title=f"{asset_id} allows public network access",
                threat=f"{asset_id} is reachable directly from the internet, bypassing every network control.",
                impact="Direct exposure of customer data to internet-wide scanning and exploitation.",
                control_id="NET-001",
                policy=f"{asset_id} must disable public network access and be reachable only via private endpoint.",
                mitigation="Set public_network_access_enabled = false and add a private endpoint in the data subnet.",
            )
        if asset.get("allow_public_blob"):
            yield Finding(
                rule_id="NET-PUBLIC-02",
                stride=Stride.INFO_DISCLOSURE,
                severity=Severity.CRITICAL,
                asset_ids=[asset_id],
                title=f"{asset_id} allows public blob/container access",
                threat=f"Any container in {asset_id} could be individually set to public, exposing its contents with a URL.",
                impact="Silent data exposure — no network log will show it as unusual, it's 'working as configured'.",
                control_id="NET-001",
                policy=f"{asset_id} must set allow_nested_items_to_be_public = false.",
                mitigation="Disable public nested-item access at the account level so no container can opt in later.",
            )


def rule_unencrypted_at_rest(arch: Architecture):
    for asset_id, asset in arch.assets.items():
        if asset.get("type") not in SENSITIVE_TYPES:
            continue
        if asset.get("sensitivity") in HIGH_SENSITIVITY and asset.get("encrypted_at_rest") is False:
            yield Finding(
                rule_id="DATA-ENC-01",
                stride=Stride.TAMPERING,
                severity=Severity.HIGH,
                asset_ids=[asset_id],
                title=f"{asset_id} has no encryption at rest",
                threat=f"Data in {asset_id} is readable/tamperable by anyone with disk-level or backup access.",
                impact="Regulatory exposure (data protection requirements) plus tampering risk on backups/snapshots.",
                control_id="DATA-002",
                policy=f"{asset_id} must have infrastructure/double encryption enabled.",
                mitigation="Enable encryption at rest (see the require-encryption-at-rest Azure Policy in modules/policy).",
            )


def rule_flat_trust_boundary(arch: Architecture):
    for tb in arch.trust_boundaries:
        members = tb.get("contains", [])
        has_compute = any(arch.assets.get(m, {}).get("type") == "compute" for m in members)
        sensitive_members = [
            m for m in members
            if arch.assets.get(m, {}).get("type") in SENSITIVE_TYPES
            and arch.assets.get(m, {}).get("sensitivity") in HIGH_SENSITIVITY
        ]
        if has_compute and sensitive_members:
            yield Finding(
                rule_id="NET-SEGMENT-01",
                stride=Stride.ELEVATION_OF_PRIVILEGE,
                severity=Severity.CRITICAL,
                asset_ids=members,
                title=f"No network segmentation in trust boundary '{tb['id']}'",
                threat=(
                    "Compute workloads and sensitive data stores share one flat "
                    "network zone. A single compromised container can reach every "
                    "data store here directly — this is the exact 'payment service "
                    "→ unrestricted database access' pattern."
                ),
                impact="Lateral movement from any one compromised service to all sensitive data.",
                control_id="IAM-004",
                policy="Compute and sensitive-data tiers must sit in separate subnets with NSGs restricting cross-tier traffic to the minimum required.",
                mitigation="Split into dedicated subnets (see modules/network's gateway/aks/data/mgmt layout) with deny-by-default NSGs.",
            )


def rule_unauthenticated_flow(arch: Architecture):
    for f in arch.flows:
        if f.get("authenticated"):
            continue
        dest = arch.assets.get(f["to"], {})
        sensitivity = dest.get("sensitivity", "low")
        if sensitivity not in HIGH_SENSITIVITY:
            continue
        severity = Severity.HIGH if sensitivity == "critical" else Severity.MEDIUM
        yield Finding(
            rule_id="AUTHN-FLOW-01",
            stride=Stride.SPOOFING,
            severity=severity,
            asset_ids=[f["from"], f["to"]],
            title=f"No application-layer authentication: {f['from']} → {f['to']}",
            threat=(
                f"Network reachability from {f['from']} to {f['to']} exists, but "
                "there's no app-layer proof of identity (mTLS/OAuth/service-mesh "
                "token) — anything else that lands in the same subnet can impersonate the caller."
            ),
            impact="Any workload placed in the same network path can call this service as if it were the legitimate caller.",
            control_id="ZT-001",
            policy=f"Traffic into {f['to']} must be mutually authenticated, not just network-reachable.",
            mitigation="Introduce a service mesh (mTLS) or OAuth token validation between gateway and services (Phase 4 — Zero Trust).",
        )


def rule_no_waf(arch: Architecture):
    for asset_id, asset in arch.assets.items():
        if asset.get("type") == "gateway" and asset.get("internet_facing") and not asset.get("waf_enabled", False):
            yield Finding(
                rule_id="NET-WAF-01",
                stride=Stride.DENIAL_OF_SERVICE,
                severity=Severity.MEDIUM,
                asset_ids=[asset_id],
                title=f"{asset_id} has no WAF/rate-limiting in front of it",
                threat=f"{asset_id} is directly internet-facing with no layer-7 filtering — vulnerable to L7 DoS and common injection patterns hitting the app directly.",
                impact="Availability risk and a missing layer of defense against common web attacks.",
                control_id="NET-003",
                policy=f"{asset_id} must sit behind a WAF (Azure Application Gateway/Front Door WAF policy).",
                mitigation="Deploy Azure Front Door or Application Gateway with a WAF policy in front of the gateway subnet.",
            )


def rule_logging_disabled(arch: Architecture):
    if not arch.logging.get("enabled", False):
        yield Finding(
            rule_id="LOG-001",
            stride=Stride.REPUDIATION,
            severity=Severity.HIGH,
            asset_ids=list(arch.assets.keys()),
            title="No centralized audit logging configured",
            threat="Without diagnostic logs flowing to a central workspace, there's no way to reconstruct what happened after an incident, or prove who did what.",
            impact="Undetectable breaches and no forensic trail — also a compliance gap (most frameworks require audit logging).",
            control_id="LOG-001",
            policy="All resources must send diagnostic logs to a central Log Analytics workspace.",
            mitigation="Wire up diagnostic settings + a Log Analytics workspace (Phase 9 — SIEM + Detection, not yet built).",
        )


ALL_RULES = [
    rule_broad_role_scope,
    rule_missing_identity,
    rule_public_network_access,
    rule_unencrypted_at_rest,
    rule_flat_trust_boundary,
    rule_unauthenticated_flow,
    rule_no_waf,
    rule_logging_disabled,
]


def run_engine(arch: Architecture) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(arch))
    # Most severe first.
    findings.sort(key=lambda f: f.severity.value, reverse=True)
    return findings
