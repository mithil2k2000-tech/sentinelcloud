#!/usr/bin/env python3
"""
drift.py — FR-9 in the SentinelCloud v1 spec (§16 development table, item
7): "Detect when a cloud resource's actual configuration (as read back from
the provider, or from a stored last-known-good Terraform state) no longer
matches the security baseline it was provisioned with, and raise it through
the same finding/report pipeline as FR-3."

SIMULATED MODE ONLY, on purpose (per §14's "SIMULATED" cost-discipline
category — see docs/phase1-azure.md and friends for the same stance applied
to Terraform). This module never talks to a live cloud API. It diffs two
architecture.json snapshots — a `baseline` (the last-known-good state a
resource was provisioned with) and a `current` (what a real read-back
would show) — exactly as the spec's own text plans for: "a 'simulated
drift' mode... that diffs two architecture-JSON snapshots instead of
comparing against a live API, so the capability can be demonstrated and
tested without a real account either." A real-cloud mode (reading actual
resource state via each provider's SDK) is a legitimate future extension,
not built here — see this module's "Honest limitations" in
docs/drift-detection.md.

Reuses `Finding`/`Severity`/`Stride`/`Architecture` from threat_engine.py
directly, per FR-9's own instruction to raise drift "through the same
finding/report pipeline as FR-3" — no new dataclass, same reasoning
k8s_engine.py already documented for reusing `Finding` over inventing a
fourth shape (a drift finding is still a claim about a *design-time*
security property being violated, just discovered by comparison instead of
by inspecting one snapshot). Several drift rules deliberately reuse an
EXISTING control_id (NET-001, DATA-002, LOG-001, IAM-004, ZT-001, NET-003)
rather than minting a new one per rule — the underlying control a drifted
resource now violates is the same control threat_engine.py would have
flagged had the resource been provisioned that way from the start, so the
compliance-mapping file built for FR-8 (policy/framework-mappings.yaml)
already covers these findings with zero new entries. Two rules that have
no equivalent design-time control (an asset appearing or disappearing
between snapshots) use a new "DRIFT-001" control_id, added to
policy/framework-mappings.yaml specifically for this phase.

STRIDE category: every rule here uses Stride.TAMPERING. This is a
deliberate simplification, not an oversight — a drift finding is
fundamentally a claim about *unauthorized or undetected modification of
configuration state*, which is what Tampering means, regardless of what
category the eventual consequence would fall under once exploited (e.g. a
public-access drift finding is about the config having been changed
without going through the proper process; the fact that the CONSEQUENCE of
that change is information disclosure is a separate, secondary concern —
threat_engine.py's own NET-PUBLIC-01 already covers "this resource is
publicly exposed" as a static property; DRIFT-NET-PUBLIC-01 covers "this
resource's exposure changed since it was last known-good," a genuinely
different claim, about the act of change itself).

TWO ANTI-PATTERNS THIS MODULE DELIBERATELY AVOIDS — both named directly in
the spec's own risks/anti-patterns table, right next to FR-9's own
description:

1. "Auto-remediate without human approval." This module NEVER writes to
   infrastructure, calls a cloud SDK, or modifies either input file. It
   only reads two JSON snapshots and returns Finding objects — reporting
   only, same as every other engine in this project. Nothing here is
   capable of "fixing" a drifted resource; a human (or a separate,
   explicitly-approved remediation step this project does not build) has
   to act on the report.
2. "Assume 'no error' means 'no drift'." A structural diff that only walks
   `current`'s keys would silently miss an asset, flow, or identity
   binding that existed in `baseline` and is simply gone in `current` —
   that would read as "no error, nothing to report" when a resource's
   disappearance is itself one of the most important things to flag (see
   rule_asset_removed below). Every comparison in this module walks the
   UNION of both snapshots' keys, never just one side, specifically to
   avoid this failure mode. Malformed/unreadable input still raises
   (Architecture.from_file's existing behavior, unchanged) rather than
   being caught and swallowed into an empty finding list.
"""

from __future__ import annotations

from threat_engine import Architecture, Finding, Severity, Stride

HIGH_SENSITIVITY = {"high", "critical"}
SENSITIVE_TYPES = {"database", "storage", "secret-store"}


def rule_public_access_drift(baseline: Architecture, current: Architecture):
    """A sensitive asset's public-exposure flags changed from closed (or
    absent, treated as closed) to open. Mirrors threat_engine.py's
    NET-PUBLIC-01/02 in what it checks, but the claim here is "this
    changed since baseline," not "this is currently wrong.\""""
    all_ids = set(baseline.assets) | set(current.assets)
    for asset_id in sorted(all_ids):
        base = baseline.assets.get(asset_id, {})
        cur = current.assets.get(asset_id, {})
        if cur.get("type") not in SENSITIVE_TYPES:
            continue
        for field, rule_suffix, human in (
            ("public_network_access", "PUBLIC-NET", "public network access"),
            ("allow_public_blob", "PUBLIC-BLOB", "public blob/container access"),
        ):
            was = bool(base.get(field, False))
            now = bool(cur.get(field, False))
            if not was and now:
                yield Finding(
                    rule_id=f"DRIFT-{rule_suffix}-01",
                    stride=Stride.TAMPERING,
                    severity=Severity.CRITICAL,
                    asset_ids=[asset_id],
                    title=f"{asset_id} drifted to allow {human} (baseline had it disabled)",
                    threat=(
                        f"{asset_id}'s live configuration now allows {human}, but the "
                        "last-known-good baseline it was provisioned with had this "
                        "disabled — the resource was changed outside of, or after, "
                        "the change that was actually reviewed."
                    ),
                    impact="Direct exposure of a sensitive resource, introduced silently after go-live rather than caught at design time.",
                    control_id="NET-001",
                    policy=f"{asset_id} must not regain public exposure after being provisioned without it.",
                    mitigation=f"Investigate who/what changed {asset_id}'s network exposure and revert to the baseline configuration; consider Azure Policy/Org Policy/AWS Config in enforce (not audit-only) mode to block this class of change going forward.",
                )


def rule_encryption_drift(baseline: Architecture, current: Architecture):
    """A high/critical-sensitivity asset that had encryption-at-rest
    enabled in the baseline no longer has it in the current snapshot."""
    all_ids = set(baseline.assets) | set(current.assets)
    for asset_id in sorted(all_ids):
        base = baseline.assets.get(asset_id, {})
        cur = current.assets.get(asset_id, {})
        if cur.get("type") not in SENSITIVE_TYPES:
            continue
        if cur.get("sensitivity") not in HIGH_SENSITIVITY:
            continue
        was = base.get("encrypted_at_rest") is True
        now = cur.get("encrypted_at_rest") is True
        if was and not now:
            yield Finding(
                rule_id="DRIFT-DATA-ENC-01",
                stride=Stride.TAMPERING,
                severity=Severity.HIGH,
                asset_ids=[asset_id],
                title=f"{asset_id} drifted to no longer have encryption at rest",
                threat=f"{asset_id} was provisioned with encryption at rest enabled; the current snapshot shows it disabled.",
                impact="Data at rest is now readable/tamperable by anyone with disk-level or backup access, without that ever having been reviewed as an intended change.",
                control_id="DATA-002",
                policy=f"{asset_id} must keep encryption at rest enabled at all times, not just at provisioning.",
                mitigation="Re-enable encryption at rest and investigate how/why it was disabled outside the reviewed baseline.",
            )


def rule_logging_disabled_drift(baseline: Architecture, current: Architecture):
    """Centralized logging was on in the baseline and is off now — the
    single most dangerous kind of drift, because it can hide every other
    drift that happens after it (a point this doc calls out explicitly)."""
    was = baseline.logging.get("enabled", False)
    now = current.logging.get("enabled", False)
    if was and not now:
        yield Finding(
            rule_id="DRIFT-LOG-01",
            stride=Stride.TAMPERING,
            severity=Severity.HIGH,
            asset_ids=list(current.assets.keys()),
            title="Centralized audit logging drifted from enabled to disabled",
            threat="Logging was on in the reviewed baseline and is off in the current snapshot — anything that changes after this point (including further drift) may go completely unrecorded.",
            impact="Total loss of forensic trail from this point forward; every other drift or intrusion after this one becomes harder or impossible to reconstruct.",
            control_id="LOG-001",
            policy="Centralized audit logging must remain enabled at all times once provisioned; disabling it is itself a reportable security event, not routine configuration.",
            mitigation="Re-enable diagnostic settings/audit logging immediately and treat this as a potential incident, not just a misconfiguration — investigate who disabled it and when.",
        )


def rule_identity_binding_drift(baseline: Architecture, current: Architecture):
    """An identity binding's role or scope changed since baseline. Any
    change is flagged (identity is exactly the kind of thing that should
    never change silently); broadening to a subscription/project/account-
    wide scope or an Owner/Contributor-class role is CRITICAL, any other
    change is MEDIUM."""
    all_principals = set(baseline.identity_bindings) | set(current.identity_bindings)
    BROAD_ROLES = {"Owner", "Contributor"}
    BROAD_SCOPES = {"subscription", "project", "account"}
    for principal in sorted(all_principals):
        base = baseline.identity_bindings.get(principal, {})
        cur = current.identity_bindings.get(principal, {})
        base_role, base_scope = base.get("role"), base.get("scope")
        cur_role, cur_scope = cur.get("role"), cur.get("scope")
        if base_role == cur_role and base_scope == cur_scope:
            continue
        broadened = cur_role in BROAD_ROLES or cur_scope in BROAD_SCOPES
        yield Finding(
            rule_id="DRIFT-IAM-01",
            stride=Stride.TAMPERING,
            severity=Severity.CRITICAL if broadened else Severity.MEDIUM,
            asset_ids=[principal],
            title=f"{principal}'s identity binding drifted from baseline",
            threat=(
                f"{principal} was provisioned with role={base_role!r} scope={base_scope!r}; "
                f"the current snapshot shows role={cur_role!r} scope={cur_scope!r}."
            ),
            impact="An identity's actual permissions no longer match what was reviewed — the exact kind of change that should go through an access review, not happen silently.",
            control_id="IAM-004",
            policy=f"{principal}'s role/scope must not change outside a reviewed access-control change.",
            mitigation=f"Confirm whether this was an approved change; if not, revert {principal}'s binding to the baseline role/scope and investigate how it changed.",
        )


def rule_flow_authentication_drift(baseline: Architecture, current: Architecture):
    """A flow into a high/critical-sensitivity asset that was
    authenticated in the baseline is unauthenticated now — mTLS/OAuth
    silently disabled or bypassed somewhere in the path."""
    base_flows = {(f["from"], f["to"]): f for f in baseline.flows}
    cur_flows = {(f["from"], f["to"]): f for f in current.flows}
    for key in sorted(set(base_flows) | set(cur_flows)):
        base_f = base_flows.get(key)
        cur_f = cur_flows.get(key)
        if base_f is None or cur_f is None:
            continue  # flow added/removed entirely — a structural change, not an authn regression on an existing flow
        dest = current.assets.get(key[1], baseline.assets.get(key[1], {}))
        if dest.get("sensitivity") not in HIGH_SENSITIVITY:
            continue
        was = bool(base_f.get("authenticated"))
        now = bool(cur_f.get("authenticated"))
        if was and not now:
            severity = Severity.HIGH if dest.get("sensitivity") == "critical" else Severity.MEDIUM
            yield Finding(
                rule_id="DRIFT-ZT-01",
                stride=Stride.TAMPERING,
                severity=severity,
                asset_ids=[key[0], key[1]],
                title=f"Authentication drifted off on {key[0]} → {key[1]}",
                threat=f"{key[0]} → {key[1]} was mutually authenticated in the baseline; the current snapshot shows it is not.",
                impact="Zero Trust protection on this path has silently regressed — anything reachable on the network path can now impersonate the legitimate caller.",
                control_id="ZT-001",
                policy=f"Traffic into {key[1]} must remain mutually authenticated at all times, not just at provisioning.",
                mitigation="Investigate the mesh/gateway configuration on this path for a dropped PeerAuthentication policy or misconfigured sidecar, and restore mutual authentication.",
            )


def rule_waf_drift(baseline: Architecture, current: Architecture):
    """An internet-facing gateway that had a WAF enabled in the baseline
    no longer does."""
    all_ids = set(baseline.assets) | set(current.assets)
    for asset_id in sorted(all_ids):
        base = baseline.assets.get(asset_id, {})
        cur = current.assets.get(asset_id, {})
        if cur.get("type") != "gateway" or not cur.get("internet_facing"):
            continue
        was = bool(base.get("waf_enabled", False))
        now = bool(cur.get("waf_enabled", False))
        if was and not now:
            yield Finding(
                rule_id="DRIFT-WAF-01",
                stride=Stride.TAMPERING,
                severity=Severity.MEDIUM,
                asset_ids=[asset_id],
                title=f"{asset_id} drifted to no longer have a WAF in front of it",
                threat=f"{asset_id} had a WAF/rate-limiting policy in the baseline; the current snapshot shows none.",
                impact="Loss of layer-7 filtering on an internet-facing gateway, introduced after the design was reviewed.",
                control_id="NET-003",
                policy=f"{asset_id} must keep a WAF policy attached at all times once provisioned.",
                mitigation="Re-attach the WAF/Front Door policy and investigate how it was detached.",
            )


def rule_asset_added(baseline: Architecture, current: Architecture):
    """An asset exists in the current snapshot with no baseline
    counterpart at all — a resource that was never part of the reviewed
    design. This is the rule that specifically prevents the "no error
    means no drift" anti-pattern from hiding an unauthorized addition."""
    added = set(current.assets) - set(baseline.assets)
    for asset_id in sorted(added):
        asset = current.assets[asset_id]
        sensitive_or_exposed = (
            asset.get("type") in SENSITIVE_TYPES or asset.get("internet_facing")
        )
        yield Finding(
            rule_id="DRIFT-ASSET-ADDED-01",
            stride=Stride.TAMPERING,
            severity=Severity.HIGH if sensitive_or_exposed else Severity.MEDIUM,
            asset_ids=[asset_id],
            title=f"{asset_id} appears in the current snapshot but not in the reviewed baseline",
            threat=f"{asset_id} (type={asset.get('type')}) exists in the live/current configuration with no corresponding entry in the last reviewed baseline — either an out-of-band provisioning action or a baseline that's fallen out of date.",
            impact="An unreviewed resource in the environment — potentially a legitimate change nobody updated the baseline for, or a genuinely unauthorized/shadow resource. Either way, nobody has assessed its security posture.",
            control_id="DRIFT-001",
            policy="Every asset in the live environment must correspond to an entry in the reviewed architecture baseline; new assets must go through the same review as everything else.",
            mitigation=f"Confirm whether {asset_id} was an approved change. If yes, update the baseline architecture.json to include it and run the threat-modelling agent against the updated design. If no, treat this as a potential incident.",
        )


def rule_asset_removed(baseline: Architecture, current: Architecture):
    """An asset in the baseline has no counterpart in the current
    snapshot — it either was legitimately decommissioned (and the
    baseline should be updated) or disappeared unexpectedly (which, for
    something like a logging or storage asset, could itself be an
    incident, e.g. deletion to cover tracks)."""
    removed = set(baseline.assets) - set(current.assets)
    for asset_id in sorted(removed):
        asset = baseline.assets[asset_id]
        yield Finding(
            rule_id="DRIFT-ASSET-REMOVED-01",
            stride=Stride.TAMPERING,
            severity=Severity.MEDIUM,
            asset_ids=[asset_id],
            title=f"{asset_id} is in the reviewed baseline but missing from the current snapshot",
            threat=f"{asset_id} (type={asset.get('type')}) was part of the last reviewed baseline and no longer appears in the current configuration.",
            impact="Either a legitimate decommission the baseline hasn't caught up with yet, or an unexpected/unauthorized deletion — for a logging or data asset specifically, deletion can itself be an attempt to remove evidence.",
            control_id="DRIFT-001",
            policy="An asset's removal from the live environment must be a reviewed, intentional change reflected back into the baseline, not a silent disappearance.",
            mitigation=f"Confirm whether {asset_id}'s removal was intentional. If yes, update the baseline architecture.json to drop it. If no, treat this as a potential incident — especially if {asset_id} handled logging or sensitive data.",
        )


ALL_RULES = [
    rule_public_access_drift,
    rule_encryption_drift,
    rule_logging_disabled_drift,
    rule_identity_binding_drift,
    rule_flow_authentication_drift,
    rule_waf_drift,
    rule_asset_added,
    rule_asset_removed,
]


def run_engine(baseline: Architecture, current: Architecture) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(baseline, current))
    findings.sort(key=lambda f: f.severity.value, reverse=True)
    return findings
