"""
Detection engine — Phase 9 (SIEM + Detection), v1 spec §16.

Same split as threat_engine.py, applied one layer up: threat_engine.py
reasons about an architecture *design* ("is this built safely?");
detection_engine.py reasons about what actually *happened* on it, from
the logs that Phase 9's logging infrastructure (terraform/*/modules/
logging) now produces. Same rule: deterministic correlation rules decide
what counts as an alert and how severe it is — no model call, no
ambiguity, same input always gives the same output. triage.py (the LLM
layer, mirroring explain.py) only turns an Alert into readable prose
afterward; it never gets to invent or suppress one (SR-4/SR-4a apply here
exactly as they do to the threat engine).

Every log event here is synthetic — no real customer data, no real
credentials, no real attack tooling. These are benign, hand-authored
event sequences shaped like the kind of activity a correlation rule
should or shouldn't catch, for Meridian Trust Bank (fictional).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from threat_engine import Severity, Stride

# --------------------------------------------------------------------------
# Log event schema — see threat-model/logs/SCHEMA.md for the full spec.
# --------------------------------------------------------------------------


@dataclass
class LogEvent:
    event_id: str
    timestamp: str  # ISO-8601, "YYYY-MM-DDTHH:MM:SSZ" — compared lexically, which works for ISO-8601 UTC
    event_type: str
    principal: str
    source_ip: str
    target: str
    outcome: str  # "success" | "failure"
    region: str | None = None
    bytes_transferred: int | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "LogEvent":
        return cls(
            event_id=d["event_id"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            principal=d["principal"],
            source_ip=d.get("source_ip", ""),
            target=d.get("target", ""),
            outcome=d.get("outcome", "success"),
            region=d.get("region"),
            bytes_transferred=d.get("bytes_transferred"),
        )


def load_events(path: str | Path) -> list[LogEvent]:
    with open(path) as fh:
        raw = json.load(fh)
    return [LogEvent.from_dict(e) for e in raw.get("events", raw)]


@dataclass
class Alert:
    rule_id: str
    stride: Stride
    severity: Severity
    event_ids: list[str]
    title: str
    behavior: str
    impact: str
    recommended_action: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.stride.value,
            "severity": str(self.severity),
            "events": self.event_ids,
            "alert": self.title,
            "behavior": self.behavior,
            "impact": self.impact,
            "recommended_action": self.recommended_action,
            "status": "OPEN",
        }


# --------------------------------------------------------------------------
# Detection rules — each takes the full event list and yields zero or more
# Alerts. Deliberately small and inspectable, same design principle as
# threat_engine.py's rules (v1 spec §11: "a documented function, not a
# black box").
# --------------------------------------------------------------------------

BRUTE_FORCE_THRESHOLD = 5  # failed auth events, same principal + source_ip, before it's flagged
LARGE_TRANSFER_BYTES = 500_000_000  # 500 MB — arbitrary but documented threshold, not tuned on real traffic
AFTER_HOURS_START, AFTER_HOURS_END = 22, 6  # UTC hour range treated as "after hours"


def _hour(event: LogEvent) -> int:
    # "YYYY-MM-DDTHH:MM:SSZ" -> HH, without pulling in a datetime parser
    # for a single fixed format.
    return int(event.timestamp[11:13])


def _is_after_hours(event: LogEvent) -> bool:
    h = _hour(event)
    return h >= AFTER_HOURS_START or h < AFTER_HOURS_END


def rule_brute_force(events: list[LogEvent]):
    """BRUTE_FORCE_THRESHOLD or more failed logins for the same principal
    from the same source IP is treated as a credential-guessing attempt.
    If a success from that same IP follows the failures, severity is
    CRITICAL (the guessing likely worked) rather than HIGH (still just
    guessing)."""
    by_key: dict[tuple[str, str], list[LogEvent]] = {}
    for e in events:
        if e.event_type != "auth":
            continue
        by_key.setdefault((e.principal, e.source_ip), []).append(e)

    for (principal, source_ip), evs in by_key.items():
        evs_sorted = sorted(evs, key=lambda e: e.timestamp)
        failures = [e for e in evs_sorted if e.outcome == "failure"]
        if len(failures) < BRUTE_FORCE_THRESHOLD:
            continue
        last_failure_ts = failures[-1].timestamp
        success_after = [
            e for e in evs_sorted if e.outcome == "success" and e.timestamp >= last_failure_ts
        ]
        severity = Severity.CRITICAL if success_after else Severity.HIGH
        involved = failures + success_after
        yield Alert(
            rule_id="DET-BRUTEFORCE-01",
            stride=Stride.SPOOFING,
            severity=severity,
            event_ids=[e.event_id for e in involved],
            title=(
                f"{len(failures)} failed logins for {principal} from {source_ip}"
                + (", followed by a success" if success_after else "")
            ),
            behavior=(
                f"{len(failures)} consecutive authentication failures for {principal} "
                f"from {source_ip}"
                + (
                    ", then a successful login from the same IP — consistent with a "
                    "guessed or stuffed credential that worked."
                    if success_after
                    else " with no successful login yet — consistent with an "
                    "in-progress credential-guessing attempt."
                )
            ),
            impact=(
                "Likely account takeover — treat the account as compromised until verified otherwise."
                if success_after
                else "No confirmed compromise yet, but the account should be monitored or temporarily locked."
            ),
            recommended_action="Force a password/credential reset, review MFA status, and rate-limit or block the source IP.",
        )


def rule_impossible_travel(events: list[LogEvent]):
    """Two successful logins for the same principal, from two different
    regions, within IMPOSSIBLE_TRAVEL_WINDOW_MINUTES of each other — no
    real person legitimately does that. A strong account-compromise
    signal even without a failed-login pattern first (e.g. a phished
    session token used from a second location)."""
    IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 60

    by_principal: dict[str, list[LogEvent]] = {}
    for e in events:
        if e.event_type == "auth" and e.outcome == "success" and e.region:
            by_principal.setdefault(e.principal, []).append(e)

    for principal, evs in by_principal.items():
        evs_sorted = sorted(evs, key=lambda e: e.timestamp)
        for i in range(len(evs_sorted) - 1):
            a, b = evs_sorted[i], evs_sorted[i + 1]
            if a.region == b.region:
                continue
            minutes_apart = _minutes_between(a.timestamp, b.timestamp)
            if minutes_apart <= IMPOSSIBLE_TRAVEL_WINDOW_MINUTES:
                yield Alert(
                    rule_id="DET-TRAVEL-01",
                    stride=Stride.SPOOFING,
                    severity=Severity.CRITICAL,
                    event_ids=[a.event_id, b.event_id],
                    title=f"{principal} logged in from {a.region} then {b.region} {minutes_apart} min apart",
                    behavior=(
                        f"{principal} authenticated successfully from {a.region} at "
                        f"{a.timestamp}, then from {b.region} at {b.timestamp} — "
                        f"{minutes_apart} minutes apart, not physically possible for one person."
                    ),
                    impact="Strong indicator of a stolen credential or session token in active use from a second location.",
                    recommended_action=f"Force-expire {principal}'s active sessions, require re-authentication with MFA, and confirm which login was legitimate.",
                )


def _minutes_between(ts_a: str, ts_b: str) -> int:
    # Both are "YYYY-MM-DDTHH:MM:SSZ" on the same or adjacent day in these
    # fixtures — parse just enough (H*60+M, ignoring seconds) rather than
    # pulling in a full datetime dependency for a fixed, controlled format.
    def to_minutes(ts: str) -> int:
        h, m = int(ts[11:13]), int(ts[14:16])
        return h * 60 + m

    return abs(to_minutes(ts_b) - to_minutes(ts_a))


def rule_privilege_escalation_after_hours(events: list[LogEvent]):
    """A role/permission grant outside business hours is a real, if weak,
    signal on its own — legitimate change management mostly happens
    during the day. Escalated here specifically for grants that touch a
    sensitive target (matches the 'critical'/'high' vocabulary the threat
    engine already uses), since an after-hours role change on a low-value
    target is far less interesting."""
    SENSITIVE_TARGET_MARKERS = ("secrets", "payment", "customer-storage", "key-vault")

    for e in events:
        if e.event_type != "iam_change" or e.outcome != "success":
            continue
        if not _is_after_hours(e):
            continue
        if not any(marker in e.target for marker in SENSITIVE_TARGET_MARKERS):
            continue
        yield Alert(
            rule_id="DET-PRIVESC-01",
            stride=Stride.ELEVATION_OF_PRIVILEGE,
            severity=Severity.HIGH,
            event_ids=[e.event_id],
            title=f"After-hours privilege change by {e.principal} on {e.target}",
            behavior=(
                f"{e.principal} granted/changed permissions on {e.target} at "
                f"{e.timestamp} (outside {AFTER_HOURS_END:02d}:00-{AFTER_HOURS_START:02d}:00 UTC business hours)."
            ),
            impact="Off-hours IAM changes to sensitive resources are a common early step in both insider misuse and post-compromise privilege escalation.",
            recommended_action=f"Confirm this change against an approved change ticket; if none exists, revert it and investigate {e.principal}.",
        )


def rule_data_exfiltration_volume(events: list[LogEvent]):
    """A single data-transfer event moving more than LARGE_TRANSFER_BYTES
    out of a sensitive store is flagged regardless of whether the
    credential used was valid — a legitimate account moving an unusually
    large volume of data is exactly the pattern insider-threat and
    post-compromise exfiltration both produce."""
    for e in events:
        if e.event_type != "data_transfer" or e.outcome != "success":
            continue
        if not e.bytes_transferred or e.bytes_transferred < LARGE_TRANSFER_BYTES:
            continue
        yield Alert(
            rule_id="DET-EXFIL-01",
            stride=Stride.INFO_DISCLOSURE,
            severity=Severity.CRITICAL,
            event_ids=[e.event_id],
            title=f"{e.principal} transferred {e.bytes_transferred / 1_000_000:.0f} MB from {e.target}",
            behavior=(
                f"{e.principal} moved {e.bytes_transferred / 1_000_000:.0f} MB out of "
                f"{e.target} in a single transfer at {e.timestamp} — well above the "
                f"{LARGE_TRANSFER_BYTES / 1_000_000:.0f} MB baseline for normal activity."
            ),
            impact="Large single-transfer volumes from a sensitive store are the single strongest signal of bulk data exfiltration, insider or external.",
            recommended_action=f"Suspend {e.principal}'s active sessions pending review, and confirm the transfer against a known, approved business process.",
        )


def rule_audit_logging_tampered(events: list[LogEvent]):
    """A principal disabling or deleting the audit trail itself is
    REPUDIATION in the most direct sense — it's usually the attacker
    covering their tracks, and it's always CRITICAL regardless of what
    else that principal did, because it can hide everything that comes
    after it."""
    for e in events:
        if e.event_type in ("logging_disabled", "log_deleted") and e.outcome == "success":
            yield Alert(
                rule_id="DET-LOGTAMPER-01",
                stride=Stride.REPUDIATION,
                severity=Severity.CRITICAL,
                event_ids=[e.event_id],
                title=f"{e.principal} {'disabled' if e.event_type == 'logging_disabled' else 'deleted'} audit logging on {e.target}",
                behavior=(
                    f"{e.principal} {'disabled logging on' if e.event_type == 'logging_disabled' else 'deleted logs from'} "
                    f"{e.target} at {e.timestamp}."
                ),
                impact="Tampering with the audit trail is a near-universal signal of an active, deliberate attack — it removes the evidence needed to investigate everything else.",
                recommended_action=f"Treat as an active incident immediately: re-enable/restore logging, isolate {e.principal}'s credentials, and escalate — do not wait for corroborating alerts.",
            )


ALL_DETECTION_RULES = [
    rule_brute_force,
    rule_impossible_travel,
    rule_privilege_escalation_after_hours,
    rule_data_exfiltration_volume,
    rule_audit_logging_tampered,
]


def run_detection(events: list[LogEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in ALL_DETECTION_RULES:
        alerts.extend(rule(events))
    alerts.sort(key=lambda a: a.severity.value, reverse=True)
    return alerts
