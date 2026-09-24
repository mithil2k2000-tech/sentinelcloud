#!/usr/bin/env python3
"""
CLI entrypoint — Phase 9's detection side, sibling to analyze.py.

Usage:
    python3 detect.py <logs.json> [--json out.json] [--triage] [--fail-on HIGH]

Pipeline:
    logs.json -> detection_engine (deterministic alerts)
              -> triage.narrate_alert (LLM or template, per alert, opt-in)
              -> aggregate risk + INCIDENT/CLEAR decision
              -> human-readable report (+ optional JSON export)

This is deliberately NOT wired into the security-gate.yml deployment gate
that analyze.py drives — that gate answers "is this architecture safe to
deploy", a pre-deployment question. detect.py answers "did something bad
already happen", a retrospective/monitoring question over log data that
doesn't exist until something is actually running. The two are related
(detect.py is what the logging infrastructure analyze.py's LOG-001 rule
requires is actually *for*) but are different pipelines with different
triggers — see docs/phase9-siem-detection.md.

Exit code is 1 when the decision is INCIDENT, 0 when CLEAR.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from detection_engine import ALL_DETECTION_RULES, Severity, load_events, run_detection
from triage import narrate_alert

# logging/ sits alongside agent/, not under it — see logging/log_store.py's
# own docstring for why this is a separate top-level module rather than
# another file in agent/: it's the spec's own §16-table Key-files answer
# for this phase ("Centralized logging (design + local simulation)").
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "logging"))
from log_store import LogStore  # noqa: E402

DEFAULT_FAIL_ON = Severity.HIGH  # any HIGH or CRITICAL alert raises an incident by default


def aggregate_alerts(alerts, fail_on: Severity = DEFAULT_FAIL_ON) -> dict:
    """Summarize alerts and decide INCIDENT/CLEAR against a severity
    threshold — same shape as analyze.py's aggregate(), deliberately, so
    the two pipelines read the same way even though they answer different
    questions."""
    counts = {s: 0 for s in Severity}
    for a in alerts:
        counts[a.severity] += 1
    if counts[Severity.CRITICAL] > 0:
        overall = "CRITICAL"
    elif counts[Severity.HIGH] > 0:
        overall = "HIGH"
    elif counts[Severity.MEDIUM] > 0:
        overall = "MEDIUM"
    elif counts[Severity.LOW] > 0:
        overall = "LOW"
    else:
        overall = "NONE"
    incident = any(a.severity.value >= fail_on.value for a in alerts)
    return {
        "overall_risk": overall,
        "counts": {str(s): counts[s] for s in Severity},
        "fail_on": str(fail_on),
        "status": "INCIDENT" if incident else "CLEAR",
    }


def render_report(source_name: str, event_count: int, alerts, summary: dict, narratives: dict[str, str]) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f"DETECTION REPORT — {source_name} ({event_count} events)")
    lines.append("=" * 72)
    lines.append(f"Overall Risk: {summary['overall_risk']}")
    lines.append(
        "CRITICAL: {CRITICAL}  HIGH: {HIGH}  MEDIUM: {MEDIUM}  LOW: {LOW}".format(
            **summary["counts"]
        )
    )
    status_symbol = "🚨 INCIDENT" if summary["status"] == "INCIDENT" else "✅ CLEAR"
    lines.append(f"Status: {status_symbol}  (alert threshold: {summary['fail_on']}+)")
    lines.append("")

    if not alerts:
        lines.append(f"No alerts. (Engine ran {len(ALL_DETECTION_RULES)} rules across {event_count} events.)")
        return "\n".join(lines)

    lines.append(f"Alerts ({len(alerts)}, most severe first):")
    lines.append("-" * 72)
    for i, a in enumerate(alerts, 1):
        lines.append(f"[{i}] {a.severity} — {a.stride.value} — {a.rule_id}")
        lines.append(f"    Alert:      {a.title}")
        lines.append(f"    Events:     {', '.join(a.event_ids)}")
        narrative = narratives.get(a.rule_id + "|" + ",".join(a.event_ids))
        if narrative:
            lines.append(f"    Triage:     {narrative}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", help="Path to a logs.json file (see threat-model/logs/SCHEMA.md)")
    parser.add_argument("--json", dest="json_out", help="Also write the full report as JSON to this path")
    parser.add_argument(
        "--triage",
        action="store_true",
        help="Add an LLM (or template-fallback) narrative per alert. Purely additive — "
             "never changes which alerts exist, their severity, or the INCIDENT/CLEAR decision.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Minimum severity that raises an incident (default: HIGH).",
    )
    parser.add_argument(
        "--store",
        dest="store_path",
        help="Also capture these events into a local, queryable log-aggregation "
             "store (logging/log_store.py) at this SQLite file path. Purely "
             "additive — never changes which alerts exist, their severity, or "
             "the INCIDENT/CLEAR decision. See docs/centralized-logging.md.",
    )
    args = parser.parse_args()

    events = load_events(args.logs)
    alerts = run_detection(events)
    summary = aggregate_alerts(alerts, fail_on=Severity[args.fail_on])

    if args.store_path:
        store = LogStore(args.store_path)
        n = store.ingest_events([dataclasses.asdict(e) for e in events], source_name=args.logs)
        store.close()
        print(f"(captured {n} event(s) into local log store: {args.store_path})\n")

    narratives: dict[str, str] = {}
    if args.triage:
        for a in alerts:
            key = a.rule_id + "|" + ",".join(a.event_ids)
            narratives[key] = narrate_alert(a)

    report_text = render_report(args.logs, len(events), alerts, summary, narratives)
    print(report_text)

    if args.json_out:
        payload = {
            "source": args.logs,
            "event_count": len(events),
            "summary": summary,
            "alerts": [a.to_dict() for a in alerts],
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2))
        print(f"\n(full JSON report written to {args.json_out})")

    return 1 if summary["status"] == "INCIDENT" else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
