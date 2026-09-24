#!/usr/bin/env python3
"""
logging/query_cli.py — the "queryable" half of the local log-aggregation
simulation (agent/detect.py --store is the "captured" half). Sibling CLI
to analyze.py/detect.py/k8s_scan.py/drift_scan.py/report_compliance.py,
same family, different job: this one never makes a security decision at
all — no BLOCKED/ALLOWED, no INCIDENT/CLEAR, no exit code that means
anything beyond "the query ran." It exists to make the spec's own
required test for this phase runnable by hand, interactively: "test that
a simulated log event is captured and queryable locally."

Usage:
    python3 query_cli.py <db.sqlite> --ingest ../threat-model/logs/logs-multi-stage-incident.json
    python3 query_cli.py <db.sqlite> --principal s.okoye --event-type auth
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from log_store import LogStore


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db", help="Path to the local log store (a SQLite file; created if it doesn't exist)")
    parser.add_argument("--ingest", dest="ingest_path", help="Also ingest a logs.json file before querying")
    parser.add_argument("--event-type", dest="event_type")
    parser.add_argument("--principal")
    parser.add_argument("--target")
    parser.add_argument("--outcome", choices=["success", "failure"])
    parser.add_argument("--since", help="ISO-8601 timestamp lower bound (inclusive)")
    parser.add_argument("--until", help="ISO-8601 timestamp upper bound (inclusive)")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json", dest="json_out", help="Also write the matching rows as JSON to this path")
    args = parser.parse_args()

    store = LogStore(args.db)

    if args.ingest_path:
        n = store.ingest_file(args.ingest_path)
        print(f"(ingested {n} event(s) from {args.ingest_path} into {args.db})")

    rows = store.query(
        event_type=args.event_type,
        principal=args.principal,
        target=args.target,
        outcome=args.outcome,
        since=args.since,
        until=args.until,
        limit=args.limit,
    )

    print(f"{len(rows)} matching event(s) in {args.db} (total stored: {store.count()}):")
    for r in rows:
        print(
            "  [{timestamp}] {event_type:<16} {principal:<14} -> {target:<26} ({outcome})".format(
                timestamp=r["timestamp"],
                event_type=r["event_type"],
                principal=r["principal"],
                target=r["target"] or "-",
                outcome=r["outcome"] or "-",
            )
        )

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(rows, indent=2))
        print(f"\n(query result written to {args.json_out})")

    store.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
