#!/usr/bin/env python3
"""
logging/log_store.py — SentinelCloud v1 spec §16 development table, item 9
("Centralized logging (design + local simulation)"): "Close the
repudiation gap (§10) with a LOCAL log-aggregation simulation."

WHY LOCAL, NOT A REAL SIEM. Same cost-discipline/SIMULATED-mode reasoning
as agent/drift.py (§14): this project has never had a real cloud account
to ship real logs from, and terraform/*/modules/logging (Phase 9) already
covers the *design* of a real logging pipeline (Log Analytics / Cloud
Logging sink / CloudTrail) for when one exists. What was still missing —
the actual gap this module closes — is anything that makes a captured
log event *queryable after the fact* rather than just "present in a
logs.json file you'd have to grep by hand." The spec's own §10 text is
explicit about the distinction this module exists to close: auditability
today is "reproducible if you re-run it" (analyze.py/detect.py's own JSON
report output); centralized logging is what extends that to "queryable
after the fact" — this module, not a new correlation engine, is that
extension. detection_engine.py already reasons about events *as they
stream past*; LogStore is what lets you come back later and ask "what did
m.reyes actually do to notification-service-role that afternoon?" without
re-running any detection rule at all.

WHAT THIS IS NOT. Not a new deterministic security engine — there is no
Finding/Alert/Severity concept here, no rule fires, and nothing here ever
makes a BLOCKED/ALLOWED or INCIDENT/CLEAR decision (that stays entirely
with threat_engine.py/analyze.py and detection_engine.py/detect.py,
respectively; SR-4/SR-4a are unaffected — this module doesn't touch the
LLM layer at all). It is a small, local, file-backed simulation of "logs
land somewhere queryable" — literally a SQLite table (stdlib `sqlite3`,
zero new dependencies) — that agent/detect.py can optionally write
through (`--store`, purely additive) and this module's own CLI
(query_cli.py) can read back from independently, in a separate process,
after the fact. That "separate process, after the fact" property is the
whole point: it's what makes the store's persistence real rather than
just an in-memory list that dies with the run that produced it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS log_events (
    event_id           TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    principal            TEXT NOT NULL,
    source_ip            TEXT,
    target               TEXT,
    outcome              TEXT,
    region               TEXT,
    bytes_transferred    INTEGER,
    ingested_from        TEXT
);
"""

# The full set of columns ingest_event() accepts, in the fixed order used
# by both the INSERT statement and query()'s row-to-dict conversion.
_EVENT_FIELDS = (
    "event_id", "timestamp", "event_type", "principal", "source_ip",
    "target", "outcome", "region", "bytes_transferred", "ingested_from",
)


class LogStore:
    """A local, file-backed (or in-memory, for tests) simulation of a
    centralized log-aggregation store. Event capture is idempotent by
    event_id — ingesting the same event twice (e.g. re-running
    `detect.py --store` against the same logs.json, or a query_cli.py
    --ingest against a file already loaded) updates it in place rather
    than erroring or silently duplicating rows, because "capture" needs
    to be safe to repeat."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def ingest_event(self, event: dict) -> None:
        if "event_id" not in event or "timestamp" not in event or "event_type" not in event or "principal" not in event:
            raise ValueError(f"log event missing a required field (event_id/timestamp/event_type/principal): {event}")
        values = tuple(event.get(f) for f in _EVENT_FIELDS)
        self._conn.execute(
            f"""INSERT INTO log_events ({", ".join(_EVENT_FIELDS)})
                VALUES ({", ".join("?" for _ in _EVENT_FIELDS)})
                ON CONFLICT(event_id) DO UPDATE SET
                {", ".join(f"{f}=excluded.{f}" for f in _EVENT_FIELDS if f != "event_id")}""",
            values,
        )
        self._conn.commit()

    def ingest_events(self, events: list[dict], source_name: str | None = None) -> int:
        """Ingest a batch of events (the same shape load_events()/LogEvent
        in agent/detection_engine.py already use). Returns the number of
        events ingested (not necessarily the number of *new* rows, since
        ingestion is idempotent by event_id)."""
        n = 0
        for e in events:
            e = dict(e)
            if source_name and not e.get("ingested_from"):
                e["ingested_from"] = source_name
            self.ingest_event(e)
            n += 1
        return n

    def ingest_file(self, path: str | Path) -> int:
        """Ingest every event in a threat-model/logs/*.json-shaped file
        directly, without going through detect.py at all — this is what
        makes "a simulated log event is captured" (the spec's required
        test for this phase) provable with nothing but this module."""
        data = json.loads(Path(path).read_text())
        return self.ingest_events(data.get("events", []), source_name=str(path))

    def query(
        self,
        *,
        event_type: str | None = None,
        principal: str | None = None,
        target: str | None = None,
        outcome: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Every filter is optional and AND-combined; timestamps are
        compared lexically (ISO-8601 UTC, same convention as
        detection_engine.py's rules), so `since`/`until` work as plain
        string bounds without any datetime parsing. No filters at all
        returns every event, oldest first."""
        sql = "SELECT * FROM log_events WHERE 1=1"
        params: list = []
        if event_type is not None:
            sql += " AND event_type = ?"
            params.append(event_type)
        if principal is not None:
            sql += " AND principal = ?"
            params.append(principal)
        if target is not None:
            sql += " AND target = ?"
            params.append(target)
        if outcome is not None:
            sql += " AND outcome = ?"
            params.append(outcome)
        if since is not None:
            sql += " AND timestamp >= ?"
            params.append(since)
        if until is not None:
            sql += " AND timestamp <= ?"
            params.append(until)
        sql += " ORDER BY timestamp ASC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM log_events").fetchone()[0]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "LogStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
