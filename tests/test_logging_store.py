"""
Tests for logging/log_store.py — spec §16 development table, item 9
("Centralized logging (design + local simulation)"). The spec's own
required test for this phase is verbatim: "Test that a simulated log
event is captured and queryable locally." The tests below are that
requirement taken literally (capture one event, read it back), plus real
fixture ingestion, persistence across a process-like reopen (the property
that actually makes this "local storage" rather than "an in-memory list"),
idempotent re-ingestion, and every query filter.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGGING_DIR = REPO_ROOT / "logging"
LOGS_DIR = REPO_ROOT / "threat-model" / "logs"
sys.path.insert(0, str(LOGGING_DIR))

from log_store import LogStore  # noqa: E402

_EVENT = {
    "event_id": "evt-test-001",
    "timestamp": "2026-09-22T10:00:00Z",
    "event_type": "auth",
    "principal": "a.tester",
    "source_ip": "10.0.0.1",
    "target": "api-gateway",
    "outcome": "success",
}


# ---------------------------------------------------------------------------
# THE required test: a simulated log event is captured and queryable
# locally.
# ---------------------------------------------------------------------------

def test_a_simulated_log_event_is_captured_and_queryable_locally():
    store = LogStore(":memory:")
    store.ingest_event(_EVENT)

    rows = store.query(principal="a.tester")
    assert len(rows) == 1
    assert rows[0]["event_id"] == "evt-test-001"
    assert rows[0]["event_type"] == "auth"
    assert rows[0]["target"] == "api-gateway"
    store.close()


# ---------------------------------------------------------------------------
# Persistence across reopen — the property that makes this "local storage,"
# not just an in-memory list that dies with the process that ingested it.
# ---------------------------------------------------------------------------

def test_events_are_queryable_after_the_store_is_closed_and_reopened(tmp_path):
    db_path = tmp_path / "events.sqlite"

    writer = LogStore(db_path)
    writer.ingest_event(_EVENT)
    writer.close()

    reader = LogStore(db_path)
    rows = reader.query()
    assert len(rows) == 1
    assert rows[0]["event_id"] == "evt-test-001"
    reader.close()


def test_context_manager_closes_the_connection(tmp_path):
    db_path = tmp_path / "events.sqlite"
    with LogStore(db_path) as store:
        store.ingest_event(_EVENT)
        assert store.count() == 1
    # A second, independent open still sees the data — proves the first
    # __exit__ actually committed and closed rather than leaving a dangling
    # transaction.
    reopened = LogStore(db_path)
    assert reopened.count() == 1
    reopened.close()


# ---------------------------------------------------------------------------
# Idempotent ingestion — capturing must be safe to repeat.
# ---------------------------------------------------------------------------

def test_ingesting_the_same_event_id_twice_updates_in_place_not_duplicates():
    store = LogStore(":memory:")
    store.ingest_event(_EVENT)
    changed = dict(_EVENT)
    changed["outcome"] = "failure"
    store.ingest_event(changed)

    assert store.count() == 1
    rows = store.query()
    assert rows[0]["outcome"] == "failure"
    store.close()


def test_ingest_event_requires_the_core_fields():
    store = LogStore(":memory:")
    with pytest.raises(ValueError):
        store.ingest_event({"event_id": "evt-x"})  # missing timestamp/event_type/principal
    store.close()


# ---------------------------------------------------------------------------
# Real fixture ingestion — threat-model/logs/*.json, the same files
# detection_engine.py already reads.
# ---------------------------------------------------------------------------

def test_ingest_file_loads_every_event_in_a_real_fixture():
    store = LogStore(":memory:")
    n = store.ingest_file(LOGS_DIR / "logs-multi-stage-incident.json")
    assert n == 9  # matches SCHEMA.md's documented event count for this fixture
    assert store.count() == 9
    store.close()


def test_ingest_file_records_the_source_name():
    store = LogStore(":memory:")
    path = LOGS_DIR / "logs-normal.json"
    store.ingest_file(path)
    rows = store.query()
    assert all(r["ingested_from"] == str(path) for r in rows)
    store.close()


def test_ingesting_two_fixtures_into_one_store_accumulates_both():
    store = LogStore(":memory:")
    store.ingest_file(LOGS_DIR / "logs-normal.json")
    store.ingest_file(LOGS_DIR / "logs-brute-force.json")
    assert store.count() == store.query().__len__()
    assert store.count() > 0
    # event_ids don't collide across the two fixtures, so nothing merges
    normal_ids = {e["event_id"] for e in __import__("json").loads((LOGS_DIR / "logs-normal.json").read_text())["events"]}
    bf_ids = {e["event_id"] for e in __import__("json").loads((LOGS_DIR / "logs-brute-force.json").read_text())["events"]}
    assert normal_ids.isdisjoint(bf_ids)
    assert store.count() == len(normal_ids) + len(bf_ids)
    store.close()


# ---------------------------------------------------------------------------
# query() filters
# ---------------------------------------------------------------------------

@pytest.fixture
def incident_store():
    store = LogStore(":memory:")
    store.ingest_file(LOGS_DIR / "logs-multi-stage-incident.json")
    yield store
    store.close()


def test_query_with_no_filters_returns_everything_oldest_first(incident_store):
    rows = incident_store.query()
    assert len(rows) == 9
    timestamps = [r["timestamp"] for r in rows]
    assert timestamps == sorted(timestamps)


def test_query_filters_by_event_type(incident_store):
    rows = incident_store.query(event_type="iam_change")
    assert len(rows) == 1
    assert rows[0]["target"] == "secrets-manager-role"


def test_query_filters_by_principal(incident_store):
    rows = incident_store.query(principal="k.doran")
    assert len(rows) == 9  # the entire multi-stage-incident fixture is one attacker


def test_query_filters_by_target(incident_store):
    rows = incident_store.query(target="customer-storage")
    assert len(rows) == 1
    assert rows[0]["event_type"] == "data_transfer"


def test_query_filters_by_outcome(incident_store):
    rows = incident_store.query(outcome="success")
    assert all(r["outcome"] == "success" for r in rows)


def test_query_filters_by_time_range(incident_store):
    all_rows = incident_store.query()
    midpoint = all_rows[len(all_rows) // 2]["timestamp"]
    later = incident_store.query(since=midpoint)
    assert all(r["timestamp"] >= midpoint for r in later)
    assert len(later) < len(all_rows)


def test_query_respects_limit(incident_store):
    rows = incident_store.query(limit=2)
    assert len(rows) == 2


def test_query_with_a_filter_matching_nothing_returns_empty(incident_store):
    assert incident_store.query(principal="nobody-real") == []
