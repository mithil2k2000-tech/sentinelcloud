"""
Tests for logging/query_cli.py — the "queryable" half of the centralized
logging simulation (spec §16 table item 9), sibling to
test_logging_store.py, which covers the same behavior at the module level.
These are the CLI-level tests, run as real subprocesses, matching the
pattern every other CLI in this project uses (test_analyze_cli.py,
test_detect_cli.py, test_drift_scan_cli.py, etc.).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGGING_DIR = REPO_ROOT / "logging"
LOGS_DIR = REPO_ROOT / "threat-model" / "logs"
QUERY_CLI_PY = LOGGING_DIR / "query_cli.py"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(QUERY_CLI_PY), *args],
        cwd=LOGGING_DIR,
        capture_output=True,
        text=True,
    )


def test_ingest_flag_captures_a_real_fixture_and_reports_the_count(tmp_path):
    db_path = tmp_path / "events.sqlite"
    result = _run_cli(str(db_path), "--ingest", str(LOGS_DIR / "logs-multi-stage-incident.json"))
    assert result.returncode == 0
    assert "ingested 9 event(s)" in result.stdout
    assert "total stored: 9" in result.stdout
    assert db_path.exists()


def test_query_after_a_separate_ingest_run_still_sees_the_data(tmp_path):
    """The point of this module: capture and query don't have to happen in
    the same process. Ingest in one subprocess, query in a completely
    separate one, and the data is still there — real local persistence,
    not an in-memory artifact of one run."""
    db_path = tmp_path / "events.sqlite"
    ingest_result = _run_cli(str(db_path), "--ingest", str(LOGS_DIR / "logs-multi-stage-incident.json"))
    assert ingest_result.returncode == 0

    query_result = _run_cli(str(db_path), "--principal", "k.doran", "--event-type", "iam_change")
    assert query_result.returncode == 0
    assert "1 matching event(s)" in query_result.stdout
    assert "secrets-manager-role" in query_result.stdout


def test_query_with_no_matches_reports_zero_not_an_error(tmp_path):
    db_path = tmp_path / "events.sqlite"
    _run_cli(str(db_path), "--ingest", str(LOGS_DIR / "logs-normal.json"))
    result = _run_cli(str(db_path), "--principal", "nobody-real")
    assert result.returncode == 0
    assert "0 matching event(s)" in result.stdout


def test_json_flag_writes_matching_rows(tmp_path):
    db_path = tmp_path / "events.sqlite"
    out_file = tmp_path / "result.json"
    result = _run_cli(
        str(db_path), "--ingest", str(LOGS_DIR / "logs-multi-stage-incident.json"),
        "--principal", "k.doran", "--json", str(out_file),
    )
    assert result.returncode == 0
    payload = json.loads(out_file.read_text())
    assert len(payload) == 9
    assert all(row["principal"] == "k.doran" for row in payload)
