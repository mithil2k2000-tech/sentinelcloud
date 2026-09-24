# Centralized logging — design + local simulation (spec §16 table item 9)

Status: **built, tested, and run for real**. 23 new tests (244 total in
`tests/`, all passing: 17 in `test_logging_store.py`, 4 in
`test_logging_query_cli.py`, 2 more in `test_detect_cli.py` for the
`--store` flag).

## What the spec asks for, verbatim

> **Objective:** Close the repudiation gap (§10) with a LOCAL
> log-aggregation simulation.
> **Key files:** `logging/`, updated `architecture.json` schema
> (`logging.enabled` → structured detail).
> **Tests required before "done":** Test that a simulated log event is
> captured and queryable locally.

## A real divergence caught before building, not after

This phase's own name and "Key files" (`logging/`, a top-level directory)
are easy to confuse with what the informal roadmap already calls "Phase 9
— SIEM + Detection" (`terraform/*/modules/logging`, `agent/detection_engine.py`,
`agent/detect.py`) — a previously-noted numbering gap (see the note at
the top of `claude/roadmap.md`) that had been flagged as "not yet
investigated" until this phase was actually started. Re-reading the
spec's own §16 table row for item 9 before writing anything settled it:
this is a genuinely different, smaller piece of work than what Phase 9
already built.

Phase 9 already covers: (a) the *design* of real logging infrastructure
on all three clouds (Log Analytics, a GCS audit sink, CloudTrail), and
(b) a *correlation engine* that reasons about a batch of log events and
raises alerts. Neither of those makes a captured event **queryable after
the fact** — `detect.py` reads a `logs.json` file, runs its rules once,
and prints a report; nothing persists anywhere you could come back to
later and ask "what did this principal actually do?" That's the specific
gap item 9 names, and its own text in §10/§11 of the spec is explicit
about it: today's auditability is "reproducible if you re-run it";
centralized logging should extend that to "queryable after the fact."
This module is that extension — a small piece, not a restart of Phase 9.

## What was built

**`logging/log_store.py`** — `LogStore`, a local, file-backed (or
`:memory:`, for tests) simulation of a centralized log-aggregation store.
Backed by the Python standard library's `sqlite3` — zero new dependencies,
consistent with this project's cost discipline (same reasoning as
`drift.py`'s SIMULATED mode: no real cloud account exists to ship real
logs from, so "centralized" here means "captured somewhere queryable
locally," not a real log-shipping pipeline). Three operations:
`ingest_event()`/`ingest_events()`/`ingest_file()` (idempotent by
`event_id` — re-ingesting the same event updates it in place rather than
duplicating or erroring), and `query()` (every field —
`event_type`/`principal`/`target`/`outcome`/`since`/`until`/`limit` — is
an optional, AND-combined filter).

**`logging/query_cli.py`** — the CLI half: ingest a `logs.json` file
and/or query an existing store, from the command line, in a separate
process from whatever ingested it. That "separate process" property is
deliberate — it's what actually proves persistence rather than an
in-memory artifact of one run:

```
$ python3 query_cli.py events.sqlite --ingest ../threat-model/logs/logs-multi-stage-incident.json
(ingested 9 event(s) from ../threat-model/logs/logs-multi-stage-incident.json into events.sqlite)
9 matching event(s) in events.sqlite (total stored: 9): ...

$ python3 query_cli.py events.sqlite --principal k.doran --event-type iam_change
1 matching event(s) in events.sqlite (total stored: 9):
  [2026-09-17T01:22:10Z] iam_change       k.doran        -> secrets-manager-role       (success)
```

**`agent/detect.py --store <path>`** — the capture half wired into the
existing detection CLI: every event `detect.py` analyzes is also written
into a local `LogStore` at the given path, so the exact events behind a
detection decision are the ones you can query back later — not a
separately-curated copy. **Purely additive**, the same contract as
`--triage`/`--risk-model`/`--compliance` before it: proven by
`test_cli_store_flag_is_purely_additive`, which diffs the full alerts/
summary JSON with and without `--store` and asserts byte-for-byte
equality of everything except the one informational line `--store` adds
to stdout. Confirmed for real, not just by the test: running
`detect.py logs-multi-stage-incident.json` with and without `--store`
gives the identical INCIDENT/CRITICAL decision and identical report body,
differing only by the line `(captured 9 event(s) into local log store: ...)`.

## The `architecture.json` schema extension

`logging.enabled` was already a plain boolean (`threat_engine.py`'s
`rule_logging_disabled` only ever reads that one field). Per item 9's own
"Key files" column, the schema now carries structured detail alongside
it — `retention_days` and `local_query_enabled` — both optional, both
additive (see `threat-model/SCHEMA.md`). The three hardened baselines
(`architecture-hardened{,-gcp,-aws}.json`) were updated to set
`local_query_enabled: true` now that a real local store exists for them
to point at; `architecture-proposed.json` (the pre-hardening design, with
`logging.enabled: false`) was deliberately left untouched — there's
nothing to describe the detail of when logging isn't enabled at all.
Confirmed additive, not just asserted: the full 221-test suite that
existed before this change (`threat_engine`/`risk_model`/`drift`/
`compliance`/`report_compliance`, all of which read these same fixture
files) still passes unchanged after the schema extension — no finding,
no decision, and no snapshot anywhere shifted.

## The required test, run for real

`test_a_simulated_log_event_is_captured_and_queryable_locally` in
`tests/test_logging_store.py` is the spec's own required test, taken
literally: ingest one event, query it back by `principal`, assert it's
there. Sitting alongside it: real-fixture ingestion (`logs-multi-stage-incident.json`'s
9 events, matching the count already documented in
`threat-model/logs/SCHEMA.md`), every `query()` filter exercised
individually, idempotent re-ingestion, and — the test that actually
proves "local storage" rather than "an in-memory list" —
`test_events_are_queryable_after_the_store_is_closed_and_reopened`,
which closes the store, opens a brand-new `LogStore` against the same
file path, and confirms the data is still there. The CLI-level tests in
`test_logging_query_cli.py` push this one step further: ingest in one
subprocess, query in a completely separate one, same result.

## CI integration

Added a ninth job, `centralized-logging-demo` (non-gating, `needs:
unit-tests`), which ingests the `logs-multi-stage-incident.json` fixture
into a fresh local store and runs one demonstration query against it,
posting both to the job summary — see `docs/ci-cd.md` for the full
nine-job breakdown. Non-gating for the same reason `detection-engine-demo`
and `drift-detection-demo` are: this module never makes a security
decision, so there is nothing here for a gate to enforce.

## Honest limitations

- **This is a local simulation, not a real SIEM ingestion pipeline.**
  `terraform/*/modules/logging` (Phase 9) already covers the *design* of
  real log shipping on all three clouds — this module doesn't replace or
  extend that; it just closes the "queryable after the fact" gap for
  whatever gets fed to `detect.py` locally, exactly as scoped by item 9's
  own "design + local simulation" title.
- **No retention enforcement.** `retention_days` in the schema is
  documentation of an architecture's intended retention policy, not
  something `LogStore` actually enforces — nothing expires or gets
  pruned; it's a design-level detail like `waf_enabled`, not a live
  control.
- **Single-file, single-machine store.** `LogStore` is one SQLite file at
  one path — there's no multi-user access, no remote query interface, and
  no indexing beyond the primary key on `event_id`. Fine for a local
  simulation and for this project's test/demo scale; a real deployment
  would need an actual queryable backend (which is exactly what
  `terraform/*/modules/logging`'s real infrastructure is *for*).
- **`query_cli.py` has no free-text search** — only the exact-match/range
  filters `LogStore.query()` exposes. A grep-style search across
  `target`/`principal` would be a reasonable next step, not built here.

## Running it yourself

```bash
cd logging
python3 query_cli.py /tmp/events.sqlite --ingest ../threat-model/logs/logs-multi-stage-incident.json
python3 query_cli.py /tmp/events.sqlite --principal k.doran

cd ../agent
python3 detect.py ../threat-model/logs/logs-multi-stage-incident.json --store /tmp/events.sqlite

cd ../tests
python3 -m pytest test_logging_store.py test_logging_query_cli.py -v
```
