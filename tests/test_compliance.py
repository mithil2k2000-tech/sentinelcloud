"""
Tests for agent/compliance.py — FR-8 (compliance framework mapping,
reference only per SR-6). Two tests here are the ones the SentinelCloud v1
spec's own §16 development-phase table names explicitly as required before
this feature counts as "done":

  1. every control_id emitted by the engine has a mapping entry
  2. the report renders the "reference only" label

Both are tested against REAL engine output from real fixtures (not a
hand-picked list of control_ids), plus a static source-scan so a future rule
that's never actually triggered by a fixture still can't slip in an
unmapped control_id unnoticed.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from compliance import (
    REFERENCE_ONLY_LABEL,
    control_ids_in_source,
    get_mapping,
    load_mappings,
    mapping_rows_for_json,
    render_mapping_table,
)
from threat_engine import Architecture, run_engine as run_threat_engine
from k8s_engine import K8sManifest, run_engine as run_k8s_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "agent"
ANALYZE_PY = AGENT_DIR / "analyze.py"
K8S_SCAN_PY = AGENT_DIR / "k8s_scan.py"


# ---------------------------------------------------------------------------
# load_mappings() — the file actually parses and has the shape we assume
# ---------------------------------------------------------------------------

def test_load_mappings_parses_and_is_nonempty():
    mappings = load_mappings()
    assert isinstance(mappings, dict)
    assert len(mappings) == 15  # 14 as of Phase 5 (FR-8) + DRIFT-001 added in Phase 7 (FR-9)


def test_every_mapping_entry_has_all_three_frameworks():
    mappings = load_mappings()
    for control_id, entry in mappings.items():
        assert "description" in entry, control_id
        for fw in ("cis_v8", "nist_csf_2", "pci_dss_v4"):
            assert fw in entry["frameworks"], f"{control_id} missing {fw}"
            assert entry["frameworks"][fw]["control"]
            assert entry["frameworks"][fw]["title"]


# ---------------------------------------------------------------------------
# Required test #1 — every control_id the engines actually emit is mapped.
# Two angles: real fixture output (what a user would actually see), and a
# static scan of every control_id="..." literal in the engine source (so an
# unmapped control_id in a rule that no current fixture happens to trigger
# still fails this test, not just the ones fixtures cover today).
# ---------------------------------------------------------------------------

def _control_ids_from_source(path: Path) -> set[str]:
    text = path.read_text()
    return set(re.findall(r'control_id="([^"]+)"', text))


def test_every_control_id_in_threat_engine_source_has_a_mapping():
    mappings = load_mappings()
    control_ids = _control_ids_from_source(AGENT_DIR / "threat_engine.py")
    assert control_ids, "regex found nothing — did threat_engine.py's control_id= literal syntax change?"
    missing = control_ids - set(mappings.keys())
    assert not missing, f"threat_engine.py emits control_id(s) with no mapping: {missing}"


def test_every_control_id_in_k8s_engine_source_has_a_mapping():
    mappings = load_mappings()
    control_ids = _control_ids_from_source(AGENT_DIR / "k8s_engine.py")
    assert control_ids, "regex found nothing — did k8s_engine.py's control_id= literal syntax change?"
    missing = control_ids - set(mappings.keys())
    assert not missing, f"k8s_engine.py emits control_id(s) with no mapping: {missing}"


def test_every_control_id_in_drift_source_has_a_mapping():
    """Phase 7 (drift detection). Most of drift.py's rules deliberately
    reuse an existing control_id from Phase 3/5 (see drift.py's own module
    docstring) — this test also implicitly confirms that reuse actually
    lines up with what's in the mapping file, not just that DRIFT-001
    (the one genuinely new control_id) is covered."""
    mappings = load_mappings()
    control_ids = _control_ids_from_source(AGENT_DIR / "drift.py")
    assert control_ids, "regex found nothing — did drift.py's control_id= literal syntax change?"
    missing = control_ids - set(mappings.keys())
    assert not missing, f"drift.py emits control_id(s) with no mapping: {missing}"
    assert "DRIFT-001" in control_ids  # sanity: the new control_id is actually emitted, not just declared in the YAML


def test_every_control_id_from_a_real_threat_engine_run_has_a_mapping():
    """architecture-proposed.json (pre-hardening) is the one fixture known to
    trigger every rule in threat_engine.ALL_RULES at once — see the
    docstring/history in docs/phase*.md. Confirmed by direct engine run, not
    assumed, that this yields all 6 distinct threat-engine control_ids."""
    arch = Architecture.from_file(REPO_ROOT / "threat-model" / "architecture-proposed.json")
    findings = run_threat_engine(arch)
    control_ids = {f.control_id for f in findings}
    assert control_ids == {"IAM-004", "NET-001", "DATA-002", "ZT-001", "NET-003", "LOG-001"}
    mappings = load_mappings()
    for cid in control_ids:
        assert get_mapping(cid, mappings) is not None, cid


def test_every_control_id_from_a_real_k8s_engine_run_has_a_mapping():
    """kubernetes/manifests/vulnerable/ is the fixture documented in
    docs/phase5-kubernetes.md as triggering all 8 K8s rules. Confirmed by
    direct engine run, not assumed."""
    manifest = K8sManifest.from_dir(REPO_ROOT / "kubernetes" / "manifests" / "vulnerable")
    findings = run_k8s_engine(manifest)
    control_ids = {f.control_id for f in findings}
    assert control_ids == {f"K8S-{i:03d}" for i in range(1, 9)}
    mappings = load_mappings()
    for cid in control_ids:
        assert get_mapping(cid, mappings) is not None, cid


def test_control_ids_in_source_is_the_same_utility_the_static_scan_tests_use_by_hand():
    """report_compliance.py (Phase 8) relies on this being a real,
    reusable function rather than the ad hoc regex the static-scan tests
    above inline — this pins that it returns the same set either way."""
    via_utility = control_ids_in_source(AGENT_DIR / "threat_engine.py")
    via_inline_regex = _control_ids_from_source(AGENT_DIR / "threat_engine.py")
    assert via_utility == via_inline_regex


def test_unmapped_control_id_renders_an_explicit_gap_not_a_silent_omission():
    table = render_mapping_table(["NOT-A-REAL-CONTROL-ID"], mappings=load_mappings())
    assert "NOT-A-REAL-CONTROL-ID" in table
    assert "NO MAPPING ON FILE" in table


# ---------------------------------------------------------------------------
# Required test #2 — the report always renders the "reference only" label.
# ---------------------------------------------------------------------------

def test_render_mapping_table_includes_reference_only_label():
    table = render_mapping_table(["IAM-004", "K8S-001"], mappings=load_mappings())
    assert REFERENCE_ONLY_LABEL in table
    assert "reference only, not a certification" in table


def test_render_mapping_table_includes_label_even_with_no_findings():
    """SR-6 applies whether or not there happen to be findings this run —
    the label isn't conditional on there being something to map."""
    table = render_mapping_table([], mappings=load_mappings())
    assert REFERENCE_ONLY_LABEL in table


def test_mapping_rows_for_json_always_marks_reference_only():
    rows = mapping_rows_for_json(["IAM-004", "NOT-A-REAL-CONTROL-ID"], mappings=load_mappings())
    assert len(rows) == 2
    for row in rows:
        assert row["reference_only"] is True
        assert row["label"] == REFERENCE_ONLY_LABEL
    mapped_row = next(r for r in rows if r["control_id"] == "IAM-004")
    assert mapped_row["mapped"] is True
    unmapped_row = next(r for r in rows if r["control_id"] == "NOT-A-REAL-CONTROL-ID")
    assert unmapped_row["mapped"] is False


def test_render_mapping_table_deduplicates_repeated_control_ids():
    """threat_engine.py's IAM-004 is reused by four different rule_ids
    (IAM-BROAD-01/02, IAM-MISSING-01, NET-SEGMENT-01) — a real run's finding
    list can repeat the same control_id several times; the table should
    describe it once, not four times."""
    table = render_mapping_table(["IAM-004", "IAM-004", "IAM-004"], mappings=load_mappings())
    assert table.count("IAM-004:") == 1


# ---------------------------------------------------------------------------
# CLI-level — --compliance is wired into both analyze.py and k8s_scan.py,
# purely additively (never changes the BLOCKED/ALLOWED decision).
# ---------------------------------------------------------------------------

def test_analyze_cli_compliance_flag_prints_label_and_preserves_decision():
    base = subprocess.run(
        [sys.executable, str(ANALYZE_PY), str(REPO_ROOT / "threat-model" / "architecture-proposed.json"), "--no-explain"],
        cwd=ANALYZE_PY.parent, capture_output=True, text=True,
    )
    with_flag = subprocess.run(
        [sys.executable, str(ANALYZE_PY), str(REPO_ROOT / "threat-model" / "architecture-proposed.json"), "--no-explain", "--compliance"],
        cwd=ANALYZE_PY.parent, capture_output=True, text=True,
    )
    assert with_flag.returncode == base.returncode
    assert "reference only, not a certification" in with_flag.stdout
    assert "reference only, not a certification" not in base.stdout


def test_analyze_cli_compliance_json_includes_compliance_array(tmp_path):
    out_file = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable, str(ANALYZE_PY),
            str(REPO_ROOT / "threat-model" / "architecture-proposed.json"),
            "--no-explain", "--compliance", "--json", str(out_file),
        ],
        cwd=ANALYZE_PY.parent, capture_output=True, text=True,
    )
    assert out_file.exists()
    import json
    payload = json.loads(out_file.read_text())
    assert "compliance" in payload
    assert all(row["reference_only"] is True for row in payload["compliance"])


def test_k8s_scan_cli_compliance_flag_prints_label_and_preserves_decision():
    manifests_dir = REPO_ROOT / "kubernetes" / "manifests" / "vulnerable"
    base = subprocess.run(
        [sys.executable, str(K8S_SCAN_PY), str(manifests_dir), "--no-explain"],
        cwd=K8S_SCAN_PY.parent, capture_output=True, text=True,
    )
    with_flag = subprocess.run(
        [sys.executable, str(K8S_SCAN_PY), str(manifests_dir), "--no-explain", "--compliance"],
        cwd=K8S_SCAN_PY.parent, capture_output=True, text=True,
    )
    assert with_flag.returncode == base.returncode
    assert "reference only, not a certification" in with_flag.stdout


def test_k8s_scan_cli_compliance_json_includes_compliance_array(tmp_path):
    out_file = tmp_path / "report.json"
    manifests_dir = REPO_ROOT / "kubernetes" / "manifests" / "vulnerable"
    result = subprocess.run(
        [
            sys.executable, str(K8S_SCAN_PY), str(manifests_dir),
            "--no-explain", "--compliance", "--json", str(out_file),
        ],
        cwd=K8S_SCAN_PY.parent, capture_output=True, text=True,
    )
    assert out_file.exists()
    import json
    payload = json.loads(out_file.read_text())
    assert "compliance" in payload
    assert len(payload["compliance"]) == 8  # 8 distinct K8S-* control_ids on the vulnerable set
