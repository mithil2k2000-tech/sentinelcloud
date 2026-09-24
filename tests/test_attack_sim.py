"""
Tests for agent/attack_sim.py — attack path simulation (a portfolio
checklist deliverable, not part of the SentinelCloud v1 spec's own §16
table). See attack_sim.py's module docstring for what this is and isn't:
a read-only graph-reachability walk over architecture.json's own `flows`,
never a live probe, exploit, or credential-theft tool.

Every count below was taken from a real run of the tool against the real
committed fixtures before being hardcoded here (not derived by reading the
code and guessing) — the same "verify before asserting" discipline used
throughout this project. In particular, the hardened-vs-proposed contrast
(4/4 HIGH -> 3/0 HIGH) is an independent, second confirmation — via a
completely different analysis (graph reachability, not STRIDE rules) —
that Phase 4's mesh-wide mTLS/auth work closed every previously-open path
from the internet edge to sensitive data, not just the specific findings
threat_engine.py already flagged.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from threat_engine import Architecture
from attack_sim import (
    REFERENCE_ONLY_LABEL,
    find_attack_chains,
    render_report,
    narrate_chain,
    _entry_points,
    _sensitive_targets,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "agent"
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"
ATTACK_SIM_PY = AGENT_DIR / "attack_sim.py"

PROPOSED = THREAT_MODEL_DIR / "architecture-proposed.json"
HARDENED = THREAT_MODEL_DIR / "architecture-hardened.json"
HARDENED_GCP = THREAT_MODEL_DIR / "architecture-hardened-gcp.json"
HARDENED_AWS = THREAT_MODEL_DIR / "architecture-hardened-aws.json"
DRIFTED = THREAT_MODEL_DIR / "architecture-drifted.json"


def _load(path: Path) -> Architecture:
    return Architecture.from_file(path)


# ---------------------------------------------------------------------------
# Entry points / targets — the two graph endpoints this module derives
# straight from architecture.json's own flow list, no hardcoded asset IDs.
# ---------------------------------------------------------------------------

def test_entry_points_are_sources_that_are_never_a_destination():
    arch = _load(HARDENED)
    entries = _entry_points(arch)
    assert entries == ["mobile-app"]
    # api-gateway is a source too, but it's also a destination (mobile-app -> api-gateway) — not an entry point.
    assert "api-gateway" not in entries


def test_sensitive_targets_match_threat_engines_own_sensitive_types():
    arch = _load(HARDENED)
    targets = set(_sensitive_targets(arch))
    assert targets == {"key-vault", "customer-storage"}


# ---------------------------------------------------------------------------
# The core regression proof: naive proposal has real broken chains,
# hardened architecture (all three clouds) has none.
# ---------------------------------------------------------------------------

def test_proposed_architecture_has_four_high_feasibility_chains():
    arch = _load(PROPOSED)
    chains = find_attack_chains(arch)
    assert len(chains) == 4
    assert all(c.feasibility == "HIGH" for c in chains)
    assert all(c.broken_hop_count >= 1 for c in chains)
    targets = {c.target for c in chains}
    assert targets == {"customer-db", "customer-storage"}


def test_proposed_broken_hop_is_always_the_gateway_to_service_edge():
    """Every chain in the naive proposal breaks at exactly the same place
    — api-gateway had no authentication requirement to any of the three
    services — which is exactly the gap Phase 4's mTLS work closed."""
    arch = _load(PROPOSED)
    for chain in find_attack_chains(arch):
        broken = [h for h in chain.hops if not h["authenticated"]]
        assert len(broken) == 1
        assert broken[0]["from"] == "api-gateway"


def test_hardened_azure_architecture_has_zero_high_feasibility_chains():
    arch = _load(HARDENED)
    chains = find_attack_chains(arch)
    assert len(chains) == 3
    assert all(c.feasibility == "LOW" for c in chains)
    assert all(c.broken_hop_count == 0 for c in chains)


def test_hardened_gcp_and_aws_also_have_zero_high_feasibility_chains():
    for fixture in (HARDENED_GCP, HARDENED_AWS):
        arch = _load(fixture)
        chains = find_attack_chains(arch)
        assert len(chains) == 3
        assert all(c.feasibility == "LOW" for c in chains), fixture


def test_drifted_fixture_shows_exactly_the_one_chain_drift_reopened():
    """Independent cross-check of the drift-detection demo fixture from a
    completely different angle: architecture-drifted.json's ZT-001-style
    identity/auth drift (see docs/drift-detection.md) shows up here too,
    as exactly one chain flipping from LOW back to HIGH — not discovered
    by reading drift.py's rules, but by this module's own graph walk."""
    arch = _load(DRIFTED)
    chains = find_attack_chains(arch)
    assert len(chains) == 3
    high = [c for c in chains if c.feasibility == "HIGH"]
    low = [c for c in chains if c.feasibility == "LOW"]
    assert len(high) == 1
    assert len(low) == 2
    assert high[0].target == "key-vault"
    assert high[0].entry == "mobile-app"


# ---------------------------------------------------------------------------
# Report rendering — the honesty label must always be present, including
# the zero-chain edge case, and narration must never claim exploitation.
# ---------------------------------------------------------------------------

def test_reference_only_label_present_even_with_zero_chains():
    empty_arch = Architecture({"name": "empty", "assets": [], "flows": []})
    report = render_report(find_attack_chains(empty_arch), empty_arch.name)
    assert REFERENCE_ONLY_LABEL in report
    assert "No path" in report


def test_reference_only_label_present_in_populated_report():
    arch = _load(PROPOSED)
    report = render_report(find_attack_chains(arch), arch.name)
    assert REFERENCE_ONLY_LABEL in report
    assert "CHAIN-01" in report


def test_narrate_chain_template_fallback_never_claims_a_confirmed_breach():
    """No ANTHROPIC_API_KEY in this sandbox, so this always exercises the
    deterministic template — same fallback guarantee as explain.py's and
    triage.py's own template paths."""
    arch = _load(PROPOSED)
    chain = find_attack_chains(arch)[0]
    narrative = narrate_chain(chain)
    assert REFERENCE_ONLY_LABEL in narrative
    for overclaim in ("confirmed", "exploited", "breach occurred", "was hacked"):
        assert overclaim not in narrative.lower()


# ---------------------------------------------------------------------------
# CLI — always exits 0 (report, not a gate), same as drift_scan.py and
# report_compliance.py, even when HIGH-feasibility chains are present.
# ---------------------------------------------------------------------------

def test_cli_exits_zero_even_with_high_feasibility_chains_present():
    result = subprocess.run(
        [sys.executable, str(ATTACK_SIM_PY), str(PROPOSED), "--no-explain"],
        cwd=AGENT_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "HIGH" in result.stdout
    assert REFERENCE_ONLY_LABEL in result.stdout


def test_cli_exits_zero_on_fully_authenticated_hardened_architecture():
    result = subprocess.run(
        [sys.executable, str(ATTACK_SIM_PY), str(HARDENED), "--no-explain"],
        cwd=AGENT_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "0 HIGH feasibility" in result.stdout


def test_cli_json_export_matches_in_process_result(tmp_path):
    out = tmp_path / "chains.json"
    result = subprocess.run(
        [sys.executable, str(ATTACK_SIM_PY), str(HARDENED), "--no-explain", "--json", str(out)],
        cwd=AGENT_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0
    payload = json.loads(out.read_text())
    assert payload["label"] == REFERENCE_ONLY_LABEL
    assert payload["chain_count"] == 3
    assert payload["high_feasibility_count"] == 0
    assert len(payload["chains"]) == 3
    assert {c["target"] for c in payload["chains"]} == {"key-vault", "customer-storage"}


def test_cli_never_writes_to_its_input_architecture_file(tmp_path):
    """Read-only, same guarantee as drift_scan.py's own test for baseline/
    current — this module reads architecture.json, it never writes one."""
    fixture_copy = tmp_path / "architecture-hardened.json"
    fixture_copy.write_bytes(HARDENED.read_bytes())
    before = fixture_copy.read_bytes()
    subprocess.run(
        [sys.executable, str(ATTACK_SIM_PY), str(fixture_copy), "--no-explain"],
        cwd=AGENT_DIR, capture_output=True, text=True,
    )
    after = fixture_copy.read_bytes()
    assert before == after
