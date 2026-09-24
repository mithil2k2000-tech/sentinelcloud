"""
Tests for agent/dashboard.py — the security posture dashboard (a portfolio
checklist deliverable, not part of the SentinelCloud v1 spec's own §16
table). See dashboard.py's module docstring: this is a rendering layer
over JSON reports other, already-tested CLIs produce — it contributes no
new judgment about severity, feasibility, or pass/fail, so these tests
check that every number on the page matches the real committed report
files exactly, not that any new logic is "correct" (there isn't any new
logic to be correct or wrong about).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from dashboard import load_reports, render_summary_table, render_html, REPORT_SOURCES

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "agent"
DASHBOARD_PY = AGENT_DIR / "dashboard.py"


def test_load_reports_finds_every_committed_source():
    """Every source this module lists is a real, already-committed file in
    this repository — a genuine regression check that a future rename or
    move of one of those report files would be caught here."""
    data = load_reports()
    assert data.sources_missing == []
    assert set(data.sources_found.keys()) == set(REPORT_SOURCES.keys())


def test_summary_table_matches_real_committed_threat_model_reports():
    data = load_reports()
    table = render_summary_table(data)
    assert "Azure: ALLOWED" in table
    assert "GCP: ALLOWED" in table
    assert "AWS: ALLOWED" in table
    # Real, hand-verified counts as of this phase — see docs/phase4-zero-trust.md.
    assert "CRITICAL=0 HIGH=0 MEDIUM=2 LOW=0" in table  # Azure
    assert "CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0" in table  # GCP and AWS share this shape


def test_summary_table_matches_real_attack_sim_and_compliance_numbers():
    data = load_reports()
    table = render_summary_table(data)
    assert "naive proposal: 4/4 chains HIGH feasibility" in table
    assert "hardened baseline: 0/3 chains HIGH feasibility" in table
    assert "4/6 in-scope controls PASS" in table


def test_summary_table_matches_real_eval_harness_result():
    data = load_reports()
    table = render_summary_table(data)
    assert "38/38 narrations" in table
    assert "MEETS threshold" in table


def test_summary_table_never_claims_live_monitoring():
    data = load_reports()
    table = render_summary_table(data)
    assert "Snapshot only" in table
    assert "not live monitoring" in table.lower()  # the honest disclaimer itself
    for overclaim in ("real-time", "currently deployed", "live dashboard"):
        assert overclaim not in table.lower()


def test_missing_source_degrades_gracefully_instead_of_crashing(tmp_path):
    """A source file that doesn't exist yet must show up as 'no report
    found', never raise — this module reads whatever's actually there."""
    fake_sources = {"threat_model_azure": tmp_path / "does-not-exist.json"}
    data = load_reports(fake_sources)
    assert data.sources_missing == ["threat_model_azure"]
    table = render_summary_table(data)
    assert "no report found" in table
    html_out = render_html(data)
    assert "no report found" in html_out


def test_html_output_is_self_contained_with_no_external_requests():
    """No CDN, no external script/stylesheet, no live API — a snapshot
    page that renders correctly with zero network access, same cost/
    simplicity posture as every other output in this project."""
    data = load_reports()
    page = render_html(data)
    assert "<html" in page.lower()
    assert "http://" not in page
    assert "https://" not in page
    assert "<script" not in page.lower()  # no client-side logic at all — pure static markup


def test_html_output_never_omits_the_reference_only_compliance_label():
    data = load_reports()
    page = render_html(data)
    assert "reference only, not a certification" in page


def test_html_escapes_report_content():
    """Every string rendered into the page comes from a JSON file — even
    though every committed fixture is trusted, this guards against a
    future report containing characters that would break the markup."""
    from dashboard import DashboardData
    data = DashboardData(generated_at="2026-01-01 00:00 UTC")
    data.raw["threat_model_azure"] = {
        "summary": {
            "deployment": "<script>alert(1)</script>",
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "fail_on": "HIGH",
        }
    }
    page = render_html(data)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_cli_writes_html_and_prints_summary_and_exits_zero(tmp_path):
    out = tmp_path / "dashboard.html"
    result = subprocess.run(
        [sys.executable, str(DASHBOARD_PY), "--out", str(out)],
        cwd=AGENT_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "Security Posture Dashboard" in result.stdout
    assert out.exists()
    assert "<html" in out.read_text().lower()


def test_cli_never_writes_to_any_of_its_input_report_files():
    """Read-only, same guarantee as every other report/CLI in this
    project (drift_scan.py, attack_sim.py) — dashboard.py must not
    mutate the reports it reads."""
    before = {k: p.read_bytes() for k, p in REPORT_SOURCES.items()}
    subprocess.run(
        [sys.executable, str(DASHBOARD_PY), "--out", "/tmp/dashboard-readonly-check.html"],
        cwd=AGENT_DIR, capture_output=True, text=True,
    )
    after = {k: p.read_bytes() for k, p in REPORT_SOURCES.items()}
    assert before == after


def test_no_html_flag_skips_writing_the_file(tmp_path):
    out = tmp_path / "should-not-exist.html"
    result = subprocess.run(
        [sys.executable, str(DASHBOARD_PY), "--out", str(out), "--no-html"],
        cwd=AGENT_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert not out.exists()
