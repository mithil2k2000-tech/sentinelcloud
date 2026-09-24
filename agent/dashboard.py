#!/usr/bin/env python3
"""
dashboard.py — a single-page security posture dashboard (portfolio
checklist item, not part of the SentinelCloud v1 spec's own §16 table).

WHAT THIS IS: a static HTML page that aggregates the JSON reports every
other CLI in this project already produces — analyze.py's per-cloud
threat-model reports, k8s_scan.py's manifest-gate report,
report_compliance.py's audit-style report, drift_scan.py's demo report,
detect.py's demo report, attack_sim.py's chain reports, and
eval/benchmark.py's harness result — into one page an engineer (or an
interviewer) can open and read in ten seconds, instead of running seven
different CLIs by hand.

WHAT THIS ISN'T: a live monitoring system. It reads whichever JSON report
files are already sitting in threat-model/ and kubernetes/manifests/ at
generation time — it never calls a cloud API, never polls anything, and
never refreshes itself. Every dashboard this module renders is a snapshot
of the last time each underlying CLI was run (locally, or by the CI
pipeline), and says so, with a timestamp, on the page itself. Treating a
static snapshot as if it were live data would be exactly the kind of
overclaim this project's SR-6 discipline exists to prevent elsewhere
(compliance labeling) — the same honesty applies here even though no
compliance framework is involved.

This module never re-derives a decision. Every number on the dashboard is
read straight out of a JSON file some other, already-tested CLI produced
— dashboard.py contributes zero new judgment about severity, feasibility,
or pass/fail. It is a rendering layer, nothing else. Like
report_compliance.py/attack_sim.py before it, its CLI always exits 0.
"""

from __future__ import annotations

import argparse
import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
THREAT_MODEL_DIR = REPO_ROOT / "threat-model"
K8S_DIR = REPO_ROOT / "kubernetes" / "manifests"

# Every source this module reads, and which section of the dashboard it
# feeds — kept as one explicit table so a missing file degrades gracefully
# (the section is shown as "no report found", not a crash) rather than
# assuming every report always exists.
REPORT_SOURCES = {
    "threat_model_azure": THREAT_MODEL_DIR / "report-hardened.json",
    "threat_model_gcp": THREAT_MODEL_DIR / "report-hardened-gcp.json",
    "threat_model_aws": THREAT_MODEL_DIR / "report-hardened-aws.json",
    "k8s_manifest_gate": K8S_DIR / "report-hardened.json",
    "compliance_audit": THREAT_MODEL_DIR / "report-compliance-audit.json",
    "drift_demo": THREAT_MODEL_DIR / "report-drift-demo.json",
    "detection_demo": THREAT_MODEL_DIR / "report-detection-demo.json",
    "attack_sim_proposed": THREAT_MODEL_DIR / "attack-chains-proposed.json",
    "attack_sim_hardened": THREAT_MODEL_DIR / "attack-chains-hardened.json",
    "agent_eval": THREAT_MODEL_DIR / "agent-eval-result.json",
}


@dataclass
class DashboardData:
    generated_at: str
    sources_found: dict = field(default_factory=dict)   # key -> path str
    sources_missing: list = field(default_factory=list)  # keys
    raw: dict = field(default_factory=dict)               # key -> parsed JSON


def load_reports(sources: dict[str, Path] = REPORT_SOURCES) -> DashboardData:
    """Deterministic: reads whatever JSON files exist right now, doesn't
    invent data for the ones that don't. Two runs against the same
    threat-model/ directory produce the same DashboardData every time."""
    data = DashboardData(generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    for key, path in sources.items():
        if path.exists():
            data.sources_found[key] = str(path)
            data.raw[key] = json.loads(path.read_text())
        else:
            data.sources_missing.append(key)
    return data


# ---------------------------------------------------------------------------
# Plain-text summary — CLI stdout and the CI job summary both use this.
# ---------------------------------------------------------------------------

def render_summary_table(data: DashboardData) -> str:
    lines = [f"# Security Posture Dashboard — generated {data.generated_at}", ""]
    lines.append("Snapshot only — not live monitoring. Every number below was read from a JSON report an earlier CLI run already produced; see docs/dashboard.md.")
    lines.append("")

    lines.append("## Cloud architecture threat-model gates")
    for cloud, key in (("Azure", "threat_model_azure"), ("GCP", "threat_model_gcp"), ("AWS", "threat_model_aws")):
        if key not in data.raw:
            lines.append(f"- {cloud}: no report found")
            continue
        s = data.raw[key]["summary"]
        lines.append(
            f"- {cloud}: {s['deployment']} "
            f"(CRITICAL={s['counts']['CRITICAL']} HIGH={s['counts']['HIGH']} "
            f"MEDIUM={s['counts']['MEDIUM']} LOW={s['counts']['LOW']}, --fail-on {s['fail_on']})"
        )
    lines.append("")

    lines.append("## Kubernetes manifest gate")
    if "k8s_manifest_gate" in data.raw:
        s = data.raw["k8s_manifest_gate"]["summary"]
        lines.append(
            f"- hardened manifest set: {s['deployment']} "
            f"(CRITICAL={s['counts']['CRITICAL']} HIGH={s['counts']['HIGH']} "
            f"MEDIUM={s['counts']['MEDIUM']} LOW={s['counts']['LOW']})"
        )
    else:
        lines.append("- no report found")
    lines.append("")

    lines.append("## Compliance audit report (reference only, not a certification)")
    if "compliance_audit" in data.raw:
        rows = data.raw["compliance_audit"]["rows"]
        passed = sum(1 for r in rows if r["status"] == "PASS")
        lines.append(f"- {passed}/{len(rows)} in-scope controls PASS (as of {data.raw['compliance_audit'].get('as_of', 'not specified')})")
    else:
        lines.append("- no report found")
    lines.append("")

    lines.append("## Attack path simulation (reachability analysis, not a penetration test)")
    for label, key in (("naive proposal", "attack_sim_proposed"), ("hardened baseline", "attack_sim_hardened")):
        if key not in data.raw:
            lines.append(f"- {label}: no report found")
            continue
        r = data.raw[key]
        lines.append(f"- {label}: {r['high_feasibility_count']}/{r['chain_count']} chains HIGH feasibility")
    lines.append("")

    lines.append("## Drift detection demo (fixed demo fixture, not a live re-check)")
    if "drift_demo" in data.raw:
        s = data.raw["drift_demo"]["summary"]
        lines.append(
            f"- baseline vs. drifted snapshot: {s['deployment']} "
            f"(CRITICAL={s['counts']['CRITICAL']} HIGH={s['counts']['HIGH']})"
        )
    else:
        lines.append("- no report found")
    lines.append("")

    lines.append("## Detection engine demo (synthetic multi-stage incident fixture)")
    if "detection_demo" in data.raw:
        s = data.raw["detection_demo"]["summary"]
        lines.append(f"- status: {s['status']} (CRITICAL={s['counts']['CRITICAL']} HIGH={s['counts']['HIGH']})")
    else:
        lines.append("- no report found")
    lines.append("")

    lines.append("## Agent evaluation harness (AI-narration grounding, not a live LLM quality score without ANTHROPIC_API_KEY)")
    if "agent_eval" in data.raw:
        e = data.raw["agent_eval"]
        lines.append(f"- pass rate {e['pass_rate']:.0%} (threshold {e['threshold']:.0%}) — {'MEETS' if e['meets_threshold'] else 'BELOW'} threshold, {e['passed']}/{e['total']} narrations")
    else:
        lines.append("- no report found")

    if data.sources_missing:
        lines.append("")
        lines.append(f"Missing reports (not yet generated in this checkout): {', '.join(sorted(data.sources_missing))}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML rendering — self-contained, no external CSS/JS, no network calls.
# ---------------------------------------------------------------------------

def _esc(s) -> str:
    return html.escape(str(s))


def _status_class(status: str) -> str:
    return {
        "ALLOWED": "ok", "PASS": "ok", "LOW": "ok",
        "BLOCKED": "bad", "FAIL": "bad", "HIGH": "bad", "INCIDENT": "bad",
    }.get(status, "neutral")


def render_html(data: DashboardData) -> str:
    sections = []

    # Threat-model gates
    rows = []
    for cloud, key in (("Azure", "threat_model_azure"), ("GCP", "threat_model_gcp"), ("AWS", "threat_model_aws")):
        if key not in data.raw:
            rows.append(f"<tr><td>{cloud}</td><td colspan='5' class='neutral'>no report found</td></tr>")
            continue
        s = data.raw[key]["summary"]
        rows.append(
            f"<tr><td>{cloud}</td>"
            f"<td class='{_status_class(s['deployment'])}'>{_esc(s['deployment'])}</td>"
            f"<td>{s['counts']['CRITICAL']}</td><td>{s['counts']['HIGH']}</td>"
            f"<td>{s['counts']['MEDIUM']}</td><td>{s['counts']['LOW']}</td></tr>"
        )
    sections.append(f"""
    <section>
      <h2>Cloud architecture threat-model gates</h2>
      <table><thead><tr><th>Cloud</th><th>Deployment</th><th>CRIT</th><th>HIGH</th><th>MED</th><th>LOW</th></tr></thead>
      <tbody>{"".join(rows)}</tbody></table>
    </section>""")

    # Kubernetes gate
    if "k8s_manifest_gate" in data.raw:
        s = data.raw["k8s_manifest_gate"]["summary"]
        k8s_html = (
            f"<p>Hardened manifest set: <span class='{_status_class(s['deployment'])}'>{_esc(s['deployment'])}</span> "
            f"(CRIT={s['counts']['CRITICAL']} HIGH={s['counts']['HIGH']} MED={s['counts']['MEDIUM']} LOW={s['counts']['LOW']})</p>"
        )
    else:
        k8s_html = "<p class='neutral'>no report found</p>"
    sections.append(f"<section><h2>Kubernetes manifest gate</h2>{k8s_html}</section>")

    # Compliance
    if "compliance_audit" in data.raw:
        c = data.raw["compliance_audit"]
        passed = sum(1 for r in c["rows"] if r["status"] == "PASS")
        compliance_html = (
            f"<p>{passed}/{len(c['rows'])} in-scope controls PASS "
            f"(as of {_esc(c.get('as_of', 'not specified'))}) "
            f"<em>{_esc(c.get('label', ''))}</em></p>"
        )
    else:
        compliance_html = "<p class='neutral'>no report found</p>"
    sections.append(f"<section><h2>Compliance audit report</h2>{compliance_html}</section>")

    # Attack simulation
    attack_rows = []
    for label, key in (("Naive proposal", "attack_sim_proposed"), ("Hardened baseline", "attack_sim_hardened")):
        if key not in data.raw:
            attack_rows.append(f"<tr><td>{label}</td><td colspan='2' class='neutral'>no report found</td></tr>")
            continue
        r = data.raw[key]
        cls = "bad" if r["high_feasibility_count"] > 0 else "ok"
        attack_rows.append(
            f"<tr><td>{label}</td><td class='{cls}'>{r['high_feasibility_count']}/{r['chain_count']} HIGH</td></tr>"
        )
    sections.append(f"""
    <section>
      <h2>Attack path simulation <small>(reachability analysis, not a penetration test)</small></h2>
      <table><tbody>{"".join(attack_rows)}</tbody></table>
    </section>""")

    # Drift demo
    if "drift_demo" in data.raw:
        s = data.raw["drift_demo"]["summary"]
        drift_html = (
            f"<p><span class='{_status_class(s['deployment'])}'>{_esc(s['deployment'])}</span> "
            f"(CRIT={s['counts']['CRITICAL']} HIGH={s['counts']['HIGH']}) — fixed demo fixture, not a live re-check</p>"
        )
    else:
        drift_html = "<p class='neutral'>no report found</p>"
    sections.append(f"<section><h2>Drift detection demo</h2>{drift_html}</section>")

    # Detection demo
    if "detection_demo" in data.raw:
        s = data.raw["detection_demo"]["summary"]
        detect_html = (
            f"<p><span class='{_status_class(s['status'])}'>{_esc(s['status'])}</span> "
            f"(CRIT={s['counts']['CRITICAL']} HIGH={s['counts']['HIGH']}) — synthetic multi-stage incident fixture</p>"
        )
    else:
        detect_html = "<p class='neutral'>no report found</p>"
    sections.append(f"<section><h2>Detection engine demo</h2>{detect_html}</section>")

    # Eval harness
    if "agent_eval" in data.raw:
        e = data.raw["agent_eval"]
        cls = "ok" if e["meets_threshold"] else "bad"
        eval_html = (
            f"<p><span class='{cls}'>{e['pass_rate']:.0%}</span> pass rate "
            f"(threshold {e['threshold']:.0%}, {e['passed']}/{e['total']} narrations) — "
            f"deterministic template fallback without ANTHROPIC_API_KEY, not a live LLM quality score</p>"
        )
    else:
        eval_html = "<p class='neutral'>no report found</p>"
    sections.append(f"<section><h2>Agent evaluation harness</h2>{eval_html}</section>")

    missing_note = ""
    if data.sources_missing:
        missing_note = f"<p class='neutral'>Missing reports (not yet generated in this checkout): {_esc(', '.join(sorted(data.sources_missing)))}</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelCloud — Security Posture Dashboard</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1b1b1b; background: #fff; }}
  h1 {{ font-size: 1.5rem; }}
  h2 {{ font-size: 1.1rem; border-bottom: 1px solid #ddd; padding-bottom: 0.3rem; margin-top: 2rem; }}
  h2 small {{ font-weight: normal; color: #666; font-size: 0.75rem; }}
  .banner {{ background: #fff3cd; border: 1px solid #997404; color: #664d03; padding: 0.75rem 1rem; border-radius: 4px; font-size: 0.9rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 0.5rem; }}
  th, td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }}
  th {{ background: #f7f7f7; }}
  .ok {{ color: #0f5132; font-weight: 600; }}
  .bad {{ color: #842029; font-weight: 600; }}
  .neutral {{ color: #666; font-style: italic; }}
  footer {{ margin-top: 2rem; font-size: 0.8rem; color: #888; }}
</style>
</head>
<body>
  <h1>SentinelCloud — Security Posture Dashboard</h1>
  <div class="banner">
    Snapshot only, not live monitoring. Every number on this page was read from a JSON report an earlier CLI run
    already produced (see docs/dashboard.md) — this page makes no new decision and reads nothing from a live cloud
    account. Generated {_esc(data.generated_at)}.
  </div>
  {"".join(sections)}
  {missing_note}
  <footer>SentinelCloud v1 — reference-only project for a fictional bank (Meridian Trust Bank). No compliance certification is implied by anything on this page (SR-6).</footer>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="dashboard.html", help="Path to write the HTML dashboard to")
    parser.add_argument("--no-html", action="store_true", help="Only print the plain-text summary, skip writing HTML")
    args = parser.parse_args(argv)

    data = load_reports()
    print(render_summary_table(data))

    if not args.no_html:
        Path(args.out).write_text(render_html(data))

    return 0  # rendering layer, never a gate — see module docstring


if __name__ == "__main__":
    import sys
    sys.exit(main())
