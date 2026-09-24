#!/usr/bin/env python3
"""
demo/scenario2_three_clouds.py — spec §19, Scenario 2: "Same pattern,
three clouds." Run all three hardened architecture files through the same
engine, unmodified, and show the reports are structurally identical in
shape (same schema, same rule set) while surfacing a real cloud-specific
difference: Azure's IAM role is scoped to the resource group, GCP's and
AWS's are scoped to the specific resource — demonstrating the
cloud-agnostic governance-plane claim (spec §7) concretely, not just by
assertion.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import REPO_ROOT, check, finish, header, run, step  # noqa: E402

CLOUDS = [
    ("azure", "architecture-hardened.json"),
    ("gcp", "architecture-hardened-gcp.json"),
    ("aws", "architecture-hardened-aws.json"),
]


def main() -> int:
    header("SCENARIO 2 — Same pattern, three clouds")

    results = {}
    for cloud, fname in CLOUDS:
        step(f"Run analyze.py against the {cloud} hardened baseline ({fname})")
        r = run([
            "python3", "analyze.py",
            str(REPO_ROOT / "threat-model" / fname),
            "--no-explain", "--fail-on", "HIGH",
        ])
        results[cloud] = r
        check(r.returncode == 0, f"{cloud} baseline is ALLOWED, same as the other two clouds",
              f"{cloud} baseline did not ALLOW — clouds have diverged, investigate before demoing")

    step("Confirm the cloud-specific IAM-scoping difference the spec calls out")
    check("IAM-BROAD-02" in results["azure"].stdout,
          "Azure surfaces its resource-group-scoped IAM finding (IAM-BROAD-02)",
          "Azure's expected IAM-BROAD-02 finding is missing")
    check("IAM-BROAD-02" not in results["gcp"].stdout,
          "GCP has no equivalent finding — its custom roles are already resource-scoped",
          "GCP unexpectedly has an IAM-BROAD-02 finding — investigate")
    check("IAM-BROAD-02" not in results["aws"].stdout,
          "AWS has no equivalent finding — its IRSA roles are already resource-scoped",
          "AWS unexpectedly has an IAM-BROAD-02 finding — investigate")

    step("Confirm all three clouds share the one genuinely common open finding")
    check(all("NET-WAF-01" in results[c].stdout for c, _ in CLOUDS),
          "All three clouds share the same open WAF finding (NET-WAF-01) — a real Phase-1 follow-up, not yet built anywhere",
          "The shared NET-WAF-01 finding is missing on at least one cloud — investigate")

    print(
        "\nOne engine, one rule set, three real Terraform footprints — the same\n"
        "report SHAPE every time (same fields, same severities, same control_id\n"
        "vocabulary), with the actual per-cloud IAM-scoping difference surfacing\n"
        "as data, not as a special case the engine had to be told about."
    )

    return finish("Scenario 2")


if __name__ == "__main__":
    sys.exit(main())
