# CI/CD — the security gate

**File location note:** the device bridge used to write files to your
Desktop folder treats `.github/` as a protected path and refuses to write
into it directly, so the workflow file was committed to
`ci-cd/security-gate.yml` instead. Before this will actually run on
GitHub, move it:

```bash
mkdir -p .github/workflows
mv ci-cd/security-gate.yml .github/workflows/security-gate.yml
```

(or just drag it there in Explorer). Everything below describes the
workflow itself, which doesn't change.

---

`.github/workflows/security-gate.yml` runs on every push/PR that touches
`terraform/`, `threat-model/`, `kubernetes/`, `agent/`, `logging/`,
`demo/`, `tests/`, or `policy/`. Thirteen jobs:

1. **`unit-tests`** (Phase 2) — runs the `tests/` pytest suite (295 tests
   as of the dashboard deliverable: threat-, detection-, Kubernetes-, and
   drift-engine rule coverage, the SR-4a decision-neutrality guarantee for
   the `explain.py`/`triage.py` layers, the
   `analyze.py`/`detect.py`/`k8s_scan.py`/`drift_scan.py`
   aggregation/CLI behavior, `agent/compliance.py`'s framework-mapping
   lookup and reference-only labeling, real Kubernetes-manifest schema
   validation, `agent/report_compliance.py`'s audit-report rendering
   (including the required byte-for-byte snapshot test against
   `threat-model/audit-report-hardened.md`), `logging/log_store.py`'s
   local log-aggregation simulation plus `detect.py --store`'s
   purely-additive capture behavior, `agent/eval/benchmark.py`'s
   AI-narration grounding rubric over a real 38-item fixture set,
   (spec §16 table item 11) `tests/test_demo_scenarios.py`'s subprocess
   runs of all five `demo/scenario*.py` scripts plus `demo/run_all.py`,
   `tests/test_attack_sim.py`'s graph-reachability tests (including the
   real naive-vs-hardened 4-HIGH-vs-0-HIGH regression proof — see
   `docs/attack-simulation.md`), and `tests/test_dashboard.py`'s checks
   that every number `agent/dashboard.py` renders matches the real
   committed report files exactly (see `docs/dashboard.md`). All of
   `threat-model-gate`, `k8s-manifest-gate`, `detection-engine-demo`,
   `drift-detection-demo`, `compliance-audit-report`,
   `centralized-logging-demo`, `agent-eval-benchmark`, `demo-walkthrough`,
   `attack-simulation-demo`, and `dashboard-demo` declare
   `needs: unit-tests`, so a broken rule or a broken decision-neutrality
   guarantee fails CI before any architecture, manifest, log fixture,
   demo scenario, attack-path analysis, or dashboard render even gets
   run — see `docs/phase2-tests.md`, `docs/phase5-kubernetes.md`,
   `docs/phase9-siem-detection.md`, `docs/compliance-mapping.md`,
   `docs/drift-detection.md`, `docs/compliance-audit-report.md`,
   `docs/centralized-logging.md`, `docs/agent-eval-harness.md`,
   `docs/demo-scenarios.md`, `docs/attack-simulation.md`, and
   `docs/dashboard.md` for what the suite covers and why.

2. **`terraform-validate`** (3-cloud matrix, Phase 3) — `terraform fmt
   -check`, `terraform init -backend=false`, `terraform validate` against
   each of `terraform/azure`, `terraform/gcp`, `terraform/aws`. This
   sandbox can't reach `releases.hashicorp.com` to run this locally
   (egress policy), so every real GitHub Actions run is the first time
   each cloud's Terraform — including the new `modules/logging` added in
   Phase 9 — gets checked against actual provider schemas, not just HCL2
   syntax.

3. **`opa-policy-test`** (Phase 2) — `opa test policy/opa -v`, the
   centralized, cloud-agnostic policy layer (v1 spec §12 Layer B),
   independent of any one cloud's native policy engine. See
   `docs/phase2-opa-policy-layer.md`.

4. **`threat-model-gate`** (3-cloud matrix, Phase 3) — runs
   `agent/analyze.py` against all three clouds' hardened architectures
   (`architecture-hardened.json` / `-gcp.json` / `-aws.json`) as parallel
   matrix jobs, each failing independently if its result is BLOCKED at the
   configured threshold. `fail-fast: false` so one cloud's failure doesn't
   hide the others' results. Reports go to each job's summary and as a
   separately-named downloadable artifact (`threat-model-report-azure`,
   `-gcp`, `-aws`) either way, pass or fail.

5. **`k8s-manifest-gate`** (Phase 5) — runs `agent/k8s_scan.py` against
   `kubernetes/manifests/hardened` (the manifest set this project would
   actually deploy) and fails the build if the result is BLOCKED at the
   configured threshold — the same gate shape as `threat-model-gate`, one
   level down the stack. `kubernetes/manifests/vulnerable` is deliberately
   never run here; it's a demonstration/test fixture (`tests/test_k8s_engine.py`
   asserts its exact finding counts), never something CI would treat as a
   real deploy candidate. See `docs/phase5-kubernetes.md`.

6. **`detection-engine-demo`** (Phase 9, non-gating) — runs
   `agent/detect.py` against the synthetic `logs-multi-stage-incident.json`
   fixture and posts the report to the job summary. Always exits 0
   regardless of the INCIDENT/CLEAR result — detection is a retrospective
   question over log data, not a pre-deploy gate; see `agent/detect.py`'s
   own header comment and `docs/phase9-siem-detection.md`.

7. **`drift-detection-demo`** (Phase 7, non-gating) — runs
   `agent/drift_scan.py` against the fixed `architecture-hardened.json` /
   `architecture-drifted.json` snapshot pair and posts the report to the
   job summary. Always exits 0 — this sandbox has no live cloud account to
   read real "current" state from (SIMULATED mode, see `agent/drift.py`'s
   own module docstring), so this job compares two fixed fixtures on every
   run rather than re-checking a real environment; gating on that would
   prove nothing. See `docs/drift-detection.md`.

8. **`compliance-audit-report`** (Phase 8, non-gating) — runs
   `agent/report_compliance.py` against `architecture-hardened.json` with
   today's date (`--as-of "$(date -u +%Y-%m-%d)"`), writes both a Markdown
   report and a JSON companion as artifacts, and posts the raw Markdown
   directly into the job summary (unlike the other demo jobs' plain-text
   ` ``` ` blocks, this one is real Markdown and GitHub renders it
   natively). Always exits 0 — a report generator, not a gate; the real
   BLOCKED/ALLOWED call already happens in `threat-model-gate`, and this
   job never duplicates or overrides it. See
   `docs/compliance-audit-report.md`.

9. **`centralized-logging-demo`** (spec §16 table item 9, non-gating) —
   ingests the `logs-multi-stage-incident.json` fixture into a fresh local
   SQLite log store (`logging/log_store.py`) via `logging/query_cli.py`,
   then runs one demonstration query (`--principal k.doran --event-type
   iam_change`) against it and posts both to the job summary. Always exits
   0 — this module never makes a security decision at all (no
   `Finding`/`Alert`/BLOCKED/INCIDENT concept exists in it); it only
   exists to prove a captured event is queryable after the fact, which is
   the whole point of this phase. See `docs/centralized-logging.md`.

10. **`agent-eval-benchmark`** (spec §16 table item 10, FR-11) — runs
    `agent/eval/benchmark.py` against a real, 38-item fixture set derived
    from the same fixtures every other job already uses, and scores every
    `explain.py`/`triage.py` narration against a documented grounding
    rubric. Unlike jobs 6-9, **this job's exit code genuinely reflects its
    result** (pass rate below the documented threshold fails the job) —
    but it has no `needs:`/dependency relationship with
    `threat-model-gate` or `k8s-manifest-gate` in either direction, so a
    failing eval run can never affect a deployment decision (SR-4a); it
    only flags a human that the AI-explanation layer regressed. No
    `ANTHROPIC_API_KEY` secret is configured, so CI's run always scores
    the deterministic template fallback (a harness regression check, not
    a demonstration of real LLM quality) — see `docs/agent-eval-harness.md`.

11. **`demo-walkthrough`** (spec §16 table item 11, non-gating) — runs
    `demo/run_all.py`, which runs all five `demo/scenario*.py` scripts
    (spec §19) back to back, and posts the full narrated output to the
    job summary. Deliberately **not** a second correctness gate:
    `tests/test_demo_scenarios.py` already runs as part of job 1
    (`unit-tests`) and fails the build on a real demo regression — this
    job's only job is visibility. The five scenarios are written to be
    "shown to an interviewer/hiring panel" (§19's own framing), so every
    CI run leaves a readable, narrated walkthrough on the job summary
    tab, not just a pass/fail dot. Always exits 0. See
    `docs/demo-scenarios.md`.

12. **`attack-simulation-demo`** (portfolio deliverable, non-gating) —
    runs `agent/attack_sim.py`'s graph-reachability walk against both the
    naive proposal and the hardened Azure baseline, and posts both
    reports to the job summary. Deliberately **not** a gate: chain
    feasibility is derived entirely from the same `authenticated` field
    `threat-model-gate`'s own rules already read, so gating on it would
    be a second, redundant judgment over the same underlying facts — the
    same reasoning `report_compliance.py` already gives for staying
    non-gating. This is a read-only graph walk over `architecture.json`,
    never a live probe or exploit attempt. Always exits 0. See
    `docs/attack-simulation.md`.

13. **`dashboard-demo`** (portfolio deliverable, non-gating) — regenerates
    every other report this workflow produces (threat-model ×3,
    Kubernetes manifest gate, compliance audit, drift demo, detection
    demo, attack simulation ×2, agent-eval harness) inside its own job —
    GitHub Actions jobs don't share a filesystem, so this is a
    self-contained re-run, not a dependency on another job's artifacts —
    then renders `agent/dashboard.py`'s single-page HTML summary and
    posts the plain-text version to the job summary. Deliberately **not**
    a gate and **not** a live dashboard: every number on the page is
    copied verbatim from a report another, already-tested CLI already
    produced — this job contributes no new judgment of its own. Always
    exits 0. See `docs/dashboard.md`.

## Why the gate threshold is HIGH, not CRITICAL anymore

`analyze.py`'s own default (run by hand, no flags) blocks on **HIGH or
CRITICAL**. Until Phase 9, the CI workflow deliberately loosened that to
`--fail-on CRITICAL`, because every one of the three clouds' HIGH findings
at the time was `LOG-001` (no centralized logging, Phase 9 not built yet)
or `AUTHN-FLOW-01` (Zero Trust, Phase 4 not built yet) — real gaps, but
ones this pipeline couldn't fix by refusing to merge, so blocking every
merge on them would just have trained everyone to ignore the gate.

**Phase 9 closed the `LOG-001` half of that** (RR-01 in
`threat-model/residual-risk-register.md` — real logging infrastructure now
exists on all three clouds, see `docs/phase9-siem-detection.md`), so the
threshold was tightened to `--fail-on HIGH` as this doc always said it
would once that landed. The practical effect at the time, deliberately not
smoothed over: **Azure passed** (0 HIGH/CRITICAL findings left), but **GCP
and AWS correctly BLOCKED** — each still had one real, open HIGH finding
(`AUTHN-FLOW-01`: `account-service → secrets` with no application-layer
authentication, RR-03 in the register, target Phase 4/Zero Trust). That was
the gate doing its job, not a broken pipeline — a real gap that used to be
invisible under the looser threshold became visible and blocking, which is
the entire point of tightening it.

**Phase 4 (Zero Trust/mTLS) then closed that remaining HIGH finding** — a
mesh-wide STRICT Istio `PeerAuthentication` makes every service-to-service
flow mutually authenticated, and `account-service` got its own scoped
identity on all three clouds (closes RR-02, RR-03 for GCP/AWS, and RR-04;
see `docs/phase4-zero-trust.md`). Re-running `analyze.py` for real against
all three updated hardened architectures confirms it: **all three clouds
now pass at `--fail-on HIGH`** — Azure at MEDIUM 2 / HIGH 0, GCP and AWS
each at MEDIUM 1 / HIGH 0. This is the first point in the project where
every cloud passes the gate simultaneously.

**The plan is to keep tightening this over time**, not leave it here
permanently — but not yet:

- The only findings left anywhere are `NET-WAF-01` (RR-05, missing WAF,
  all three clouds) and `IAM-BROAD-02` (RR-06, Azure's `payment-service`
  role scoped to resource-group), both explicitly tracked as "Phase 1
  follow-up" work, not part of Zero Trust. Tightening `--fail-on` to
  `MEDIUM` right now would immediately re-block all three clouds on
  findings this phase was never meant to close, so the threshold is
  staying at `HIGH` until RR-05/RR-06 have their own fix, not because
  MEDIUM tightening was forgotten.
- The report artifact and job summary always show every finding regardless
  of the threshold, so nothing is actually hidden — the threshold only
  controls what blocks a merge, not what's visible.

## Getting this onto GitHub

This folder isn't pushed anywhere yet. From `cloud-security-platform/`, on
your own machine:

```bash
git init
git add .
git commit -m "Phase 1 Azure scaffold + Phase 3 threat-model agent + CI gate"
gh repo create cloud-security-platform --private --source=. --remote=origin
git push -u origin main
```

(`gh` is the GitHub CLI — `gh auth login` first if you haven't. Or create
the empty repo on github.com and `git remote add origin <url>` instead of
`gh repo create`.)

Once it's pushed, the workflow runs automatically on the next push or PR —
no extra setup needed unless you want `ANTHROPIC_API_KEY` set as a repo
secret for LLM-generated explanations in the job summary (optional; the
gate's pass/fail behavior is identical without it).
