# Demonstration Scenarios (spec §16 table item 11, spec §19)

This is the closing phase of the SentinelCloud v1 spec's §16 development
table. It builds the five demonstration scenarios the spec's own §19
describes, packages them so they can be run end to end from a clean
checkout, and — per §22's Definition of Done, item 9 — re-reads the
specification document itself against the finished repository and
corrects anywhere it had drifted out of date.

## The spec's own text (§19, verbatim)

> Five scenarios, each runnable from a clean checkout with no cloud
> account, designed to be shown to an interviewer/hiring panel in under
> 10 minutes total — the actual portfolio artifact this whole
> specification serves.
>
> **Scenario 1 — Naive vs. hardened, side by side.** Run `analyze.py`
> against `architecture-proposed.json` (13 findings, 6 CRITICAL, BLOCKED)
> and then `architecture-hardened-azure.json` back to back — shows the
> engine actually discriminates between a bad design and a better one,
> with real numbers, not a scripted "pass" demo.
>
> **Scenario 2 — Same pattern, three clouds.** Run all three hardened
> architecture files through the same engine, unmodified, and show the
> reports are structurally identical in shape (same schema, same rule
> set) while surfacing real cloud-specific differences (Azure's
> resource-group-scoped role vs. GCP/AWS's resource-scoped roles) —
> demonstrates the cloud-agnostic governance-plane claim in §7
> concretely.
>
> **Scenario 3 — AI explanation degrades gracefully.** Run `analyze.py`
> once with `ANTHROPIC_API_KEY` set (real narrative explanations) and
> once with it unset (template fallback), showing the BLOCKED/ALLOWED
> decision and finding list are identical in both runs — the live
> version of the SR-4/Phase-2 decision-neutrality test, made visible
> rather than only asserted by a test file.
>
> **Scenario 4 — CI gate in action.** Push a change that reintroduces a
> fixed bug (e.g. an empty `thumbprint_list`) and show the GitHub
> Actions run failing the `threat-model-gate` job — demonstrates the
> gate is a real control, not a job that always passes.
>
> **Scenario 5 — A rule catches a real regression.** Deliberately remove
> `notification-service`'s (still-missing) identity binding requirement
> from a test fixture, show the corresponding unit test fail, then
> correctly restore it — demonstrates the test suite from §17 actually
> protects the engine's behavior, not just its ability to run without
> crashing.
>
> **Optional Scenario 6 (stretch, REAL CLOUD, §14) — One real apply.** If
> a personal free-tier account becomes available: `terraform plan` (and,
> if comfortable with the cost, `apply`) the Azure module set once, and
> re-run Scenario 1 against the real `terraform show` output translated
> into `architecture.json`, showing the SIMULATED and REAL CLOUD versions
> of the same architecture produce the same findings — the strongest
> possible evidence that the simulation was accurate, not just
> convenient. Explicitly optional; its absence does not make Scenarios
> 1–5 any less complete.

(Scenarios 1 and 5's spec text above is quoted as it reads *today*,
already corrected in place per the divergence write-up below — the spec
document itself was edited during this phase, not left to silently drift
out of date. Scenario 6 is explicitly optional and out of scope for this
phase; it needs a real cloud account this sandbox does not have.)

## What was built

- `demo/_lib.py` — shared helpers (`header`, `step`, `run`, `check`,
  `finish`). Every scenario script both narrates its walkthrough AND
  asserts, in code, that reality matches the narration: `check()` raises
  `AssertionError` (non-zero exit) the moment a real command's output
  stops matching what the script is claiming. A script that only printed
  canned text could silently drift out of sync with the actual codebase;
  these can't.
- `demo/scenario1_naive_vs_hardened.py` through
  `demo/scenario5_rule_catches_a_regression.py` — one script per
  scenario, each independently runnable.
- `demo/run_all.py` — runs all five in sequence with a combined
  pass/fail summary and total wall time.
- `demo/README.md` — index and walkthrough table for the `demo/`
  directory.
- `tests/test_demo_scenarios.py` — the spec's own required test for this
  phase ("Five demonstration scenarios (§19) run end-to-end from a clean
  checkout"): runs each script as a subprocess and asserts exit code 0.

## Two honest divergences found, and corrected in the spec itself

Before writing any script, this phase re-read the real current output of
every fixture §19 references (as the project's "verify before advancing"
discipline requires for every phase). Two of the spec's own literal §19
claims had gone stale since they were written — before Phase 4 (Zero
Trust) — and a third stale claim was found in §21 (Risks and
Limitations) while checking §22's Definition of Done:

1. **Scenario 1 — the hardened Azure baseline is now stronger than the
   spec predicted, not weaker.** The spec originally read "0 CRITICAL,
   still BLOCKED on real remaining HIGH findings." Phase 4's mesh-wide
   mTLS and scoped `account-service`/`payment-service` identities closed
   the last open HIGH finding on all three clouds. The real current
   result, confirmed by an actual run:

   ```
   $ python3 analyze.py threat-model/architecture-hardened.json --no-explain --fail-on HIGH
   CRITICAL: 0  HIGH: 0  MEDIUM: 2  LOW: 0
   Deployment: ✅ ALLOWED  (gate threshold: HIGH+)
   ```

2. **Scenario 5 — the workload with the still-missing identity binding
   is `notification-service`, not `account-service`.** The spec
   originally named `account-service`. Phase 4 gave `account-service` its
   own dedicated, resource-scoped identity on all three clouds (closing
   residual risks RR-02/RR-03/RR-04). Confirmed directly from the real,
   current `architecture-hardened.json`:

   ```json
   {"principal": "payment-service", "role": "IAM-004-payment-service-data-access", "scope": "resource-group"}
   {"principal": "account-service", "role": "IAM-004-account-service-secrets-access", "scope": "resource"}
   {"principal": "notification-service", "role": null, "scope": null}
   ```

   `notification-service` is the one entry with no role and no scope —
   the workload genuinely still missing an identity binding today.

3. **§21 (Risks and Limitations) — only one workload is deliberately
   incomplete, not two.** The spec's §21 originally read "Two workloads
   are deliberately, not accidentally, incomplete. `account-service` and
   `notification-service` have no identity binding..." — this was true
   when §21 was written, but is the same Phase-4 fact as above: only
   `notification-service` remains unbound today.

**How this was handled:** per this project's established pattern
(the same one used for the Kubernetes-schema-validation gap and the
centralized-logging numbering gap in earlier phases), the demo scripts
and this document use the real current state, not the spec's original
text. Beyond that, this phase went one step further because §22's
Definition of Done requires it explicitly (item 9: "This specification
document itself has been re-read against the finished repository at
least once, and any place where the build diverged from the plan ... is
reflected back into this document rather than left to silently drift out
of date.") — so the spec's own §19 and §21 text was edited in place, with
an inline `[Updated during Phase 11: ...]` note at each edit explaining
what changed and why, rather than silently rewriting history or leaving
the stale prose standing uncorrected.

## Honest limitations

- **Scenario 3** — this sandbox has no `ANTHROPIC_API_KEY` (the same
  cost-discipline stance held throughout this project — see
  `docs/agent-eval-harness.md`). Both runs the script performs use the
  same deterministic template fallback, so it cannot show real LLM prose
  actually diverging from the template. What it does show, for real,
  every time it runs: the BLOCKED/ALLOWED decision and the exact ordered
  finding list are byte-identical whether explanation is requested or
  not — the part of SR-4a that matters for a deployment decision.
  `tests/test_explain_fallback.py` is the mechanical proof this same
  guarantee holds with a real API key too.
- **Scenario 4** — this repo has not been pushed to GitHub yet (needs the
  user's own GitHub auth), so there is no live GitHub Actions run to
  watch turn red. The script runs the exact command `threat-model-gate`
  runs in CI, locally, against a throwaway temp-file copy of the hardened
  baseline with one previously-fixed regression reintroduced
  (`customer-storage.public_network_access` flipped back to `true`) — and
  asserts the real committed `architecture-hardened.json` was never
  touched. Once the repo is pushed, the true version of this scenario is
  the one-line spec text: make the same change on a branch, open a PR,
  and watch the job go red in the Actions tab.
- **Scenario 5** — mutates the real, committed `tests/test_threat_engine.py`
  file in place (there is no other way to make pytest observe a real
  failure and recovery of a real committed test), inside a `try/finally`
  that unconditionally restores the original content, followed by a
  byte-for-byte equality check and a final re-run confirming the restored
  test passes again. Verified independently outside the script itself
  (an `md5sum`/`diff` taken before and after the run) before this phase
  was considered complete.

## Real verification performed this phase

All five scenario scripts, and `run_all.py`, were run for real — not
assumed — before this phase was reported done:

- Scenarios 1–4 each passed on their first real run, with every
  assertion in each script grounded in a real command's actual output
  captured beforehand.
- Scenario 5's previously-unverified assumption — that pytest's real
  failure output contains the literal substring `AssertionError` — was
  checked against a real pytest run and confirmed true (pytest's default
  `-v` output for an `assert list(...) == []` failure includes a full
  `AssertionError` traceback line).
- `run_all.py` ran all five scenarios back to back for real: total wall
  time 1.58s (the spec's own "under 10 minutes" framing is about a human
  presenter walking through the narration, not the scripts' own runtime).
- The real repository file `tests/test_threat_engine.py` was confirmed
  byte-identical to its pre-run state via an independent `diff`/`md5sum`
  check outside the demo script's own internal restoration check.
