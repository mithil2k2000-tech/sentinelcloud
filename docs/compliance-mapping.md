# Compliance framework mapping (FR-8)

Status: **built, tested, and run for real**. 15 new tests when this phase
was built (160 total at the time), plus one further entry and one further
test added when Phase 7 (drift detection) extended this file — see
"Extended in Phase 7" below. Current totals live in `docs/ci-cd.md`.

**A note on which "phase" this is.** The SentinelCloud v1 spec's own §16
development-phase table lists this as item 5 ("Compliance mapping"), but
one paragraph elsewhere in the same spec calls it "Phase 8" and this
session's informal `claude/roadmap.md` uses a third, thematic numbering
scheme entirely. Rather than trying to reconcile three inconsistent
numbering schemes retroactively, this doc just names the feature
(compliance mapping) and cites FR-8/SR-6 directly, and was built because
it was the earliest not-yet-done item in the spec's own §16 table — see
that table for the authoritative "what's next" ordering if the numbering
ever needs reconciling.

## REFERENCE ONLY, NOT A CERTIFICATION — this is the whole point of the feature

Per SR-6 in the v1 spec ("No False Compliance Claims") and FR-8's own text
("...for reference only — explicitly labeled as a mapping for engineering
traceability, never presented or claimed as a certification or audit
result"), every piece of this feature exists to make one thing traceable
— *which* internal control an engineer means when they say "IAM-004" —
without ever implying an audit happened. Concretely:

- `policy/framework-mappings.yaml`'s own header comment states this
  explicitly, in the first paragraph, before any mapping data.
- `agent/compliance.py`'s `render_mapping_table()` — the one function
  every consumer is expected to call — hard-codes the literal string
  `(reference only, not a certification)` into its own output. There is
  no code path that renders a mapping without it.
- `tests/test_compliance.py::test_render_mapping_table_includes_reference_only_label`
  and `::test_render_mapping_table_includes_label_even_with_no_findings`
  check this directly, not just trust the docstring — the second one
  specifically because the label needs to appear whether or not there
  happen to be findings this run.
- Meridian Trust Bank (the fictional reference customer) is never claimed
  to be CIS/NIST/PCI-compliant anywhere in this project. This file maps
  *SentinelCloud's own internal controls* to *where a human reader could
  go look up the closest real-framework language* — nothing more.

## What was built

1. **`policy/framework-mappings.yaml`** — 14 entries, one per distinct
   `control_id` emitted across `threat_engine.py` (`IAM-004`, `NET-001`,
   `DATA-002`, `ZT-001`, `NET-003`, `LOG-001`) and `k8s_engine.py`
   (`K8S-001` through `K8S-008`). Each entry has a plain-English
   `description` and, per framework, a `control` id and `title` for:
   - **CIS Controls v8** — free to read, no paid membership required.
   - **NIST CSF 2.0** — likewise free, and named explicitly in the spec's
     own FR-8 text as an example framework.
   - **PCI DSS v4.0** — added because Meridian Trust Bank is explicitly a
     bank handling payment card flows through `payment-service`; PCI DSS
     is the one framework here with actual jurisdiction over that data.

2. **`agent/compliance.py`** — `load_mappings()` (parses the YAML file),
   `get_mapping(control_id)` (single lookup), `render_mapping_table()`
   (the human-readable, always-labeled table used by both CLIs), and
   `mapping_rows_for_json()` (the same data shaped for `--json` output,
   with `reference_only: true` and the label repeated on every row so
   the JSON is self-describing even read in isolation from the printed
   report).

3. **`--compliance`** wired into both `agent/analyze.py` and
   `agent/k8s_scan.py`, following the exact same purely-additive pattern
   `--risk-model` already established in Phase 4: it never changes which
   findings exist or the BLOCKED/ALLOWED decision, it only adds an extra
   printed table (and, with `--json`, an extra `compliance` array in the
   report). Confirmed by running both CLIs with and without the flag
   against the same architecture/manifest and diffing the exit code and
   decision line — identical either way.

## Scoping decision: `detection_engine.py`'s alerts are explicitly excluded

`detect.py` has no `--compliance` flag and isn't getting one. Its `Alert`
dataclass (Phase 9) deliberately has no `control_id` field at all — a
detected alert is a retrospective claim about events that already
happened (`docs/phase9-siem-detection.md`'s "why two engines" section
covers this distinction in full), not a design-time control with a
framework mapping. There's nothing to map an `Alert` to, so rather than
inventing a fake mapping to force symmetry with the other two CLIs, this
feature stays scoped to `threat_engine.py` and `k8s_engine.py`'s
`Finding`-based control_ids only.

## The actual, verified result

Ran for real, not hand-derived:

```
$ python3 agent/analyze.py threat-model/architecture-proposed.json --no-explain --compliance
```

prints all 13 findings, then a compliance table for the 6 distinct
`control_id`s that fired (`IAM-004`, `NET-001`, `DATA-002`, `LOG-001`,
`ZT-001`, `NET-003`), each with its CIS/NIST/PCI mapping and the
reference-only label. Re-ran all four hardened architectures/manifest
sets with `--compliance --json` to regenerate
`threat-model/report-hardened*.json` and
`kubernetes/manifests/report-hardened.json` with the new `compliance`
array included — decisions unchanged (Azure MEDIUM/ALLOWED with 2
findings, GCP and AWS MEDIUM/ALLOWED with 1 finding each — `NET-003`/
NET-WAF-01 in all three cases — and the hardened Kubernetes manifest set
still at NONE/ALLOWED with nothing to map).

## Two required tests, both against real engine output, not a hand-picked list

The spec's own §16 table names two tests as required before this feature
counts as "done." Both exist in `tests/test_compliance.py`:

1. **"Test that every `control_id` emitted by the engine has a mapping
   entry."** Done four ways, not one:
   - `test_every_control_id_from_a_real_threat_engine_run_has_a_mapping`
     — runs `threat_engine.run_engine()` against the real
     `architecture-proposed.json` fixture (documented as triggering all
     8 rules at once) and checks every resulting `control_id` against
     the mapping file.
   - `test_every_control_id_from_a_real_k8s_engine_run_has_a_mapping` —
     same, against `kubernetes/manifests/vulnerable/` (documented in
     `docs/phase5-kubernetes.md` as triggering all 8 K8s rules).
   - `test_every_control_id_in_threat_engine_source_has_a_mapping` and
     `test_every_control_id_in_k8s_engine_source_has_a_mapping` — a
     static regex scan of every literal `control_id="..."` in both
     engine source files, so a future rule that no current fixture
     happens to trigger still can't add an unmapped `control_id` without
     failing this test. This is stricter than "run the two engines and
     check the output" alone.
2. **"Test that the report renders the 'reference only' label."** —
   `test_render_mapping_table_includes_reference_only_label` and
   `test_render_mapping_table_includes_label_even_with_no_findings`
   (the label must appear even when there's nothing to map), plus
   `test_mapping_rows_for_json_always_marks_reference_only` for the
   `--json` path specifically.

Fifteen tests in total (`test_compliance.py`), including CLI-level checks
that `--compliance` doesn't change the BLOCKED/ALLOWED decision, a
dedup check (four different `rule_id`s in `threat_engine.py` all share
`control_id="IAM-004"` — the table describes it once, not four times),
and an explicit-gap check (an unmapped `control_id` renders as
`NO MAPPING ON FILE`, never silently disappears from the table).

## Extended in Phase 7 (drift detection, FR-9)

`agent/drift.py`'s rules reuse six of this file's existing control_ids
directly (the control a drifted resource now violates is the same one
`threat_engine.py` would have flagged had it been provisioned that way
from the start) — zero new mapping work needed for those. Two rules
(`rule_asset_added`/`rule_asset_removed`, "a resource appeared or
disappeared between snapshots") have no design-time equivalent to reuse,
so one genuinely new entry, `DRIFT-001`, was added — 15 entries total as
of Phase 7, up from 14. See `docs/drift-detection.md` for the full
reasoning and `test_every_control_id_in_drift_source_has_a_mapping` in
`tests/test_compliance.py` for the same static-source-scan guarantee this
doc's "Two required tests" section describes, now also covering
`agent/drift.py`.

## Honest limitations

- **The mappings were hand-selected, not machine-generated or reviewed
  by a compliance professional.** `policy/framework-mappings.yaml`'s own
  header comment says this directly. A real audit might map some of
  these controls differently, or map one internal control to multiple
  framework clauses where this file picked one. This file is a
  traceability aid for engineers, not a substitute for an actual
  compliance review.
- **Kubernetes controls map to general language, not container-specific
  clauses.** None of CIS Controls v8, NIST CSF 2.0, or PCI DSS v4.0 has
  first-class Kubernetes/container controls (that's the domain of
  frameworks like the CIS Kubernetes Benchmark, which isn't one of the
  three chosen here), so `K8S-001` through `K8S-008` all map to each
  framework's general secure-configuration or access-control language
  instead. That's a real gap in specificity, not a bug — flagged in the
  YAML file's own header comment.
- **`K8S-007` (missing resource limits) is the weakest mapping in the
  file.** Missing CPU/memory limits is fundamentally an availability/DoS
  concern, and none of these three frameworks has a strong
  availability-specific control that fits — it maps to the same generic
  "configuration management" language as several other, better-fitting
  K8s controls (`K8S-001`, `K8S-002`, `K8S-004`) purely because there's
  nothing more specific to point to. This is called out explicitly in
  both the YAML file's `K8S-007` entry and here, rather than papering
  over it with a mapping that reads more confident than it is.
- **No mechanism cross-checks these framework control numbers against
  the actual published framework text.** The `control` and `title`
  fields were typed by hand from each framework's public documentation
  at the time this was written; if CIS, NIST, or PCI SSC ever renumber
  or revise the referenced controls, nothing here would catch that
  drift automatically.
- **This isn't wired into CI.** Following the same precedent
  `--risk-model` already set (also not run in
  `.github/workflows/security-gate.yml`), `--compliance` is an opt-in,
  purely-additive CLI flag a human runs by choice — it was deliberately
  not added to the CI gate jobs, since the gate's job is the
  BLOCKED/ALLOWED decision and this flag, by design, never changes it.

## Running it yourself

```bash
cd agent
python3 analyze.py ../threat-model/architecture-proposed.json --no-explain --compliance
python3 k8s_scan.py ../kubernetes/manifests/vulnerable --no-explain --compliance
python3 -m pytest ../tests/test_compliance.py -v
```

## Next steps for this piece

1. Have the mappings reviewed by someone with actual compliance/audit
   experience — this file is honest about being hand-built by an
   engineer, not a substitute for that review.
2. Consider adding the CIS Kubernetes Benchmark as a fourth framework
   specifically for `K8S-*` control_ids, closing the "maps to general
   language" gap noted above with a framework that actually has
   container-specific controls.
3. A machine-readable cross-check against each framework's own published
   control catalog (where one exists in a parseable format) to catch
   control-number drift automatically instead of relying on this file
   staying manually up to date.
