# Attack Path Simulation

A portfolio-checklist deliverable — not part of the SentinelCloud v1 spec's own §16 development table, named without a roadmap phase number the same way Compliance Mapping/Audit Reporting/Centralized Logging/Agent Evaluation Harness are (see `claude/roadmap.md`'s numbering note).

## What this is, and — just as importantly — what it isn't

`agent/attack_sim.py` walks `architecture.json`'s own `flows` list as a directed graph and asks one narrow question: starting from every true entry point (an asset that is the source of a flow but never the destination of one — in every fixture in this repo, that's `mobile-app`), is there a path to an asset holding sensitive data (a `database`, `storage`, or `secret-store` type asset — the exact same `SENSITIVE_TYPES` set `agent/threat_engine.py`'s own rules already use), and does every hop on that path require authentication?

It is **not** a penetration test. It never opens a socket, sends a request, or touches anything outside the JSON file it's given. It is **not** a new source of findings — every signal it reads (the `authenticated` field on each flow) is the same field `threat_engine.py`'s own rules already read; this module recombines that data across multiple hops rather than discovering anything new about a single asset. And it is **not** a certification or a proof of exploitability: a "HIGH feasibility" chain means the flow graph contains at least one unauthenticated hop on a path that reaches sensitive data — nothing about whether that hop is reachable at runtime, whether an attacker could actually traverse it, or whether any control outside this JSON file (a WAF, a network ACL, a runtime admission controller) would stop them. Every report this module renders carries an explicit label saying so: `(reachability analysis only — not a penetration test or proof of exploitability)`.

This project has a standing constraint against any malware, credential-theft, or destructive attack tooling. Nothing here comes close to that line — there is no payload, no target beyond a local JSON file, and no code path that could reach a real system even by accident.

## Why a chain isn't a `Finding`

`threat_engine.py`'s `Finding` dataclass is a claim about *one* asset (or one identity binding) being misconfigured. An attack chain is a claim about *reachability across several assets* — a different shape of claim, the same reasoning that already kept `detection_engine.py`'s `Alert` (a retrospective claim about log events) as its own dataclass rather than forcing it into `Finding`'s shape. `attack_sim.py` defines its own `AttackChain` dataclass rather than reusing `Finding`, and deliberately never emits a `Finding` — creating one would risk double-counting the exact same `authenticated: false` fact `threat_engine.py`'s own rules (or, on the naive proposal, the equivalent Kubernetes/architecture rules) already flag independently.

## Report, not a gate

Like `agent/drift_scan.py` and `agent/report_compliance.py` before it, `attack_sim.py`'s CLI always exits 0. Chain feasibility is derived entirely from data `threat-model-gate` already reads and already enforces a decision on — gating a second time on a re-derived view of the same facts would create two sources of truth for one question, exactly the reasoning `report_compliance.py`'s own module docstring already gives for staying non-gating. CI's twelfth job, `attack-simulation-demo`, posts the full reachability report to the job summary on every run, purely for visibility.

## Real results, run for real

Every number below came from an actual run of the tool against the real committed architecture fixtures, not from reading the code and predicting an outcome:

| Fixture | Chains found | HIGH feasibility | LOW feasibility |
|---|---|---|---|
| `architecture-proposed.json` (naive, pre-Phase-4) | 4 | 4 | 0 |
| `architecture-hardened.json` (Azure) | 3 | 0 | 3 |
| `architecture-hardened-gcp.json` | 3 | 0 | 3 |
| `architecture-hardened-aws.json` | 3 | 0 | 3 |
| `architecture-drifted.json` (Phase 7 drift-demo fixture) | 3 | 1 | 2 |

The naive-vs-hardened contrast (4/4 HIGH → 3/0 HIGH) is a second, independent confirmation of Phase 4's Zero Trust work — arrived at through graph reachability, a completely different analysis from the STRIDE rules `threat_engine.py` already runs — that closing the gateway's unauthenticated flows to every service didn't just silence individual findings, it closed every path from the internet edge to sensitive data. All four broken chains in the naive proposal break at exactly the same hop (`api-gateway -> <service>`, unauthenticated) — there's only one gap to close, and Phase 4 closed it, on all three clouds.

`architecture-drifted.json`, the fixed demonstration fixture Phase 7's drift detector already compares against the hardened baseline (see `docs/drift-detection.md`), shows exactly one chain flipping back to HIGH — `mobile-app -> api-gateway -> account-service -> key-vault`. This wasn't discovered by reading `drift.py`'s rules; it's an independent cross-check from this module's own graph walk landing on the same real gap `drift.py` already reports.

Committed artifacts (generated by actually running the CLI, the same convention every other report/`--json` output in this project follows): `threat-model/attack-sim-proposed.md` / `attack-sim-hardened.md` (rendered reports, template-narrated — no `ANTHROPIC_API_KEY` in this sandbox) and `threat-model/attack-chains-proposed.json` / `attack-chains-hardened.json` (structured chain data).

## Honest limitations

- **Flow-authentication only.** This module reasons purely over the `authenticated` field on each flow edge. It says nothing about an asset's own exposure (`public_network_access`), encryption at rest, or IAM role scope — those are exactly what `threat_engine.py`'s other rules already cover, and duplicating them here would be redundant, not additive. A chain can be LOW feasibility by this module's definition while the target asset itself is still flagged as a real finding elsewhere (e.g. `IAM-BROAD-02`) — the two views answer different questions and neither substitutes for the other.
- **No `mtls` field exists in `architecture.json`.** The Terraform mesh module (Istio `PeerAuthentication`, Phase 4) enforces mutual TLS at the infrastructure layer, but `architecture.json`'s flow schema only carries `authenticated`, not a separate `mtls` boolean — this module (and the architecture diagrams in `docs/architecture-diagrams.md`) describe mTLS in prose grounded in the real Terraform module, not as a field this JSON literally encodes. Worth knowing if a future contributor goes looking for an `mtls` key here.
- **No path-length cap beyond `MAX_PATH_DEPTH = 10`**, generous for every fixture in this repo (the deepest real chain is 4 nodes) but untested against a much larger, hand-adversarial architecture graph.
- **Not covered by the agent evaluation harness yet.** `narrate_chain()`'s template fallback is tested directly (`tests/test_attack_sim.py`), but `agent/eval/benchmark.py` (spec §16 table item 10) doesn't yet include attack-chain narration in its fixture set — a real, undone piece of follow-up work, named here rather than silently left unmentioned.
