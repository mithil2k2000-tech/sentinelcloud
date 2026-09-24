# Residual Risk Register (SentinelCloud v1 spec, §11 Phase 4)

Every finding listed here is a real, currently-open gap in the hardened
architectures (`threat-model/architecture-hardened*.json`) — not
something quietly dropped between a doc and the actual code. Each row is
accepted-for-now with an explicit owner, a target phase to close it, and
the reason it's not blocking merges today (`docs/ci-cd.md` explains the
`--fail-on HIGH` gate threshold this register directly supports — tightened
from `CRITICAL` once Phase 9 closed RR-01 below).

This register is a living document: when a phase in the v1 spec's §16
plan closes one of these, the row moves to "Closed" with the date and PR/
commit that closed it — it does not just disappear.

## Open

| ID | Finding | Rule | Clouds affected | Risk model score¹ | Owner | Target phase | Why accepted for now |
|---|---|---|---|---|---|---|---|
| RR-05 | `api-gateway` has no WAF/rate-limiting | `NET-WAF-01` | Azure, GCP, AWS | HIGH (9) | Raghavan | Phase 1 follow-up (Azure Front Door / App Gateway WAF, or cloud equivalent) | Not yet built; genuinely lower urgency than the (now closed) RR-01–04 per the recalibrated risk model (§ below). The only open finding left in any hardened architecture. |
| RR-06 | Azure's `payment-service` IAM role scoped to resource-group, not the specific resource | `IAM-BROAD-02` | Azure only | CRITICAL (12) | Raghavan | Phase 1 follow-up | GCP and AWS already scope to the specific bucket/resource (a real improvement found by the threat engine, documented in `docs/phase1-gcp.md`/`docs/phase1-aws.md`) — backporting to Azure needs a real payments resource to scope `assignable_scopes` against. Scores CRITICAL under the risk model (not just MEDIUM as `threat_engine.py`'s raw severity has it) because `payment-service` is edge-adjacent and touches `critical`-sensitivity data — a good example of the risk model surfacing real urgency the fixed severity alone understates. |

¹ Risk model score/label from `agent/risk_model.py` (Phase 4, opt-in via
`analyze.py --risk-model`), not `threat_engine.py`'s raw Severity —
factors in the sensitivity of what each finding actually touches and how
structurally exposed it is. See `docs/phase4-risk-model.md` for what the
score means and its known limitation (global findings — `LOG-001` was the
example before it closed below — score against the most sensitive asset in
the *whole* architecture, which inflates them; that limitation is noted
there, not hidden here, and still applies to any future global finding).

## Closed

| ID | Finding | Rule | Clouds affected | Closed | What closed it |
|---|---|---|---|---|---|
| RR-01 | No centralized audit logging | `LOG-001` | Azure, GCP, AWS | 2026-09-17, Phase 9 | `terraform/{azure,gcp,aws}/modules/logging` — real logging infrastructure (Log Analytics workspace + diagnostic settings on Azure; a project-wide audit-log sink into a locked-down GCS bucket plus Data Access audit logging on GCP; a multi-region CloudTrail with object-level data events into an encrypted S3 bucket + CloudWatch Log Group on AWS). `architecture-hardened{,-gcp,-aws}.json` now carry a `log-workspace` asset in the `mgmt` boundary and `"logging": {"enabled": true}`, which is what flips `LOG-001` off. `tests/test_analyze_cli.py`'s documented finding counts were updated to match (Azure: HIGH 1→0; GCP/AWS: HIGH 2→1) — the intended trip-wire this register's own "how to use" section describes below, not a stale test silently left behind. See `docs/phase9-siem-detection.md`. |
| RR-02 | `account-service` has no dedicated identity/role | `IAM-MISSING-01` | Azure, GCP, AWS | 2026-09-17, Phase 4 | `terraform/{azure,gcp,aws}/modules/iam` — a dedicated `account-service` identity per cloud, scoped to the one secrets resource it actually needs (Azure: custom `azurerm_role_definition` + `azurerm_role_assignment` scoped to the Key Vault; GCP: `google_project_iam_custom_role` + `google_secret_manager_secret_iam_member` scoped to the one secret; AWS: a full IRSA trust policy + role + scoped Secrets Manager policy, mirroring `payment-service`'s existing pattern). `architecture-hardened{,-gcp,-aws}.json`'s `identity_bindings` for `account-service` now carry a real `role`/`scope` instead of `null`/`null`. |
| RR-03 | `account-service → secrets` has no application-layer authentication | `AUTHN-FLOW-01` | GCP, AWS (never actually open on Azure — see note) | 2026-09-17, Phase 4 | Mesh-wide STRICT Istio `PeerAuthentication` (`terraform/{azure,gcp,aws}/modules/mesh`) makes every in-mesh call mutually authenticated, so `account-service`'s calls to the secrets store are no longer just network-reachable. **Correction while closing this row**: `architecture-hardened.json` (Azure) already had `account-service → key-vault` marked `authenticated: true` before Phase 4 started — an inconsistency from an earlier phase that meant this finding, despite being listed above as affecting all three clouds, was never actually open for Azure specifically. Recorded here plainly rather than silently narrowing the "clouds affected" column with no explanation. |
| RR-04 | `api-gateway → {payment,account}-service` has no application-layer authentication | `AUTHN-FLOW-01` | Azure, GCP, AWS | 2026-09-17, Phase 4 | Same mesh-wide STRICT `PeerAuthentication` as RR-03 — every `api-gateway → service` flow is now mutually authenticated, not just network-reachable. `architecture-hardened{,-gcp,-aws}.json`'s flows for `payment-service`, `account-service`, and `notification-service` are all now `authenticated: true`. `tests/test_analyze_cli.py`'s documented finding counts were updated to match (Azure: MEDIUM 5, HIGH 0; GCP/AWS: MEDIUM 1, HIGH 0 — all three clouds now `ALLOWED` at the default `--fail-on HIGH` gate). See `docs/phase4-zero-trust.md`, including its honest caveat about `helm`/`kubernetes` providers being configured in the same root module as the cluster they target — syntactically valid for `terraform validate` (the only check this project's CI runs) but a known chicken-and-egg problem for a real `terraform apply`. |

## How to use this register

- Adding a new accepted-for-now finding: append a row with a real owner
  and target phase — never "later" with no phase attached.
- Closing a finding: move its row to **Closed** with the date and what
  actually closed it (commit/PR), and re-run `pytest tests/` — the
  integration tests in `tests/test_analyze_cli.py` assert exact finding
  counts per architecture, so closing a real finding is expected to fail
  one of those tests until the expected counts are updated to match,
  which is the intended trip-wire (a test failure here means "the docs
  and this register need updating to match reality," not "something
  broke").
