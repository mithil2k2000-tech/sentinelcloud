# Compliance Audit-Style Report (reference only, not a certification)

**Subject:** Mobile Banking App — as implemented in terraform/azure (Phase 1 scaffold)
**Scope:** controls checked by `agent/threat_engine.py` only (6 of 15 controls in `policy/framework-mappings.yaml`). Kubernetes-specific and infrastructure-drift controls are assessed separately — see `agent/k8s_scan.py --compliance` and `agent/drift_scan.py --compliance`.
**As of:** 2026-09-18

This is NOT an audit, a certification, or a claim that this architecture satisfies any of the frameworks below. It restates the SentinelCloud compliance-mapping file (`policy/framework-mappings.yaml`, FR-8) as a per-framework PASS/FAIL checklist against this run's actual findings, for engineering traceability only (SR-6).

## Executive summary

- Controls in scope: 6
- PASS: 4
- FAIL: 2

## CIS Controls v8

| Control | Status | Title | Internal control_id |
| --- | --- | --- | --- |
| 3.11 | PASS | Encrypt Sensitive Data at Rest | DATA-002 |
| 6.8 | FAIL | Define and Maintain Role-Based Access Control | IAM-004 |
| 8.5 | PASS | Collect Detailed Audit Logs | LOG-001 |
| 12.2 | PASS | Establish and Maintain a Secure Network Architecture | NET-001 |
| 13.10 | FAIL | Perform Application Layer Filtering | NET-003 |
| 3.10 | PASS | Encrypt Sensitive Data in Transit | ZT-001 |

## NIST CSF 2.0

| Control | Status | Title | Internal control_id |
| --- | --- | --- | --- |
| PR.DS-01 | PASS | The confidentiality, integrity, and availability of data-at-rest are protected | DATA-002 |
| PR.AA-05 | FAIL | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties | IAM-004 |
| PR.PS-04 | PASS | Log records are generated and made available for continuous monitoring | LOG-001 |
| PR.IR-01 | PASS | Networks and environments are protected from unauthorized logical access and usage | NET-001 |
| PR.IR-01 | FAIL | Networks and environments are protected from unauthorized logical access and usage | NET-003 |
| PR.AA-03 | PASS | Users, services, and hardware are authenticated commensurate with the risk of the transaction | ZT-001 |

## PCI DSS v4.0

| Control | Status | Title | Internal control_id |
| --- | --- | --- | --- |
| 3.5.1 | PASS | Primary account number (PAN) is rendered unreadable anywhere it is stored | DATA-002 |
| 7.2.1 | FAIL | An access control model is defined and includes appropriate assignment of privileges based on job classification and function, least privileges, and need to know | IAM-004 |
| 10.2.1 | PASS | Audit logs are enabled and active for all system components and cardholder data | LOG-001 |
| 1.4.1 | PASS | Network Security Controls between trusted and untrusted networks are implemented | NET-001 |
| 6.4.2 | FAIL | An automated technical solution (e.g. a WAF) is deployed to detect and prevent web-based attacks | NET-003 |
| 4.2.1 | PASS | Strong cryptography and security protocols are implemented to safeguard PAN during transmission | ZT-001 |

## Failing controls — detail

### IAM-004 (CIS Controls v8 6.8, NIST CSF 2.0 PR.AA-05, PCI DSS v4.0 7.2.1)

Least-privilege identity scoping and network segmentation (reused by IAM-BROAD-01/02, IAM-MISSING-01, and NET-SEGMENT-01 in threat_engine.py — see the note on shared control_ids below)

- [MEDIUM] `IAM-BROAD-02` — payment-service role scoped to resource group, not a specific resource (assets: payment-service)

### NET-003 (CIS Controls v8 13.10, NIST CSF 2.0 PR.IR-01, PCI DSS v4.0 6.4.2)

WAF / rate-limiting in front of an internet-facing gateway (NET-WAF-01)

- [MEDIUM] `NET-WAF-01` — api-gateway has no WAF/rate-limiting in front of it (assets: api-gateway)
