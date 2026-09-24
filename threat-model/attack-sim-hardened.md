# Attack Path Simulation — Mobile Banking App — as implemented in terraform/azure (Phase 1 scaffold)

(reachability analysis only — not a penetration test or proof of exploitability)

3 path(s) found: 0 HIGH feasibility, 3 LOW (defense-in-depth only).

## CHAIN-01 — LOW
Path: `mobile-app -> api-gateway -> account-service -> key-vault`
Target: `key-vault` (critical-sensitivity secret-store)
mobile-app -> api-gateway -> account-service -> key-vault reaches key-vault (critical-sensitivity secret-store), but every hop on this path requires authentication — defense-in-depth only. (reachability analysis only — not a penetration test or proof of exploitability)

## CHAIN-02 — LOW
Path: `mobile-app -> api-gateway -> payment-service -> key-vault`
Target: `key-vault` (critical-sensitivity secret-store)
mobile-app -> api-gateway -> payment-service -> key-vault reaches key-vault (critical-sensitivity secret-store), but every hop on this path requires authentication — defense-in-depth only. (reachability analysis only — not a penetration test or proof of exploitability)

## CHAIN-03 — LOW
Path: `mobile-app -> api-gateway -> payment-service -> customer-storage`
Target: `customer-storage` (critical-sensitivity storage)
mobile-app -> api-gateway -> payment-service -> customer-storage reaches customer-storage (critical-sensitivity storage), but every hop on this path requires authentication — defense-in-depth only. (reachability analysis only — not a penetration test or proof of exploitability)

