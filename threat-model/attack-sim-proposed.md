# Attack Path Simulation — Mobile Banking App — first-draft proposal (as submitted by engineering, pre-review)

(reachability analysis only — not a penetration test or proof of exploitability)

4 path(s) found: 4 HIGH feasibility, 0 LOW (defense-in-depth only).

## CHAIN-01 — HIGH
Path: `mobile-app -> api-gateway -> notification-service -> customer-db`
Target: `customer-db` (critical-sensitivity database)
mobile-app -> api-gateway -> notification-service -> customer-db reaches customer-db (critical-sensitivity database) through 1 unauthenticated hop(s): api-gateway -> notification-service. (reachability analysis only — not a penetration test or proof of exploitability)

## CHAIN-02 — HIGH
Path: `mobile-app -> api-gateway -> account-service -> customer-db`
Target: `customer-db` (critical-sensitivity database)
mobile-app -> api-gateway -> account-service -> customer-db reaches customer-db (critical-sensitivity database) through 1 unauthenticated hop(s): api-gateway -> account-service. (reachability analysis only — not a penetration test or proof of exploitability)

## CHAIN-03 — HIGH
Path: `mobile-app -> api-gateway -> payment-service -> customer-db`
Target: `customer-db` (critical-sensitivity database)
mobile-app -> api-gateway -> payment-service -> customer-db reaches customer-db (critical-sensitivity database) through 1 unauthenticated hop(s): api-gateway -> payment-service. (reachability analysis only — not a penetration test or proof of exploitability)

## CHAIN-04 — HIGH
Path: `mobile-app -> api-gateway -> payment-service -> customer-storage`
Target: `customer-storage` (critical-sensitivity storage)
mobile-app -> api-gateway -> payment-service -> customer-storage reaches customer-storage (critical-sensitivity storage) through 1 unauthenticated hop(s): api-gateway -> payment-service. (reachability analysis only — not a penetration test or proof of exploitability)

