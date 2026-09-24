# architecture.json schema

Minimal graph representation an architecture is reduced to before the threat
engine runs. Kept intentionally small — enough structure for real STRIDE
reasoning, not a full CMDB.

```jsonc
{
  "name": "string — architecture name",
  "assets": [
    {
      "id": "string, unique",
      "type": "client | gateway | compute | database | storage | secret-store | logging",
      "subnet": "string — which trust boundary it lives in",
      "sensitivity": "low | medium | high | critical",
      "internet_facing": true,
      "public_network_access": true,
      "allow_public_blob": true,
      "encrypted_at_rest": true,
      "waf_enabled": true
      // only the fields relevant to the asset type need be present
    }
  ],
  "trust_boundaries": [
    { "id": "string", "contains": ["asset-id", "..."] }
  ],
  "flows": [
    {
      "from": "asset-id",
      "to": "asset-id",
      "protocol": "https | tcp | ...",
      "port": 443,
      "authenticated": true // app-layer auth (mTLS/OAuth/etc), not just network reachability
    }
  ],
  "identity_bindings": [
    {
      "principal": "asset-id of the compute asset",
      "role": "string role name, or null if none assigned",
      "scope": "what the role is scoped to: 'subscription' | 'resource-group' | 'resource' | null"
    }
  ],
  "logging": {
    "enabled": true,
    "destination": "string, optional — asset id of the logging asset (type: logging) this points at",
    "retention_days": "integer, optional — structured detail added in spec §16 table item 9 (centralized logging): how long this architecture's logging is documented to retain events",
    "local_query_enabled": "boolean, optional — same item 9 extension: whether a local, queryable log-aggregation simulation (logging/log_store.py) exists for this architecture, as opposed to logging merely being 'enabled' with nowhere to query it back from"
  }
}
```

`retention_days`/`local_query_enabled` are additive, optional detail —
`rule_logging_disabled` in `agent/threat_engine.py` only ever reads
`logging.enabled`, so their presence or absence never changes a threat
finding. They exist to make `logging.enabled: true` mean something more
concrete than a bare boolean once a real local log store is attached (see
`docs/centralized-logging.md`), per the spec's own §16-table item 9
("updated `architecture.json` schema: `logging.enabled` → structured
detail").

Design choice: this is deliberately close to what you'd get by reading a
Terraform plan's resource graph, so a later upgrade (auto-extracting this
from `terraform show -json` instead of hand-writing it) is a parser change,
not a redesign.
