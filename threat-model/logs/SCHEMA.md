# logs.json schema

Synthetic log events fed to `agent/detection_engine.py`. Same design choice
as `threat-model/SCHEMA.md`: kept close to what a SIEM query result or a
normalized CloudTrail/Cloud-Logging/Log-Analytics record looks like, so a
later upgrade (ingesting real exported logs instead of hand-authored
fixtures) is a parser change, not a redesign.

```jsonc
{
  "events": [
    {
      "event_id": "string, unique",
      "timestamp": "YYYY-MM-DDTHH:MM:SSZ — UTC, compared lexically",
      "event_type": "auth | iam_change | data_transfer | logging_disabled | log_deleted",
      "principal": "string — the identity that performed the action",
      "source_ip": "string, optional",
      "target": "string — the resource acted on",
      "outcome": "success | failure",
      "region": "string, optional — only used by the impossible-travel rule",
      "bytes_transferred": "integer, optional — only used by the exfiltration-volume rule"
    }
  ]
}
```

Every value in every fixture under this directory is synthetic and
hand-authored to exercise one detection rule at a time (or, for
`logs-multi-stage-incident.json`, several in sequence as a single
narrative) — never captured from a real system. No real IPs, no real
account identifiers, no real customer data. Principal names are fictional
Meridian Trust Bank employees (v1 spec §2's fictional reference customer),
consistent with the rest of this repo.

| Fixture | Exercises | Expected alerts |
|---|---|---|
| `logs-normal.json` | nothing — baseline | 0 |
| `logs-brute-force.json` | `DET-BRUTEFORCE-01` (no success) | 1, HIGH |
| `logs-credential-stuffing-success.json` | `DET-BRUTEFORCE-01` (success after failures) | 1, CRITICAL |
| `logs-impossible-travel.json` | `DET-TRAVEL-01` | 1, CRITICAL |
| `logs-privilege-escalation.json` | `DET-PRIVESC-01` | 1, HIGH |
| `logs-data-exfiltration.json` | `DET-EXFIL-01` | 1, CRITICAL |
| `logs-log-tampering.json` | `DET-LOGTAMPER-01` | 1, CRITICAL |
| `logs-multi-stage-incident.json` | all four rules that can co-occur, one attacker | 4 (3 CRITICAL, 1 HIGH) |
