# Detection Rules

SentinelOps v2 uses a focused JSON rule model inspired by Sigma metadata and detection
concepts. It is not a complete Sigma YAML implementation. JSON keeps Phase 2 dependency
free while providing a stable format that can later be translated to and from Sigma.

## Rule Example

```json
{
  "id": "custom-suspicious-process",
  "title": "Suspicious Process Execution",
  "description": "Detects a suspicious process command line.",
  "status": "experimental",
  "level": "High",
  "enabled": true,
  "confidence": 80,
  "logsource": {"product": "windows", "category": "process_creation"},
  "match": {"all": [{"field": "command", "operator": "regex", "value": "rundll32|regsvr32"}]},
  "threshold": {"count": 3, "groupBy": "host", "windowSeconds": 300},
  "mitre": {"id": "T1218", "name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
  "tags": ["attack.defense_evasion", "attack.t1218"],
  "falsepositives": ["Approved software installation"]
}
```

## Operators

- `equals`: case-insensitive equality
- `contains`: case-insensitive substring
- `regex`: JavaScript regular expression
- `in`: value is included in an array
- `exists`: field presence or absence

`match.all` requires every condition. `match.any` requires at least one condition. If
both are supplied, both groups must pass.

## Thresholds

Threshold rules group matching events by a normalized event field. An alert is created
when `count` matches occur inside `windowSeconds`. Analysts can override count, window,
and severity from the rule library without changing the original rule.

## Allowlists

Allowlists support exact values and `*` wildcards for users, hosts, source IPs, and
processes. Allowlisted events are removed before rules are evaluated.

## Suppression and Confidence

Duplicate alerts from the same rule and entity are suppressed inside the configured
suppression window. Each alert includes confidence and a plain-language explanation.

## Importing Rules

Use **Detection rules → Import JSON**. The file may contain one rule object or an array
of rule objects. Imported rules are validated by API v2 before storage.
