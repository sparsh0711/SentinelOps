# Detection Rules

SentinelOps v2 uses a focused JSON rule model inspired by Sigma metadata and detection
concepts. It is not a complete Sigma YAML implementation. JSON keeps the app dependency
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
  "logsource": {
    "product": "windows",
    "category": "process_creation"
  },
  "match": {
    "all": [
      {
        "field": "command",
        "operator": "regex",
        "value": "rundll32|regsvr32"
      }
    ]
  },
  "threshold": {
    "count": 3,
    "groupBy": "host",
    "windowSeconds": 300
  },
  "mitre": {
    "id": "T1218",
    "name": "System Binary Proxy Execution",
    "tactic": "Defense Evasion"
  },
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

Threshold rules group matching events by `sourceIp`, `user`, `host`, `process`, or
another normalized event field. An alert is created when `count` matches occur inside
`windowSeconds`.

Analysts can override count, window, and severity from the rule library without
changing the original rule.

## Allowlists

Allowlists support exact values and `*` wildcards for:

- Users
- Hosts
- Source IPs
- Processes

Allowlisted events are removed before rules are evaluated. Keep allowlists narrow and
review them regularly.

## Suppression and Confidence

Duplicate alerts from the same rule and entity are suppressed inside the configured
suppression window. Each alert includes the rule confidence and a plain-language list
of matched conditions and thresholds.

## Importing Rules

Use **Detection rules -> Import JSON**. The file may contain one rule object or an array
of rule objects. Imported rules are validated by API v2 before they are stored.

## Phase 3 Built-In Coverage

The default rule pack now includes these groups:

| Rule area | Main evidence | MITRE ATT&CK |
| --- | --- | --- |
| Brute force and password spray | Failed authentication events grouped by source | T1110.001 / T1110.003 |
| Suspicious PowerShell | Encoded commands, web downloads, credential strings | T1059.001 |
| LOLBin execution | `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`, and similar tools | T1218 |
| Suspicious parent-child chains | Office, browser, PDF, or archive tools spawning shells/scripts | T1204.002 |
| Script/tool network activity | Sysmon Event ID 3 from scripting/admin tools to common ports | T1105 |
| Registry autoruns | Sysmon registry events touching Run, RunOnce, Winlogon, Services paths | T1547.001 |
| Suspicious file drops | Executables or scripts written to Temp, AppData, Downloads, or Public | T1105 |
| Defender tamper | Defender config changes or disabled protection indicators | T1562.001 |
| Log clearing | Windows Security event log clear activity | T1070.001 |
| Service installation | New Windows service creation | T1543.003 |
| Account manipulation | Account creation, enablement, reset, or changes | T1098 |
| Remote interactive logon | Successful RDP-style logons by logon type | T1021.001 |
