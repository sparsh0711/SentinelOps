# SentinelOps

A local-first Windows security log analyzer and SOC dashboard. SentinelOps processes
real event data, identifies common attack patterns, maps findings to MITRE ATT&CK,
and keeps analysis history on the local machine.

![SentinelOps dashboard analyzing a public EVTX sample](dashboard-verification.png)

> **v2.0 development:** The completed Phase 1 foundation is available in
> [`v2.0/`](v2.0/README.md). The application in the repository root remains the
> stable v1 release.

## Highlights

- Analyze Windows `.evtx`, JSON, JSONL, CSV, LOG, and TXT files
- Collect live Windows Security, System, Application, PowerShell, Defender, and Sysmon events
- Detect failed logins, brute force, password spraying, suspicious PowerShell, and privilege activity
- Correlate multi-stage behavior across authentication, execution, and privilege events
- Map alerts to MITRE ATT&CK techniques
- Calculate Low, Medium, and High risk scores
- Create custom keyword or regular-expression detection rules
- Store analysis history and collection checkpoints in SQLite
- Export JSON, CSV, printable HTML, and PDF-ready reports
- Keep logs local: the service binds to `127.0.0.1` and does not send data externally

## Quick Start

### Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or newer
- Python 3.10 or newer

No Python packages need to be installed.

### Run

Open PowerShell in the project directory:

```powershell
.\start.ps1
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080).

If PowerShell blocks the script, allow it only for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start.ps1
```

Stop the service with `Ctrl+C`.

Opening `index.html` directly supports pasted JSON, JSONL, CSV, and text logs. EVTX
parsing, live collection, checkpoints, and analysis history require the local service.

## How It Works

1. `server.py` serves the dashboard, converts EVTX records through Windows PowerShell,
   collects live event channels, and stores history in SQLite.
2. `app.js` normalizes fields from different log formats into one event model.
3. Detection rules evaluate event IDs, messages, commands, users, timestamps, and
   source addresses.
4. Correlation logic groups related activity and assigns severity, risk, and MITRE
   ATT&CK context.
5. The dashboard renders findings, timelines, event details, and exportable reports.

Common normalized fields include `timestamp`, `event_id`, `user`, `source_ip`, `host`,
`status`, `message`, `process`, `command`, `group`, and `privileges`.

## Detection Coverage

| Detection | Example evidence | MITRE ATT&CK |
| --- | --- | --- |
| Failed authentication | Windows Event ID 4625 and matching log messages | T1110 |
| Brute force / password spray | Repeated failures grouped by IP, user, and time | T1110.001 / T1110.003 |
| Suspicious PowerShell | Script block and command indicators, including Event IDs 4103/4104 | T1059.001 |
| Privilege escalation indicators | Sensitive privilege, service, group, and audit events | T1068 / related context |
| Suspicious IP activity | External addresses associated with repeated authentication activity | T1078 |
| Attack-chain correlation | Login failure, success, execution, and privilege stages | Multiple techniques |

## Testing With Real Logs

The `test-logs/README.md` guide lists public EVTX samples verified with SentinelOps.
The EVTX binaries are intentionally excluded from this repository; download them from
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
and place them in `test-logs/`.

This avoids presenting generated events as real telemetry and keeps third-party
GPL-licensed data separate from the SentinelOps source code.

## Privacy and Security

- The HTTP service listens only on the local loopback interface.
- Log data and analysis history remain on the local computer.
- The SQLite database is excluded from Git.
- Source files and the database are blocked from direct static serving.
- Live Security log collection may require an Administrator PowerShell session.

Do not publish `sentinelops.db` or logs collected from a real organization. They may
contain usernames, hostnames, addresses, commands, and other sensitive information.

## Current Scope

SentinelOps is a portfolio and learning project, not a replacement for a production
SIEM or EDR. Its detections are rule-based and should be validated by an analyst.
Future work can add Sigma rules, threat-intelligence enrichment, allowlists, automated
tests, and ingestion from remote systems.

## License

SentinelOps source code is available under the [MIT License](LICENSE). Third-party test
logs remain subject to their original licenses.
