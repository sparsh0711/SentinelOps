# SentinelOps v2.0 Phase 6

SentinelOps is a local-first security log analyzer and SOC dashboard built with Python, SQLite, and browser-native JavaScript.

## Phase 6

- Six transparent threat-hunting queries covering failed logins, PowerShell abuse, privilege escalation, account creation, lateral movement, and reconnaissance
- Local IOC lists for IP addresses, domains, hashes, usernames, and file paths
- IOC matching against loaded event telemetry
- Simple Sigma JSON/YAML conversion into SentinelOps detection rules
- MITRE ATT&CK technique frequency heatmap
- Chronological incident investigation timeline
- Local HTML and PDF incident report export
- SQLite hunt history and IOC persistence

Earlier phases include the modular API and database foundation, the detection engine, Windows/Sysmon coverage, incident workflow, and evidence-grounded AI incident summaries.

## Privacy

Telemetry, IOC lists, hunt history, reports, and the default incident summaries remain local. OpenAI summaries are optional and only enabled when `OPENAI_API_KEY` is configured. API requests use a restricted evidence packet and `store: false`.

## Run

```powershell
cd v2.0
.\start.ps1
```

Open `http://127.0.0.1:8081`.

## Test

```powershell
.\test.ps1
```

See [docs/architecture.md](docs/architecture.md), [docs/detection-rules.md](docs/detection-rules.md), [docs/ai-incident-summaries.md](docs/ai-incident-summaries.md), and [docs/threat-hunting.md](docs/threat-hunting.md).
