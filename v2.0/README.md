# SentinelOps v2.0 Phase 5

This is the clean Phase 5 build of SentinelOps v2.0, kept separate from the experimental AI assistant project.

## Completed Phases

### Phase 1 Foundation
- Modular Python backend and versioned `/api/v2` endpoints
- Environment configuration, structured logging, SQLite migrations, validation, ES-module frontend, and tests

### Phase 2 Detection Engine
- Sigma-inspired JSON rules, custom rule persistence, thresholds, time windows, allowlists, suppression, confidence scores, overrides, and rule test bench

### Phase 3 Windows And Sysmon Coverage
- 15 built-in detections covering process creation, PowerShell, LOLBins, suspicious network connections, registry autoruns, file drops, Defender tampering, log clearing, services, account changes, and RDP

### Phase 4 Incident Workflow
- SQLite incident cases with status, severity, owner, evidence, notes, timeline, filtering, and dashboard details

### Phase 5 AI Incident Summary Engine
- Executive and technical summaries
- Suspicious behaviour explanation based only on saved evidence
- MITRE ATT&CK mappings already present in evidence
- Stored-risk explanation
- Investigation and conditional containment/remediation actions
- Evidence limitations and SHA-256 evidence fingerprint
- Summary history in SQLite
- Correlated incidents containing multiple alerts and events
- Optional OpenAI Responses API with strict Structured Outputs
- Private local evidence-only mode when no API key is configured

## AI Configuration

The default mode does not send data outside the computer. To enable OpenAI summaries for the current PowerShell session:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:SENTINELOPS_OPENAI_MODEL = "gpt-5.5"
.\start.ps1
```

Never commit an API key or place one in the frontend. Cloud mode sends only a restricted evidence packet and requests use `store: false`.

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

## Structure

```text
v2.0/
|-- backend/
|   |-- ai_summary.py
|   |-- api.py
|   |-- app.py
|   |-- config.py
|   |-- database.py
|   |-- rules.py
|   |-- validation.py
|   `-- migrations/
|-- frontend/
|   |-- js/
|   |-- styles/
|   `-- index.html
|-- rules/
|-- tests/
|-- start.ps1
`-- test.ps1
```

See [docs/architecture.md](docs/architecture.md), [docs/detection-rules.md](docs/detection-rules.md), and [docs/ai-incident-summaries.md](docs/ai-incident-summaries.md).
