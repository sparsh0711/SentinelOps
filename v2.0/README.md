# SentinelOps v2.0 Phase 4

SentinelOps v2.0 is developed separately from the stable root application.

## Phase 1 Foundation

- [x] Modular Python backend
- [x] Versioned `/api/v2` endpoints
- [x] Environment-based configuration
- [x] JSON structured logging
- [x] Ordered SQLite migrations
- [x] Consistent validation and API errors
- [x] ES-module frontend
- [x] Python and JavaScript tests

## Phase 2 Detection Engine

- [x] Sigma-inspired JSON detection rules
- [x] Built-in and custom rule persistence
- [x] Rule enable, disable, update, delete, and JSON import
- [x] Configurable event counts and time windows
- [x] User, host, source IP, and process allowlists
- [x] Duplicate alert suppression
- [x] Confidence scoring and match explanations
- [x] Severity and threshold overrides
- [x] In-browser rule test bench

## Phase 3 Windows And Sysmon Coverage

- [x] Expanded built-in rule pack from 4 rules to 15 rules
- [x] Sysmon process creation detections for LOLBins and suspicious parent-child chains
- [x] Sysmon network connection detections for scripting tools making outbound traffic
- [x] Sysmon registry autorun persistence detections
- [x] Sysmon suspicious file-drop detections in user-writable folders
- [x] Defender tamper and security-control modification detections
- [x] Security log clear, service installation, account manipulation, and RDP logon detections
- [x] Additional normalized fields for parent process, logon type, destination, registry, file, service, and hash data

## Phase 4 Incident Workflow

- [x] Create incidents from real detection alerts
- [x] Store incidents locally in SQLite
- [x] Track status: New, Investigating, Contained, Resolved, and False Positive
- [x] Track severity, owner, source, alert ID, rule ID, MITRE ID, and risk score
- [x] Add analyst investigation notes
- [x] Maintain a case timeline for creation, updates, and notes
- [x] Filter the incident queue by status
- [x] Open incident details from the SOC dashboard

## Run

```powershell
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
|   |-- api.py
|   |-- app.py
|   |-- config.py
|   |-- database.py
|   |-- server.py
|   |-- validation.py
|   |-- windows.py
|   `-- migrations/
|-- frontend/
|   |-- js/
|   |-- styles/
|   `-- index.html
|-- tests/
|   |-- backend/
|   `-- frontend/
|-- start.ps1
|-- rules/
`-- test.ps1
```

See [docs/architecture.md](docs/architecture.md) for module responsibilities and
[docs/detection-rules.md](docs/detection-rules.md) for the rule schema and coverage.
