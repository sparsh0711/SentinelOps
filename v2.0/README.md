# SentinelOps v2.0

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

## Run

```powershell
.\start.ps1
```

Open `http://127.0.0.1:8081`.

## Test

```powershell
.\test.ps1
```

Phase 3 will expand Windows and Sysmon detection coverage. Incident management remains
planned for Phase 4.

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
the API contract. See [docs/detection-rules.md](docs/detection-rules.md) for the rule
schema and tuning workflow.
