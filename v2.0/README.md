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

## Run

```powershell
.\start.ps1
```

Open `http://127.0.0.1:8081`.

## Test

```powershell
.\test.ps1
```

Phase 1 intentionally focuses on architecture. Sigma rules, Sysmon-focused
detections, incident management, and allowlists will be added in later phases.

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
`-- test.ps1
```

See [docs/architecture.md](docs/architecture.md) for module responsibilities and
the API contract.
