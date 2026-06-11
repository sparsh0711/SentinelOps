# SentinelOps v2 Phase 5 Architecture

## Backend

- `app.py`: application composition and HTTP server lifecycle
- `config.py`: validated environment configuration
- `server.py`: HTTP transport, request IDs, structured errors, and static files
- `api.py`: versioned API routing and use-case coordination
- `database.py`: SQLite persistence and migration execution
- `validation.py`: request and domain validation
- `windows.py`: Windows Event Log and EVTX PowerShell adapter
- `rules.py`: detection rule and engine-setting repository
- `ai_summary.py`: evidence packet creation, local summaries, OpenAI provider, and schema validation
- `migrations/`: ordered, one-time database schema changes

The backend uses only the Python standard library. JSON request logs contain request metadata without writing uploaded event content.

## Frontend

- `api.js`: API v2 client
- `parsers.js`: JSON, JSONL, CSV, text parsing, and event normalization
- `detections.js`: pure rule evaluation and risk scoring
- `rule_engine.js`: condition matching, thresholds, allowlists, overrides, and suppression
- `state.js`: observable application state
- `ui.js`: DOM rendering and event binding
- `main.js`: application composition

Phase 4 adds a local incident workflow on top of detections. Phase 5 adds summary generation. The backend builds a restricted evidence packet containing selected incident metadata, alert fields, and allowlisted event fields. Unknown keys are discarded. The packet is hashed and its SHA-256 fingerprint is stored with the summary.

If `OPENAI_API_KEY` is present, the backend uses the OpenAI Responses API with strict JSON-schema Structured Outputs and `store: false`. Without a key, a deterministic local provider produces a clearly labeled evidence-only summary. The frontend never receives or stores the API key.

## Incident Data Model

Incidents are stored by migration `003_incidents.sql`. Summary versions are stored separately by `004_incident_summaries.sql`, preserving provider, model, creation time, evidence fingerprint, and structured output.

## API v2

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v2/status` | Service capabilities, version, and AI provider status |
| GET/POST | `/api/v2/analyses` | List or save analyses |
| GET | `/api/v2/analyses/{id}` | Open a saved analysis |
| GET/POST | `/api/v2/incidents` | List or create incidents |
| GET | `/api/v2/incidents/{id}` | Open an incident with notes, timeline, and summaries |
| POST | `/api/v2/incidents/{id}/update` | Update incident workflow fields |
| POST | `/api/v2/incidents/{id}/notes` | Add an investigation note |
| GET/POST | `/api/v2/incidents/{id}/summaries` | List or generate summary versions |
| GET | `/api/v2/events/windows` | Collect a Windows event channel |
| POST | `/api/v2/imports/evtx` | Parse an uploaded EVTX file |
| GET/POST | `/api/v2/rules` | List or save detection rules |
| GET/POST | `/api/v2/detection-settings` | Read or save engine tuning |

## Configuration

| Variable | Default |
| --- | --- |
| `SENTINELOPS_V2_HOST` | `127.0.0.1` |
| `SENTINELOPS_V2_PORT` | `8081` |
| `SENTINELOPS_V2_DB` | `v2.0/sentinelops-v2.db` |
| `SENTINELOPS_V2_LOG_LEVEL` | `INFO` |
| `SENTINELOPS_V2_MAX_UPLOAD_BYTES` | `104857600` |
| `SENTINELOPS_V2_MAX_EVENTS` | `5000` |
| `OPENAI_API_KEY` | Empty; local evidence-only mode |
| `SENTINELOPS_OPENAI_MODEL` | `gpt-5.5` |
| `SENTINELOPS_AI_TIMEOUT_SECONDS` | `45` |
