# SentinelOps v2 Phase 3 Architecture

## Backend

- `app.py`: application composition and HTTP server lifecycle
- `config.py`: validated environment configuration
- `server.py`: HTTP transport, request IDs, structured errors, and static files
- `api.py`: versioned API routing and use-case coordination
- `database.py`: SQLite persistence and migration execution
- `validation.py`: request and domain validation
- `windows.py`: Windows Event Log and EVTX PowerShell adapter
- `rules.py`: detection rule and engine-setting repository
- `migrations/`: ordered, one-time database schema changes

The backend uses only the Python standard library. JSON request logs contain a request
ID, method, path, status, and duration without writing uploaded event content.

## Frontend

- `api.js`: API v2 client
- `parsers.js`: JSON, JSONL, CSV, text parsing, and event normalization
- `detections.js`: pure rule evaluation and risk scoring
- `rule_engine.js`: condition matching, thresholds, allowlists, overrides, and suppression
- `state.js`: observable application state
- `ui.js`: DOM rendering and event binding
- `main.js`: application composition

Detection and parsing modules are independent of the DOM, which allows them to run in
Node's built-in test runner.

## Normalized Event Fields

Phase 3 expands the normalized event model used by the browser rule engine and the
Windows/EVTX collector.

| Field | Common source examples |
| --- | --- |
| `eventId` | Windows event ID or Sysmon event ID |
| `user` | `TargetUserName`, `SubjectUserName`, `user` |
| `sourceIp` | `IpAddress`, `SourceNetworkAddress`, `ClientAddress` |
| `destinationIp` | `DestinationIp`, `DestinationIpAddress` |
| `destinationPort` | `DestinationPort`, `DestPort` |
| `process` | `Image`, `NewProcessName` |
| `parentProcess` | `ParentImage`, `ParentProcessName` |
| `command` | `CommandLine`, `ScriptBlockText` |
| `logonType` | Windows `LogonType` |
| `targetFilename` | Sysmon `TargetFilename` |
| `registryKey` | Sysmon `TargetObject`, Windows `ObjectName` |
| `serviceName` | Windows `ServiceName` |
| `hash` | Sysmon `Hashes`, `Hash` |
| `group` | Group membership events |
| `privileges` | `PrivilegeList` |
| `message` | Rendered event message |

## API v2

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v2/status` | Service capabilities and version |
| GET | `/api/v2/analyses` | List saved analyses |
| GET | `/api/v2/analyses/{id}` | Open one saved analysis |
| POST | `/api/v2/analyses` | Save a completed analysis |
| GET | `/api/v2/events/windows` | Collect a Windows event channel |
| POST | `/api/v2/imports/evtx` | Parse an uploaded EVTX file |
| POST | `/api/v2/checkpoints/reset` | Reset a channel checkpoint |
| GET | `/api/v2/rules` | List built-in and custom rules |
| GET | `/api/v2/rules/{id}` | Read one rule |
| POST | `/api/v2/rules` | Create or update a custom rule |
| POST | `/api/v2/rules/toggle` | Enable or disable a rule |
| POST | `/api/v2/rules/delete` | Delete a custom rule |
| GET | `/api/v2/detection-settings` | Read allowlists and engine tuning |
| POST | `/api/v2/detection-settings` | Save allowlists and engine tuning |

Errors use this shape:

```json
{
  "error": {
    "code": "invalid_payload",
    "message": "Analysis payload is missing required fields.",
    "details": {
      "missing": ["events"]
    },
    "requestId": "..."
  }
}
```

## Configuration

| Variable | Default |
| --- | --- |
| `SENTINELOPS_V2_HOST` | `127.0.0.1` |
| `SENTINELOPS_V2_PORT` | `8081` |
| `SENTINELOPS_V2_DB` | `v2.0/sentinelops-v2.db` |
| `SENTINELOPS_V2_LOG_LEVEL` | `INFO` |
| `SENTINELOPS_V2_MAX_UPLOAD_BYTES` | `104857600` |
| `SENTINELOPS_V2_MAX_EVENTS` | `5000` |
