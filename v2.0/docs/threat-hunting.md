# Phase 6 Threat Hunting

Phase 6 keeps telemetry local. Hunts and IOC matching run in the Python service against event arrays supplied by the local dashboard. IOC lists and hunt history are stored in the local SQLite database.

## Built-In Hunts

- Failed login activity
- PowerShell abuse
- Privilege escalation indicators
- Suspicious account creation
- Lateral movement indicators
- Reconnaissance behaviour

Hunts are transparent filters rather than opaque scoring models. Results contain matching events and observed entities.

## IOC Matching

Supported types are `ip`, `domain`, `hash`, `username`, and `file_path`. Values are normalized before SQLite persistence. Matching does not contact an external threat-intelligence service.

## Sigma Import

The importer accepts a practical subset of Sigma JSON or YAML: metadata, named selections, simple conditions, contains/startswith/endswith modifiers, and ATT&CK tags. Advanced correlation and aggregation require manual conversion.

## Reports

Incident reports can be exported as HTML or PDF. Both formats are generated locally from the stored incident, latest summary, and related event timeline. No report data is uploaded.
