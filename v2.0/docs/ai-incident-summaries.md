# AI Incident Summaries

Phase 5 creates structured summaries for saved incidents.

## Output

Each summary contains:

- Executive summary
- Technical investigation summary
- Suspicious behaviour explanation
- Evidence-backed MITRE ATT&CK techniques
- Risk-level explanation
- Recommended investigation steps
- Conditional containment and remediation actions
- Evidence limitations

## Grounding Rules

The summary engine must not add facts that are absent from the incident evidence.

- MITRE techniques come only from saved mappings.
- Risk explanations use the saved severity and score.
- Missing users, hosts, addresses, events, and mappings are listed as limitations.
- Possible interpretations use cautious language.
- Recommendations describe checks or conditional actions, not completed actions.

## Privacy Modes

`local-evidence` is the default and keeps evidence on the computer.

`openai` is enabled only when `OPENAI_API_KEY` is present in the backend environment.
The backend sends a restricted evidence packet to the Responses API using strict
Structured Outputs and `store: false`. The browser never handles the API key.

Every saved result records the provider, model, creation time, and SHA-256 evidence
fingerprint.
