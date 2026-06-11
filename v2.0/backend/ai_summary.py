import hashlib
import json
import urllib.error
import urllib.request

from .errors import ApiError


SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "executiveSummary": {"type": "string"},
        "technicalSummary": {"type": "string"},
        "suspiciousBehaviour": {"type": "array", "items": {"type": "string"}},
        "mitreTechniques": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["id", "name", "evidence"],
            },
        },
        "riskExplanation": {"type": "string"},
        "investigationSteps": {"type": "array", "items": {"type": "string"}},
        "containmentActions": {"type": "array", "items": {"type": "string"}},
        "evidenceLimitations": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "executiveSummary",
        "technicalSummary",
        "suspiciousBehaviour",
        "mitreTechniques",
        "riskExplanation",
        "investigationSteps",
        "containmentActions",
        "evidenceLimitations",
    ],
}

SYSTEM_INSTRUCTIONS = """
You are a SOC incident summary engine. Use only facts present in the supplied
evidence JSON. Never invent identities, intent, malware, compromise, causality,
geolocation, threat intelligence, or missing event details. Use cautious wording
such as "may indicate" when describing a possible interpretation. If evidence is
missing, state that limitation. MITRE techniques must come only from mappings
already present in the evidence. Recommended steps must verify or respond to
observed entities and must not claim an action has already occurred.
""".strip()


def _clean(value, maximum=500):
    return str(value or "").strip()[:maximum]


def _event_view(event):
    if not isinstance(event, dict):
        return {}
    fields = (
        "timestamp",
        "eventId",
        "event_id",
        "user",
        "sourceIp",
        "source_ip",
        "host",
        "status",
        "process",
        "parentProcess",
        "command",
        "message",
        "logonType",
        "destinationIp",
        "destinationPort",
        "targetFilename",
        "registryKey",
        "serviceName",
        "group",
        "privileges",
    )
    return {
        field: event[field]
        for field in fields
        if field in event and event[field] not in (None, "", "unknown")
    }


def _alert_view(alert):
    if not isinstance(alert, dict):
        return {}
    mitre = alert.get("mitre") if isinstance(alert.get("mitre"), dict) else {}
    return {
        "id": _clean(alert.get("id"), 120),
        "ruleId": _clean(alert.get("ruleId") or alert.get("rule_id"), 120),
        "title": _clean(alert.get("title"), 200),
        "description": _clean(alert.get("description"), 1000),
        "severity": _clean(alert.get("severity"), 20),
        "confidence": alert.get("confidence"),
        "sourceIp": _clean(alert.get("sourceIp"), 80),
        "user": _clean(alert.get("user"), 120),
        "host": _clean(alert.get("host"), 120),
        "timestamp": _clean(alert.get("timestamp"), 80),
        "explanation": [
            _clean(item, 500) for item in alert.get("explanation", []) if _clean(item)
        ],
        "mitre": {
            "id": _clean(mitre.get("id"), 40),
            "name": _clean(mitre.get("name"), 160),
            "tactic": _clean(mitre.get("tactic"), 120),
        },
    }


def build_evidence_packet(incident):
    payload = incident.get("payload") if isinstance(incident.get("payload"), dict) else {}
    raw_alerts = payload.get("alerts")
    if not isinstance(raw_alerts, list):
        raw_alert = payload.get("alert")
        raw_alerts = [raw_alert] if isinstance(raw_alert, dict) else []
    raw_events = payload.get("evidence")
    if not isinstance(raw_events, list):
        raw_events = []
    for alert in raw_alerts:
        if isinstance(alert, dict) and isinstance(alert.get("events"), list):
            raw_events.extend(alert["events"])

    packet = {
        "incident": {
            "id": incident.get("id"),
            "title": _clean(incident.get("title"), 200),
            "severity": _clean(incident.get("severity"), 20),
            "status": _clean(incident.get("status"), 40),
            "sourceName": _clean(incident.get("source_name"), 255),
            "riskScore": incident.get("risk_score", 0),
            "ruleId": _clean(incident.get("rule_id"), 120),
            "mitreId": _clean(incident.get("mitre_id"), 40),
        },
        "alerts": [_alert_view(alert) for alert in raw_alerts[:50]],
        "events": [_event_view(event) for event in raw_events[:200]],
    }
    encoded = json.dumps(packet, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return packet, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_summary(summary):
    if not isinstance(summary, dict):
        raise ApiError("Summary provider returned an invalid object.", code="invalid_summary")
    normalized = {}
    for field in ("executiveSummary", "technicalSummary", "riskExplanation"):
        text = _clean(summary.get(field), 5000)
        if not text:
            raise ApiError(f"Summary field {field} is required.", code="invalid_summary")
        normalized[field] = text
    for field in (
        "suspiciousBehaviour",
        "investigationSteps",
        "containmentActions",
        "evidenceLimitations",
    ):
        values = summary.get(field, [])
        if not isinstance(values, list):
            raise ApiError(f"Summary field {field} must be an array.", code="invalid_summary")
        normalized[field] = [_clean(value, 1000) for value in values if _clean(value)]
    techniques = summary.get("mitreTechniques", [])
    if not isinstance(techniques, list):
        raise ApiError("Summary MITRE techniques must be an array.", code="invalid_summary")
    normalized["mitreTechniques"] = [
        {
            "id": _clean(item.get("id"), 40),
            "name": _clean(item.get("name"), 160),
            "evidence": _clean(item.get("evidence"), 1000),
        }
        for item in techniques
        if isinstance(item, dict) and _clean(item.get("id"))
    ]
    return normalized


class LocalEvidenceProvider:
    name = "local-evidence"
    model = "deterministic-v1"

    def generate(self, evidence):
        incident = evidence["incident"]
        alerts = evidence["alerts"]
        events = evidence["events"]
        alert_titles = [item["title"] for item in alerts if item.get("title")]
        entities = sorted(
            {
                value
                for item in alerts
                for value in (item.get("sourceIp"), item.get("user"), item.get("host"))
                if value
            }
        )
        techniques = []
        seen = set()
        for alert in alerts:
            mitre = alert.get("mitre", {})
            technique_id = mitre.get("id")
            if not technique_id or technique_id in seen:
                continue
            seen.add(technique_id)
            techniques.append(
                {
                    "id": technique_id,
                    "name": mitre.get("name") or "Mapped technique",
                    "evidence": f"Mapped by alert: {alert.get('title') or alert.get('ruleId')}.",
                }
            )
        if not techniques and incident.get("mitreId"):
            techniques.append(
                {
                    "id": incident["mitreId"],
                    "name": "Incident mapping",
                    "evidence": "Stored on the incident record.",
                }
            )

        executive = (
            f"Incident #{incident['id']} contains {len(alerts)} alert"
            f"{'' if len(alerts) == 1 else 's'} and {len(events)} supporting event"
            f"{'' if len(events) == 1 else 's'}. "
        )
        executive += (
            f"The recorded risk is {incident.get('severity') or 'Unknown'} "
            f"({incident.get('riskScore', 0)}/100)."
        )
        technical = (
            f"Observed detections: {', '.join(alert_titles)}."
            if alert_titles
            else "No alert titles were present in the saved evidence."
        )
        if entities:
            technical += f" Recorded entities: {', '.join(entities[:12])}."

        suspicious = []
        for alert in alerts:
            detail = alert.get("description") or alert.get("title")
            if detail:
                suspicious.append(detail)
        limitations = []
        if not events:
            limitations.append("No supporting event records were saved with this incident.")
        if not alerts:
            limitations.append("No alert records were saved with this incident.")
        if not entities:
            limitations.append("No source IP, user, or host entity was present in the alert evidence.")
        if not techniques:
            limitations.append("No MITRE ATT&CK mapping was present in the evidence.")

        entity_text = ", ".join(entities[:6]) or "the recorded hosts, users, and source addresses"
        return {
            "executiveSummary": executive,
            "technicalSummary": technical,
            "suspiciousBehaviour": suspicious,
            "mitreTechniques": techniques,
            "riskExplanation": (
                f"The risk level is based on the stored severity "
                f"{incident.get('severity') or 'Unknown'} and risk score "
                f"{incident.get('riskScore', 0)}. No additional risk was inferred."
            ),
            "investigationSteps": [
                f"Validate the recorded activity for {entity_text} against approved administration or user activity.",
                "Review the supporting event timestamps and sequence around each saved alert.",
                "Confirm whether the detected accounts, processes, and commands were expected.",
            ],
            "containmentActions": [
                "If investigation confirms unauthorized activity, isolate the affected host using the organization's approved process.",
                "If an account is confirmed compromised, reset credentials and revoke active sessions according to policy.",
                "Preserve the original logs and relevant endpoint evidence before remediation.",
            ],
            "evidenceLimitations": limitations,
        }


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key, model, timeout):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate(self, evidence):
        request_body = {
            "model": self.model,
            "store": False,
            "instructions": SYSTEM_INSTRUCTIONS,
            "input": json.dumps(evidence, ensure_ascii=False),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "incident_summary",
                    "strict": True,
                    "schema": SUMMARY_SCHEMA,
                }
            },
        }
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(request_body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise ApiError(
                f"OpenAI summary request failed ({error.code}).",
                status=502,
                code="ai_provider_error",
                details={"providerResponse": body[:500]},
            ) from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise ApiError(
                "OpenAI summary request could not be completed.",
                status=502,
                code="ai_provider_error",
            ) from error

        text = payload.get("output_text")
        if not text:
            for item in payload.get("output", []):
                for content in item.get("content", []):
                    if content.get("type") == "output_text":
                        text = content.get("text")
                        break
                if text:
                    break
        if not text:
            raise ApiError(
                "OpenAI returned no summary text.",
                status=502,
                code="ai_provider_error",
            )
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            raise ApiError(
                "OpenAI returned an unreadable structured summary.",
                status=502,
                code="ai_provider_error",
            ) from error


class SummaryEngine:
    def __init__(self, settings):
        self.configured = bool(settings.openai_api_key)
        self.provider = (
            OpenAIProvider(
                settings.openai_api_key,
                settings.openai_model,
                settings.ai_timeout_seconds,
            )
            if self.configured
            else LocalEvidenceProvider()
        )

    def status(self):
        return {
            "configured": self.configured,
            "provider": self.provider.name,
            "model": self.provider.model,
            "dataLeavesDevice": self.configured,
        }

    def generate(self, incident):
        evidence, evidence_hash = build_evidence_packet(incident)
        summary = validate_summary(self.provider.generate(evidence))
        return {
            "provider": self.provider.name,
            "model": self.provider.model,
            "evidenceHash": evidence_hash,
            "summary": summary,
        }
