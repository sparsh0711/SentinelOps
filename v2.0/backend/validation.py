from pathlib import Path

from .errors import ApiError


ALLOWED_RISK_LEVELS = {"Low", "Medium", "High"}
ALLOWED_OPERATORS = {"equals", "contains", "regex", "in", "exists"}


def bounded_int(value, name, default, minimum=1, maximum=5000):
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ApiError(f"{name} must be an integer.", code="invalid_parameter") from error
    if parsed < minimum or parsed > maximum:
        raise ApiError(
            f"{name} must be between {minimum} and {maximum}.",
            code="invalid_parameter",
        )
    return parsed


def validate_evtx_filename(filename):
    safe_name = Path(filename or "").name
    if not safe_name or Path(safe_name).suffix.lower() != ".evtx":
        raise ApiError("Only .evtx files are accepted.", code="invalid_file_type")
    return safe_name


def validate_analysis(payload):
    if not isinstance(payload, dict):
        raise ApiError("Analysis payload must be a JSON object.", code="invalid_payload")
    required = ("sourceName", "events", "alerts", "riskScore", "riskLevel")
    missing = [field for field in required if field not in payload]
    if missing:
        raise ApiError(
            "Analysis payload is missing required fields.",
            code="invalid_payload",
            details={"missing": missing},
        )
    if not isinstance(payload["events"], list) or not isinstance(payload["alerts"], list):
        raise ApiError("events and alerts must be arrays.", code="invalid_payload")
    score = bounded_int(payload["riskScore"], "riskScore", 0, minimum=0, maximum=100)
    level = str(payload["riskLevel"]).title()
    if level not in ALLOWED_RISK_LEVELS:
        raise ApiError("riskLevel must be Low, Medium, or High.", code="invalid_payload")
    return {
        **payload,
        "sourceName": str(payload["sourceName"])[:255] or "Unnamed analysis",
        "riskScore": score,
        "riskLevel": level,
    }


def validate_rule(payload):
    if not isinstance(payload, dict):
        raise ApiError("Rule payload must be a JSON object.", code="invalid_rule")
    required = ("id", "title", "description", "level", "match", "mitre")
    missing = [field for field in required if field not in payload]
    if missing:
        raise ApiError(
            "Detection rule is missing required fields.",
            code="invalid_rule",
            details={"missing": missing},
        )
    rule_id = str(payload["id"]).strip()
    if not rule_id or len(rule_id) > 120 or not all(
        char.isalnum() or char in "-_." for char in rule_id
    ):
        raise ApiError("Rule ID contains unsupported characters.", code="invalid_rule")
    level = str(payload["level"]).title()
    if level not in ALLOWED_RISK_LEVELS:
        raise ApiError("Rule level must be Low, Medium, or High.", code="invalid_rule")
    match = payload["match"]
    if not isinstance(match, dict) or not any(key in match for key in ("all", "any")):
        raise ApiError("Rule match must define all or any conditions.", code="invalid_rule")
    for mode in ("all", "any"):
        conditions = match.get(mode, [])
        if not isinstance(conditions, list):
            raise ApiError(f"Rule match.{mode} must be an array.", code="invalid_rule")
        for condition in conditions:
            if not isinstance(condition, dict):
                raise ApiError("Each rule condition must be an object.", code="invalid_rule")
            if condition.get("operator") not in ALLOWED_OPERATORS:
                raise ApiError("Rule condition uses an unsupported operator.", code="invalid_rule")
            if not str(condition.get("field", "")).strip():
                raise ApiError("Rule condition field is required.", code="invalid_rule")
    threshold = payload.get("threshold")
    if threshold is not None:
        if not isinstance(threshold, dict):
            raise ApiError("Rule threshold must be an object.", code="invalid_rule")
        threshold = {
            "count": bounded_int(threshold.get("count"), "threshold.count", 1, maximum=10000),
            "groupBy": str(threshold.get("groupBy", "")).strip(),
            "windowSeconds": bounded_int(
                threshold.get("windowSeconds"),
                "threshold.windowSeconds",
                300,
                maximum=86400,
            ),
        }
    mitre = payload["mitre"]
    if not isinstance(mitre, dict) or not mitre.get("id") or not mitre.get("name"):
        raise ApiError("Rule MITRE mapping requires id and name.", code="invalid_rule")
    return {
        **payload,
        "id": rule_id,
        "title": str(payload["title"]).strip()[:200],
        "description": str(payload["description"]).strip()[:1000],
        "level": level,
        "enabled": bool(payload.get("enabled", True)),
        "confidence": bounded_int(
            payload.get("confidence"), "confidence", 50, minimum=0, maximum=100
        ),
        "threshold": threshold,
    }


def validate_detection_settings(payload):
    if not isinstance(payload, dict):
        raise ApiError("Detection settings must be a JSON object.")
    allowlists = payload.get("allowlists", {})
    if not isinstance(allowlists, dict):
        raise ApiError("allowlists must be an object.")
    normalized = {}
    for key in ("users", "hosts", "sourceIps", "processes"):
        values = allowlists.get(key, [])
        if not isinstance(values, list):
            raise ApiError(f"allowlists.{key} must be an array.")
        normalized[key] = sorted(
            {str(value).strip() for value in values if str(value).strip()}
        )
    severity_overrides = payload.get("severityOverrides", {})
    if not isinstance(severity_overrides, dict):
        raise ApiError("severityOverrides must be an object.")
    normalized_severity = {}
    for rule_id, level in severity_overrides.items():
        normalized_level = str(level).title()
        if normalized_level not in ALLOWED_RISK_LEVELS:
            raise ApiError("Severity overrides must be Low, Medium, or High.")
        normalized_severity[str(rule_id)] = normalized_level
    threshold_overrides = payload.get("thresholdOverrides", {})
    if not isinstance(threshold_overrides, dict):
        raise ApiError("thresholdOverrides must be an object.")
    normalized_thresholds = {}
    for rule_id, threshold in threshold_overrides.items():
        if not isinstance(threshold, dict):
            raise ApiError("Each threshold override must be an object.")
        normalized_thresholds[str(rule_id)] = {
            "count": bounded_int(
                threshold.get("count"), "thresholdOverrides.count", 1, maximum=10000
            ),
            "windowSeconds": bounded_int(
                threshold.get("windowSeconds"),
                "thresholdOverrides.windowSeconds",
                300,
                maximum=86400,
            ),
        }
    return {
        "allowlists": normalized,
        "suppressionWindowSeconds": bounded_int(
            payload.get("suppressionWindowSeconds"),
            "suppressionWindowSeconds",
            300,
            maximum=86400,
        ),
        "severityOverrides": normalized_severity,
        "thresholdOverrides": normalized_thresholds,
    }
