from pathlib import Path

from .errors import ApiError


ALLOWED_RISK_LEVELS = {"Low", "Medium", "High"}


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
