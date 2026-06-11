import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _positive_int(name, default, maximum=None):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer.") from error
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return min(value, maximum) if maximum else value


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    database: Path
    static_dir: Path
    log_level: str
    max_upload_bytes: int
    max_events: int
    openai_api_key: str = ""
    openai_model: str = "gpt-5.5"
    ai_timeout_seconds: int = 45

    @classmethod
    def from_env(cls):
        return cls(
            host=os.environ.get("SENTINELOPS_V2_HOST", "127.0.0.1"),
            port=_positive_int("SENTINELOPS_V2_PORT", 8081, 65535),
            database=Path(
                os.environ.get("SENTINELOPS_V2_DB", ROOT / "sentinelops-v2.db")
            ).resolve(),
            static_dir=ROOT / "frontend",
            log_level=os.environ.get("SENTINELOPS_V2_LOG_LEVEL", "INFO").upper(),
            max_upload_bytes=_positive_int(
                "SENTINELOPS_V2_MAX_UPLOAD_BYTES", 100 * 1024 * 1024
            ),
            max_events=_positive_int("SENTINELOPS_V2_MAX_EVENTS", 5000, 50000),
            openai_api_key=os.environ.get("OPENAI_API_KEY", "").strip(),
            openai_model=os.environ.get(
                "SENTINELOPS_OPENAI_MODEL", "gpt-5.5"
            ).strip(),
            ai_timeout_seconds=_positive_int(
                "SENTINELOPS_AI_TIMEOUT_SECONDS", 45, 180
            ),
        )
