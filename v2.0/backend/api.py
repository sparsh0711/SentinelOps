import os
import tempfile
from pathlib import Path
from urllib.parse import parse_qs

from . import __version__
from .errors import ApiError
from .validation import bounded_int, validate_analysis, validate_evtx_filename
from .windows import ALLOWED_CHANNELS, collect, parse_evtx


class Api:
    def __init__(self, settings, database):
        self.settings = settings
        self.database = database

    def get(self, path, query):
        params = parse_qs(query)
        if path == "/api/v2/status":
            return {
                "version": __version__,
                "online": True,
                "platform": os.name,
                "windowsCollection": os.name == "nt",
                "api": "/api/v2",
            }, 200
        if path == "/api/v2/analyses":
            limit = bounded_int(
                params.get("limit", [100])[0], "limit", 100, maximum=100
            )
            return {"analyses": self.database.list_analyses(limit)}, 200
        if path.startswith("/api/v2/analyses/"):
            try:
                analysis_id = int(path.rsplit("/", 1)[-1])
            except ValueError as error:
                raise ApiError("Analysis ID must be an integer.") from error
            return self.database.get_analysis(analysis_id), 200
        if path == "/api/v2/events/windows":
            channel = params.get("channel", ["Security"])[0]
            maximum = bounded_int(
                params.get("max", [500])[0],
                "max",
                500,
                maximum=self.settings.max_events,
            )
            incremental = params.get("incremental", ["true"])[0].lower() != "false"
            previous = self.database.get_checkpoint(channel) if incremental else 0
            events = collect(channel, maximum, previous)
            record_ids = [
                int(event["record_id"])
                for event in events
                if str(event.get("record_id", "")).isdigit()
            ]
            checkpoint = max(record_ids, default=previous)
            if incremental and checkpoint:
                self.database.save_checkpoint(channel, checkpoint)
            return {
                "events": events,
                "sourceName": f"Live: {channel}",
                "incremental": incremental,
                "previousCheckpoint": previous,
                "checkpoint": checkpoint,
                "newCount": len(events),
            }, 200
        raise ApiError("API endpoint not found.", status=404, code="not_found")

    def post_json(self, path, payload):
        if path == "/api/v2/analyses":
            analysis = validate_analysis(payload)
            analysis_id = self.database.save_analysis(analysis)
            return {"saved": True, "id": analysis_id}, 201
        if path == "/api/v2/checkpoints/reset":
            channel = str(payload.get("channel", ""))
            if channel not in ALLOWED_CHANNELS:
                raise ApiError("That Windows event channel is not allowed.")
            self.database.reset_checkpoint(channel)
            return {"reset": True, "channel": channel}, 200
        raise ApiError("API endpoint not found.", status=404, code="not_found")

    def import_evtx(self, filename, stream, content_length, query):
        safe_name = validate_evtx_filename(filename)
        if content_length <= 0 or content_length > self.settings.max_upload_bytes:
            raise ApiError(
                "EVTX file is empty or exceeds the upload limit.",
                status=413,
                code="invalid_file_size",
            )
        params = parse_qs(query)
        maximum = bounded_int(
            params.get("max", [self.settings.max_events])[0],
            "max",
            self.settings.max_events,
            maximum=self.settings.max_events,
        )
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as handle:
            temporary_path = Path(handle.name)
            remaining = content_length
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                handle.write(chunk)
                remaining -= len(chunk)
        try:
            events = parse_evtx(temporary_path, maximum)
        finally:
            temporary_path.unlink(missing_ok=True)
        return {"events": events, "sourceName": safe_name}, 200
