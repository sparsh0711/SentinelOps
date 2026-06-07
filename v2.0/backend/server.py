import json
import logging
import time
import urllib.parse
import uuid
from http.server import SimpleHTTPRequestHandler
from pathlib import Path

from .errors import ApiError


LOGGER = logging.getLogger("sentinelops.http")


class SentinelHandler(SimpleHTTPRequestHandler):
    server_version = "SentinelOps/2.0"

    def __init__(self, *args, api=None, settings=None, **kwargs):
        self.api = api
        self.settings = settings
        super().__init__(*args, directory=str(settings.static_dir), **kwargs)

    def log_message(self, format_string, *args):
        return

    def _json(self, payload, status=200, request_id=None):
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", request_id or "")
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > self.settings.max_upload_bytes:
            raise ApiError("Request body is empty or too large.", status=413)
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ApiError("Request body must contain valid JSON.") from error

    def _handle(self, method):
        started = time.perf_counter()
        request_id = uuid.uuid4().hex
        parsed = urllib.parse.urlparse(self.path)
        status = 500
        try:
            if method == "GET":
                payload, status = self.api.get(parsed.path, parsed.query)
            elif parsed.path == "/api/v2/imports/evtx":
                payload, status = self.api.import_evtx(
                    urllib.parse.unquote(
                        self.headers.get("X-Filename", "uploaded.evtx")
                    ),
                    self.rfile,
                    int(self.headers.get("Content-Length", "0")),
                    parsed.query,
                )
            else:
                payload, status = self.api.post_json(parsed.path, self._read_json())
            self._json(payload, status, request_id)
        except ApiError as error:
            status = error.status
            self._json(
                {
                    "error": {
                        "code": error.code,
                        "message": error.message,
                        "details": error.details,
                        "requestId": request_id,
                    }
                },
                status,
                request_id,
            )
        except Exception:
            LOGGER.exception("Unhandled request error", extra={"request_id": request_id})
            self._json(
                {
                    "error": {
                        "code": "internal_error",
                        "message": "The local service encountered an unexpected error.",
                        "requestId": request_id,
                    }
                },
                500,
                request_id,
            )
        finally:
            LOGGER.info(
                "request_complete",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "path": parsed.path,
                    "status": status,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/"):
            return self._handle("GET")
        requested = Path(urllib.parse.unquote(parsed.path))
        if any(part.startswith(".") for part in requested.parts):
            return self.send_error(404, "File not found")
        return super().do_GET()

    def do_POST(self):
        return self._handle("POST")
