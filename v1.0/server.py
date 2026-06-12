import json
import os
import sqlite3
import subprocess
import tempfile
import urllib.parse
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("SENTINELOPS_DB", ROOT / "sentinelops.db"))
HOST = "127.0.0.1"
PORT = int(os.environ.get("SENTINELOPS_PORT", "8080"))
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_EVENTS = 5000
ALLOWED_CHANNELS = {
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-PowerShellCore/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source_name TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                alert_count INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS collection_checkpoints (
                channel TEXT PRIMARY KEY,
                record_id INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def run_powershell(script, timeout=90):
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        if "No events were found that match" in message:
            return []
        raise RuntimeError(message or "PowerShell could not read the requested event log.")
    output = completed.stdout.strip()
    if not output:
        return []
    parsed = json.loads(output)
    return parsed if isinstance(parsed, list) else [parsed]


def powershell_event_projection(event_source):
    return f"""
    $events = {event_source}
    $result = foreach ($event in $events) {{
      $xml = [xml]$event.ToXml()
      $data = @{{}}
      foreach ($node in $xml.Event.EventData.Data) {{
        if ($node.Name) {{ $data[$node.Name] = [string]$node.'#text' }}
      }}
      [pscustomobject]@{{
        timestamp = $event.TimeCreated.ToUniversalTime().ToString('o')
        event_id = $event.Id
        provider = $event.ProviderName
        level = $event.LevelDisplayName
        record_id = $event.RecordId
        host = $event.MachineName
        user = if ($data.TargetUserName) {{ $data.TargetUserName }} elseif ($data.SubjectUserName) {{ $data.SubjectUserName }} else {{ '' }}
        source_ip = if ($data.IpAddress) {{ $data.IpAddress }} elseif ($data.SourceNetworkAddress) {{ $data.SourceNetworkAddress }} elseif ($data.ClientAddress) {{ $data.ClientAddress }} elseif ($data.SourceAddress) {{ $data.SourceAddress }} elseif ($data.RemoteAddress) {{ $data.RemoteAddress }} elseif ($data.DestinationIp) {{ $data.DestinationIp }} else {{ '' }}
        process = if ($data.NewProcessName) {{ $data.NewProcessName }} elseif ($data.Image) {{ $data.Image }} else {{ '' }}
        command = if ($data.CommandLine) {{ $data.CommandLine }} elseif ($data.ProcessCommandLine) {{ $data.ProcessCommandLine }} elseif ($data.ScriptBlockText) {{ $data.ScriptBlockText }} else {{ '' }}
        group = if ($data.TargetUserName -and $event.Id -in 4728,4732,4756) {{ $data.TargetUserName }} else {{ '' }}
        privileges = if ($data.PrivilegeList) {{ $data.PrivilegeList }} else {{ '' }}
        status = if ($event.Id -eq 4625) {{ 'failed' }} elseif ($event.Id -eq 4624) {{ 'success' }} else {{ 'unknown' }}
        message = $event.Message
        event_data = $data
      }}
    }}
    @($result) | ConvertTo-Json -Depth 6 -Compress
    """


def get_checkpoint(channel):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT record_id FROM collection_checkpoints WHERE channel = ?",
            (channel,),
        ).fetchone()
    return int(row["record_id"]) if row else 0


def save_checkpoint(channel, record_id):
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO collection_checkpoints (channel, record_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(channel) DO UPDATE SET
                record_id = excluded.record_id,
                updated_at = excluded.updated_at
            """,
            (channel, int(record_id), utc_now()),
        )


def reset_checkpoint(channel):
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM collection_checkpoints WHERE channel = ?", (channel,)
        )


def collect_windows_events(channel, maximum, after_record_id=0):
    if channel not in ALLOWED_CHANNELS:
        raise ValueError("That Windows event channel is not allowed.")
    maximum = max(1, min(int(maximum), MAX_EVENTS))
    channel_literal = channel.replace("'", "''")
    after_record_id = max(0, int(after_record_id))
    if after_record_id:
        xpath = f"*[System[EventRecordID > {after_record_id}]]"
        source = (
            f"Get-WinEvent -LogName '{channel_literal}' "
            f"-FilterXPath '{xpath}' -Oldest -MaxEvents {maximum} -ErrorAction Stop"
        )
    else:
        source = (
            f"Get-WinEvent -LogName '{channel_literal}' -MaxEvents {maximum} "
            "-ErrorAction Stop"
        )
    return run_powershell(powershell_event_projection(source))


def parse_evtx(path, maximum):
    maximum = max(1, min(int(maximum), MAX_EVENTS))
    path_literal = str(path).replace("'", "''")
    source = (
        f"Get-WinEvent -Path '{path_literal}' -MaxEvents {maximum} "
        "-ErrorAction Stop"
    )
    return run_powershell(powershell_event_projection(source), timeout=180)


class SentinelHandler(SimpleHTTPRequestHandler):
    server_version = "SentinelOps/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, format_string, *args):
        print(f"[{self.log_date_time_string()}] {format_string % args}")

    def send_json(self, payload, status=200):
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            raise ValueError("Request body is empty or too large.")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            requested = Path(urllib.parse.unquote(parsed.path))
            blocked_suffixes = {".db", ".py", ".pyc", ".ps1"}
            if requested.suffix.lower() in blocked_suffixes or any(
                part.startswith(".") for part in requested.parts if part not in {"/", "\\"}
            ):
                return self.send_error(404, "File not found")
            return super().do_GET()

        try:
            if parsed.path == "/api/status":
                return self.send_json(
                    {
                        "online": True,
                        "platform": os.name,
                        "windowsCollection": os.name == "nt",
                        "database": DATABASE.name,
                    }
                )

            if parsed.path == "/api/windows-events":
                query = urllib.parse.parse_qs(parsed.query)
                channel = query.get("channel", ["Security"])[0]
                maximum = query.get("max", ["500"])[0]
                incremental = query.get("incremental", ["true"])[0].lower() != "false"
                previous_checkpoint = get_checkpoint(channel) if incremental else 0
                events = collect_windows_events(channel, maximum, previous_checkpoint)
                checkpoint_reset = False
                if incremental and previous_checkpoint and not events:
                    latest = collect_windows_events(channel, 1)
                    latest_ids = [
                        int(event["record_id"])
                        for event in latest
                        if str(event.get("record_id", "")).isdigit()
                    ]
                    if latest_ids and max(latest_ids) < previous_checkpoint:
                        reset_checkpoint(channel)
                        previous_checkpoint = 0
                        checkpoint_reset = True
                        events = collect_windows_events(channel, maximum)
                record_ids = [
                    int(event["record_id"])
                    for event in events
                    if str(event.get("record_id", "")).isdigit()
                ]
                checkpoint = max(record_ids, default=previous_checkpoint)
                if incremental and checkpoint:
                    save_checkpoint(channel, checkpoint)
                return self.send_json(
                    {
                        "events": events,
                        "sourceName": f"Live: {channel}",
                        "incremental": incremental,
                        "previousCheckpoint": previous_checkpoint,
                        "checkpoint": checkpoint,
                        "newCount": len(events),
                        "checkpointReset": checkpoint_reset,
                    }
                )

            if parsed.path == "/api/analyses":
                with get_connection() as connection:
                    rows = connection.execute(
                        """
                        SELECT id, created_at, source_name, event_count, alert_count,
                               risk_score, risk_level
                        FROM analyses
                        ORDER BY id DESC
                        LIMIT 100
                        """
                    ).fetchall()
                return self.send_json({"analyses": [dict(row) for row in rows]})

            if parsed.path.startswith("/api/analyses/"):
                analysis_id = int(parsed.path.rsplit("/", 1)[-1])
                with get_connection() as connection:
                    row = connection.execute(
                        "SELECT payload FROM analyses WHERE id = ?", (analysis_id,)
                    ).fetchone()
                if not row:
                    return self.send_json({"error": "Analysis not found."}, 404)
                return self.send_json(json.loads(row["payload"]))

            return self.send_json({"error": "API endpoint not found."}, 404)
        except (ValueError, json.JSONDecodeError) as error:
            return self.send_json({"error": str(error)}, 400)
        except subprocess.TimeoutExpired:
            return self.send_json(
                {"error": "Windows event collection timed out."}, 504
            )
        except Exception as error:
            return self.send_json({"error": str(error)}, 500)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/import-evtx":
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_UPLOAD_BYTES:
                    raise ValueError("EVTX file is empty or exceeds the 100 MB limit.")
                filename = urllib.parse.unquote(
                    self.headers.get("X-Filename", "uploaded.evtx")
                )
                if Path(filename).suffix.lower() != ".evtx":
                    raise ValueError("Only .evtx files are accepted by this endpoint.")
                query = urllib.parse.parse_qs(parsed.query)
                maximum = query.get("max", [str(MAX_EVENTS)])[0]
                with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as handle:
                    temporary_path = Path(handle.name)
                    remaining = length
                    while remaining:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        handle.write(chunk)
                        remaining -= len(chunk)
                try:
                    events = parse_evtx(temporary_path, maximum)
                finally:
                    temporary_path.unlink(missing_ok=True)
                return self.send_json(
                    {"events": events, "sourceName": Path(filename).name}
                )

            if parsed.path == "/api/windows-checkpoint/reset":
                payload = self.read_json()
                channel = str(payload.get("channel", ""))
                if channel not in ALLOWED_CHANNELS:
                    raise ValueError("That Windows event channel is not allowed.")
                reset_checkpoint(channel)
                return self.send_json({"reset": True, "channel": channel})

            if parsed.path == "/api/analyses":
                payload = self.read_json()
                required = {
                    "sourceName",
                    "events",
                    "alerts",
                    "riskScore",
                    "riskLevel",
                }
                if not required.issubset(payload):
                    raise ValueError("Analysis payload is missing required fields.")
                serialized = json.dumps(payload, ensure_ascii=False)
                with get_connection() as connection:
                    cursor = connection.execute(
                        """
                        INSERT INTO analyses (
                            created_at, source_name, event_count, alert_count,
                            risk_score, risk_level, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            utc_now(),
                            str(payload["sourceName"])[:255],
                            len(payload["events"]),
                            len(payload["alerts"]),
                            int(payload["riskScore"]),
                            str(payload["riskLevel"])[:16],
                            serialized,
                        ),
                    )
                return self.send_json({"saved": True, "id": cursor.lastrowid}, 201)

            return self.send_json({"error": "API endpoint not found."}, 404)
        except (ValueError, json.JSONDecodeError) as error:
            return self.send_json({"error": str(error)}, 400)
        except subprocess.TimeoutExpired:
            return self.send_json({"error": "EVTX parsing timed out."}, 504)
        except Exception as error:
            return self.send_json({"error": str(error)}, 500)


def main():
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), SentinelHandler)
    print(f"SentinelOps is running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SentinelOps.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
