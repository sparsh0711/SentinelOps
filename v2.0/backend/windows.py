import json
import os
import subprocess

from .errors import ApiError


ALLOWED_CHANNELS = {
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-PowerShellCore/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational",
}


def _projection(source):
    return f"""
    $events = {source}
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
        record_id = $event.RecordId
        host = $event.MachineName
        user = if ($data.TargetUserName) {{ $data.TargetUserName }} elseif ($data.SubjectUserName) {{ $data.SubjectUserName }} else {{ '' }}
        source_ip = if ($data.IpAddress) {{ $data.IpAddress }} elseif ($data.SourceNetworkAddress) {{ $data.SourceNetworkAddress }} elseif ($data.ClientAddress) {{ $data.ClientAddress }} else {{ '' }}
        process = if ($data.NewProcessName) {{ $data.NewProcessName }} elseif ($data.Image) {{ $data.Image }} else {{ '' }}
        command = if ($data.CommandLine) {{ $data.CommandLine }} elseif ($data.ScriptBlockText) {{ $data.ScriptBlockText }} else {{ '' }}
        group = if ($data.TargetUserName -and $event.Id -in 4728,4732,4756) {{ $data.TargetUserName }} else {{ '' }}
        privileges = if ($data.PrivilegeList) {{ $data.PrivilegeList }} else {{ '' }}
        status = if ($event.Id -eq 4625) {{ 'failed' }} elseif ($event.Id -eq 4624) {{ 'success' }} else {{ 'unknown' }}
        message = $event.Message
        event_data = $data
      }}
    }}
    @($result) | ConvertTo-Json -Depth 6 -Compress
    """


def _run(script, timeout=120):
    if os.name != "nt":
        raise ApiError(
            "Windows event collection is unavailable on this operating system.",
            status=501,
            code="windows_unavailable",
        )
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
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
        raise ApiError(
            message or "PowerShell could not read the event log.",
            status=422,
            code="event_collection_failed",
        )
    output = completed.stdout.strip()
    if not output:
        return []
    parsed = json.loads(output)
    return parsed if isinstance(parsed, list) else [parsed]


def collect(channel, maximum, after_record_id=0):
    if channel not in ALLOWED_CHANNELS:
        raise ApiError("That Windows event channel is not allowed.")
    channel = channel.replace("'", "''")
    if after_record_id:
        source = (
            f"Get-WinEvent -LogName '{channel}' "
            f"-FilterXPath '*[System[EventRecordID > {int(after_record_id)}]]' "
            f"-Oldest -MaxEvents {maximum} -ErrorAction Stop"
        )
    else:
        source = (
            f"Get-WinEvent -LogName '{channel}' -MaxEvents {maximum} "
            "-ErrorAction Stop"
        )
    return _run(_projection(source))


def parse_evtx(path, maximum):
    safe_path = str(path).replace("'", "''")
    source = (
        f"Get-WinEvent -Path '{safe_path}' -MaxEvents {maximum} -ErrorAction Stop"
    )
    return _run(_projection(source), timeout=180)
