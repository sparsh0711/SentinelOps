const firstValue = (object, keys, fallback = "") => {
  for (const key of keys) {
    const direct = object[key];
    if (direct !== undefined && direct !== null && direct !== "") return direct;
    const found = Object.keys(object).find((candidate) => candidate.toLowerCase() === key.toLowerCase());
    if (found && object[found] !== undefined && object[found] !== null && object[found] !== "") return object[found];
  }
  return fallback;
};

export function normalizeSourceIp(value) {
  const text = String(value ?? "").trim().replace(/^\[|\]$/g, "");
  if (!text || ["-", "::", "unknown", "n/a", "null", "0.0.0.0"].includes(text.toLowerCase())) return "unknown";
  const ipv4 = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];
  if (ipv4 && ipv4.split(".").every((part) => Number(part) <= 255)) return ipv4;
  if (/^[0-9a-f:]+$/i.test(text) && text.includes(":")) return text;
  return "unknown";
}

export function normalizeEvent(raw, index = 0) {
  const message = String(firstValue(raw, ["message", "description", "Message"], ""));
  const eventId = String(firstValue(raw, ["event_id", "eventid", "EventID", "id"], ""));
  const destinationIp = normalizeSourceIp(firstValue(raw, ["destination_ip", "dest_ip", "dst_ip", "DestinationIp", "DestinationIpAddress"], ""));
  let status = String(firstValue(raw, ["status", "result", "outcome"], "")).toLowerCase();
  if (!status) {
    status = eventId === "4625" || /failed|failure|invalid|denied/i.test(message)
      ? "failed"
      : eventId === "4624" || /success|accepted/i.test(message) ? "success" : "unknown";
  }
  return {
    id: `event-${index}`,
    timestamp: firstValue(raw, ["timestamp", "time", "@timestamp", "datetime", "TimeCreated"], new Date().toISOString()),
    eventId,
    user: String(firstValue(raw, ["user", "username", "account", "TargetUserName"], "unknown")),
    sourceIp: normalizeSourceIp(firstValue(raw, ["source_ip", "src_ip", "ip", "client_ip", "IpAddress", "SourceNetworkAddress"], "")),
    host: String(firstValue(raw, ["host", "hostname", "computer", "Computer"], "unknown")),
    status,
    message,
    process: String(firstValue(raw, ["process", "process_name", "Image", "NewProcessName"], "")),
    parentProcess: String(firstValue(raw, ["parent_process", "parentProcess", "ParentImage", "ParentProcessName"], "")),
    command: String(firstValue(raw, ["command", "commandline", "CommandLine", "ScriptBlockText"], "")),
    group: String(firstValue(raw, ["group", "group_name"], "")),
    privileges: String(firstValue(raw, ["privileges", "PrivilegeList"], "")),
    logonType: String(firstValue(raw, ["logon_type", "logonType", "LogonType"], "")),
    destinationIp,
    destinationPort: String(firstValue(raw, ["destination_port", "dest_port", "DestinationPort"], "")),
    targetFilename: String(firstValue(raw, ["target_filename", "targetFilename", "TargetFilename"], "")),
    registryKey: String(firstValue(raw, ["registry_key", "registryKey", "TargetObject", "ObjectName"], "")),
    serviceName: String(firstValue(raw, ["service_name", "serviceName", "ServiceName"], "")),
    hash: String(firstValue(raw, ["hash", "hashes", "Hashes"], "")),
    raw,
  };
}

function parseCsvLine(line) {
  const values = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"' && line[index + 1] === '"' && quoted) { value += '"'; index += 1; }
    else if (char === '"') quoted = !quoted;
    else if (char === "," && !quoted) { values.push(value.trim()); value = ""; }
    else value += char;
  }
  values.push(value.trim());
  return values;
}

export function parseLogs(text) {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Choose a real log file or paste log data.");
  try {
    const parsed = JSON.parse(trimmed);
    const rows = Array.isArray(parsed) ? parsed : parsed.events || parsed.logs || [parsed];
    if (!Array.isArray(rows)) throw new Error();
    return rows;
  } catch {
    const lines = trimmed.split(/\r?\n/).filter(Boolean);
    const jsonLines = lines.map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    });
    if (jsonLines.every(Boolean)) return jsonLines;
    if (lines[0]?.includes(",") && /timestamp|event|user|source|status|message/i.test(lines[0])) {
      const headers = parseCsvLine(lines[0]);
      return lines.slice(1).map((line) => {
        const values = parseCsvLine(line);
        return Object.fromEntries(headers.map((header, index) => [header, values[index] || ""]));
      });
    }
    return lines.map((line) => ({
      timestamp: line.match(/\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?/)?.[0] || new Date().toISOString(),
      source_ip: line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || "",
      user: line.match(/(?:user|for|account)[=:\s]+(?:invalid user\s+)?([^\s,;]+)/i)?.[1] || "unknown",
      status: /failed|failure|invalid|denied/i.test(line) ? "failed" : /accepted|success/i.test(line) ? "success" : "unknown",
      command: /powershell/i.test(line) ? line : "",
      message: line,
    }));
  }
}
