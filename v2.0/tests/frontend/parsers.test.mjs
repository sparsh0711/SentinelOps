import test from "node:test";
import assert from "node:assert/strict";

import { normalizeEvent, normalizeSourceIp, parseLogs } from "../../frontend/js/parsers.js";

test("source IP placeholders normalize to unknown", () => {
  assert.equal(normalizeSourceIp("-"), "unknown");
  assert.equal(normalizeSourceIp("0.0.0.0"), "unknown");
  assert.equal(normalizeSourceIp("10.0.2.17"), "10.0.2.17");
});

test("JSON and JSONL logs are parsed", () => {
  assert.equal(parseLogs('[{"event_id":4625}]').length, 1);
  assert.equal(parseLogs('{"event_id":4625}\n{"event_id":4624}').length, 2);
});

test("CSV fields normalize into the event model", () => {
  const parsed = parseLogs("timestamp,event_id,user,source_ip\n2026-01-01T00:00:00Z,4625,alice,203.0.113.10");
  const event = normalizeEvent(parsed[0]);
  assert.equal(event.eventId, "4625");
  assert.equal(event.status, "failed");
  assert.equal(event.sourceIp, "203.0.113.10");
});

test("Sysmon fields normalize into the event model", () => {
  const event = normalizeEvent({
    EventID: 3,
    Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    ParentImage: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    DestinationIp: "198.51.100.20",
    DestinationPort: 443,
    TargetFilename: "C:\\Users\\Public\\loader.exe",
    TargetObject: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    Hashes: "SHA256=abc123",
    LogonType: 10,
  });
  assert.equal(event.eventId, "3");
  assert.match(event.process, /powershell/i);
  assert.match(event.parentProcess, /WINWORD/i);
  assert.equal(event.destinationIp, "198.51.100.20");
  assert.equal(event.destinationPort, "443");
  assert.match(event.targetFilename, /loader\.exe/i);
  assert.match(event.registryKey, /CurrentVersion\\Run/i);
  assert.equal(event.hash, "SHA256=abc123");
  assert.equal(event.logonType, "10");
});
