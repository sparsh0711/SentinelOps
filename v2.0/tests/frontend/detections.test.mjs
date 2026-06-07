import test from "node:test";
import assert from "node:assert/strict";

import { analyzeEvents, isPrivateIp } from "../../frontend/js/detections.js";

const failures = Array.from({ length: 5 }, (_, index) => ({
  timestamp: `2026-01-01T00:0${index}:00Z`,
  event_id: 4625,
  user: "alice",
  source_ip: "203.0.113.10",
  host: "WORKSTATION-1",
}));

test("five failures produce high-risk brute force detection", () => {
  const result = analyzeEvents(failures);
  assert.equal(result.riskLevel, "High");
  assert.ok(result.alerts.some((alert) => alert.type === "brute_force"));
});

test("private addresses are not treated as external", () => {
  assert.equal(isPrivateIp("10.0.2.17"), true);
  assert.equal(isPrivateIp("fe80::1"), true);
  assert.equal(isPrivateIp("203.0.113.10"), false);
});

test("suspicious PowerShell maps to T1059.001", () => {
  const result = analyzeEvents([{
    timestamp: "2026-01-01T00:00:00Z",
    event_id: 4104,
    command: "powershell.exe -EncodedCommand SQBFAFgA",
    host: "WORKSTATION-1",
  }]);
  const finding = result.alerts.find((alert) => alert.type === "powershell");
  assert.equal(finding.mitre.id, "T1059.001");
});
