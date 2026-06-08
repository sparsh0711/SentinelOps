import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { runRuleEngine, testRule } from "../../frontend/js/rule_engine.js";
import { normalizeEvent } from "../../frontend/js/parsers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const defaultRules = JSON.parse(readFileSync(resolve(__dirname, "../../rules/default_rules.json"), "utf8"));

const thresholdRule = {
  id: "threshold-rule",
  title: "Threshold Rule",
  description: "Repeated failures.",
  level: "High",
  enabled: true,
  confidence: 90,
  match: { all: [{ field: "status", operator: "equals", value: "failed" }] },
  threshold: { count: 3, groupBy: "sourceIp", windowSeconds: 60 },
  mitre: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
};

const events = Array.from({ length: 3 }, (_, index) => normalizeEvent({
  timestamp: `2026-01-01T00:00:${index}0Z`,
  event_id: 4625,
  user: "alice",
  source_ip: "203.0.113.10",
  host: "LAB-PC",
}, index));

test("threshold rules explain why they matched", () => {
  const result = testRule(thresholdRule, events, { suppressionWindowSeconds: 300 });
  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].confidence, 90);
  assert.match(result.alerts[0].explanation.join(" "), /Threshold met/);
});

test("allowlists remove trusted events before evaluation", () => {
  const result = runRuleEngine(events, [thresholdRule], {
    allowlists: { users: ["alice"] },
    suppressionWindowSeconds: 300,
  });
  assert.equal(result.alerts.length, 0);
  assert.equal(result.eligibleEventCount, 0);
});

test("threshold and severity overrides are applied", () => {
  const result = runRuleEngine(events.slice(0, 2), [thresholdRule], {
    suppressionWindowSeconds: 300,
    severityOverrides: { "threshold-rule": "Medium" },
    thresholdOverrides: { "threshold-rule": { count: 2, windowSeconds: 30 } },
  });
  assert.equal(result.alerts[0].severity, "Medium");
});

test("duplicate alerts are suppressed inside the configured window", () => {
  const rule = {
    ...thresholdRule,
    id: "single-rule",
    threshold: null,
  };
  const result = runRuleEngine(events, [rule], { suppressionWindowSeconds: 300 });
  assert.equal(result.alerts.length, 1);
});

test("Phase 3 default rules include expanded Windows and Sysmon coverage", () => {
  const ids = new Set(defaultRules.map((rule) => rule.id));
  assert.ok(ids.has("sentinelops-sysmon-lolbin-execution"));
  assert.ok(ids.has("sentinelops-sysmon-network-tool-connection"));
  assert.ok(ids.has("sentinelops-sysmon-autorun-registry"));
  assert.ok(ids.has("sentinelops-defender-tamper"));
  assert.ok(defaultRules.length >= 14);
});

test("Sysmon network rule matches outbound scripting tool traffic", () => {
  const event = normalizeEvent({
    timestamp: "2026-01-01T00:00:00Z",
    event_id: 3,
    Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    DestinationIp: "198.51.100.20",
    DestinationPort: 443,
    Computer: "LAB-PC",
  });
  const result = runRuleEngine(
    [event],
    defaultRules.filter((rule) => rule.id === "sentinelops-sysmon-network-tool-connection"),
    { suppressionWindowSeconds: 300 },
  );
  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].mitre.id, "T1105");
});

test("registry autorun rule matches Run key modification", () => {
  const event = normalizeEvent({
    timestamp: "2026-01-01T00:00:00Z",
    event_id: 13,
    TargetObject: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    Computer: "LAB-PC",
  });
  const result = runRuleEngine(
    [event],
    defaultRules.filter((rule) => rule.id === "sentinelops-sysmon-autorun-registry"),
    { suppressionWindowSeconds: 300 },
  );
  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].mitre.id, "T1547.001");
});

test("remote interactive logon rule matches RDP logon type", () => {
  const event = normalizeEvent({
    timestamp: "2026-01-01T00:00:00Z",
    event_id: 4624,
    LogonType: 10,
    TargetUserName: "alice",
    IpAddress: "203.0.113.10",
  });
  const result = runRuleEngine(
    [event],
    defaultRules.filter((rule) => rule.id === "sentinelops-remote-interactive-logon"),
    { suppressionWindowSeconds: 300 },
  );
  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].mitre.id, "T1021.001");
});
