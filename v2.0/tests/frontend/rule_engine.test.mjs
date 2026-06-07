import test from "node:test";
import assert from "node:assert/strict";

import { runRuleEngine, testRule } from "../../frontend/js/rule_engine.js";
import { normalizeEvent } from "../../frontend/js/parsers.js";

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
  const result = runRuleEngine(events, [{ ...thresholdRule, id: "single-rule", threshold: null }], { suppressionWindowSeconds: 300 });
  assert.equal(result.alerts.length, 1);
});
