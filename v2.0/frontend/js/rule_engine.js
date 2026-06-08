const severityWeight = { High: 18, Medium: 9, Low: 3 };

const getValue = (event, field) => {
  if (field === "all") {
    return `${event.eventId} ${event.user} ${event.sourceIp} ${event.host} ${event.status} ${event.process} ${event.parentProcess} ${event.command} ${event.message} ${event.group} ${event.privileges} ${event.logonType} ${event.destinationIp} ${event.destinationPort} ${event.targetFilename} ${event.registryKey} ${event.serviceName} ${event.hash}`;
  }
  return event[field];
};

const wildcardMatch = (value, pattern) => {
  const escaped = String(pattern).replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}$`, "i").test(String(value ?? ""));
};

export function evaluateCondition(event, condition) {
  const actual = getValue(event, condition.field);
  const expected = condition.value;
  switch (condition.operator) {
    case "equals": return String(actual ?? "").toLowerCase() === String(expected ?? "").toLowerCase();
    case "contains": return String(actual ?? "").toLowerCase().includes(String(expected ?? "").toLowerCase());
    case "regex":
      try { return new RegExp(String(expected), "i").test(String(actual ?? "")); } catch { return false; }
    case "in": return Array.isArray(expected) && expected.map(String).map((value) => value.toLowerCase()).includes(String(actual ?? "").toLowerCase());
    case "exists": return expected === false ? actual === undefined || actual === null || actual === "" : actual !== undefined && actual !== null && actual !== "";
    default: return false;
  }
}

export function matchesRule(event, rule) {
  const all = rule.match?.all || [];
  const any = rule.match?.any || [];
  return (!all.length || all.every((condition) => evaluateCondition(event, condition)))
    && (!any.length || any.some((condition) => evaluateCondition(event, condition)));
}

function isAllowlisted(event, allowlists = {}) {
  const checks = [
    [event.user, allowlists.users],
    [event.host, allowlists.hosts],
    [event.sourceIp, allowlists.sourceIps],
    [event.process, allowlists.processes],
  ];
  return checks.some(([value, patterns]) => (patterns || []).some((pattern) => wildcardMatch(value, pattern)));
}

function conditionText(condition) {
  const value = Array.isArray(condition.value) ? condition.value.join(", ") : condition.value;
  return `${condition.field} ${condition.operator} ${value}`;
}

function explanationFor(rule, eventCount, threshold) {
  const conditions = [...(rule.match?.all || []), ...(rule.match?.any || [])].map(conditionText);
  const explanation = conditions.map((condition) => `Matched: ${condition}`);
  if (threshold) explanation.push(`Threshold met: ${eventCount}/${threshold.count} events within ${threshold.windowSeconds} seconds`);
  return explanation;
}

function alertFrom(rule, events, severity, threshold) {
  const latest = events.at(-1) || {};
  const entity = threshold?.groupBy ? latest[threshold.groupBy] : latest.sourceIp !== "unknown" ? latest.sourceIp : latest.user !== "unknown" ? latest.user : latest.host;
  return {
    id: `${rule.id}:${entity || "global"}:${Math.floor(new Date(latest.timestamp || 0).getTime() / 1000)}`,
    ruleId: rule.id,
    type: "rule_match",
    title: rule.title,
    description: threshold
      ? `${events.length} events matched the configured ${threshold.windowSeconds}-second threshold.`
      : rule.description,
    severity,
    confidence: Number(rule.confidence ?? 50),
    explanation: explanationFor(rule, events.length, threshold),
    falsepositives: rule.falsepositives || [],
    events,
    sourceIp: latest.sourceIp || "unknown",
    user: latest.user || "unknown",
    host: latest.host || "unknown",
    timestamp: latest.timestamp || new Date().toISOString(),
    mitre: rule.mitre,
    suppresses: rule.suppresses || [],
  };
}

function thresholdAlerts(rule, matching, threshold, severity) {
  const groups = matching.reduce((map, event) => {
    const key = String(event[threshold.groupBy] ?? "global");
    map.set(key, [...(map.get(key) || []), event]);
    return map;
  }, new Map());
  const alerts = [];
  for (const events of groups.values()) {
    const sorted = [...events].sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));
    for (let start = 0; start < sorted.length; start += 1) {
      const startTime = new Date(sorted[start].timestamp).getTime();
      const window = sorted.filter((event) => {
        const delta = new Date(event.timestamp).getTime() - startTime;
        return delta >= 0 && delta <= threshold.windowSeconds * 1000;
      });
      if (window.length >= threshold.count) {
        alerts.push(alertFrom(rule, window, severity, threshold));
        break;
      }
    }
  }
  return alerts;
}

function suppressDuplicates(alerts, seconds) {
  const kept = [];
  const lastSeen = new Map();
  for (const alert of [...alerts].sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp))) {
    const entity = `${alert.sourceIp}|${alert.user}|${alert.host}`;
    const key = `${alert.ruleId}|${entity}`;
    const timestamp = new Date(alert.timestamp).getTime();
    const previous = lastSeen.get(key);
    if (previous !== undefined && timestamp - previous <= seconds * 1000) continue;
    lastSeen.set(key, timestamp);
    kept.push(alert);
  }
  return kept.filter((candidate) => !kept.some((suppressor) => {
    if (!(suppressor.suppresses || []).includes(candidate.ruleId)) return false;
    return suppressor.sourceIp === candidate.sourceIp
      && suppressor.user === candidate.user
      && suppressor.host === candidate.host;
  }));
}

export function runRuleEngine(events, rules, settings = {}) {
  const allowlists = settings.allowlists || {};
  const eligible = events.filter((event) => !isAllowlisted(event, allowlists));
  let alerts = [];
  for (const rule of rules.filter((item) => item.enabled !== false)) {
    const matching = eligible.filter((event) => matchesRule(event, rule));
    if (!matching.length) continue;
    const severity = settings.severityOverrides?.[rule.id] || rule.level;
    const override = settings.thresholdOverrides?.[rule.id];
    const threshold = rule.threshold ? { ...rule.threshold, ...override } : null;
    alerts.push(...(threshold
      ? thresholdAlerts(rule, matching, threshold, severity)
      : matching.map((event) => alertFrom(rule, [event], severity, null))));
  }
  alerts = suppressDuplicates(alerts, settings.suppressionWindowSeconds ?? 300);
  const minimum = alerts.some((item) => item.severity === "High") ? 65 : alerts.some((item) => item.severity === "Medium") ? 30 : 0;
  const confidenceAdjustment = alerts.reduce((sum, item) => sum + Math.round(item.confidence / 25), 0);
  const riskScore = Math.min(100, Math.max(minimum, alerts.reduce((sum, item) => sum + severityWeight[item.severity], 0) + confidenceAdjustment));
  const riskLevel = riskScore >= 65 ? "High" : riskScore >= 30 ? "Medium" : "Low";
  return { alerts: alerts.sort((left, right) => severityWeight[right.severity] - severityWeight[left.severity]), riskScore, riskLevel, eligibleEventCount: eligible.length };
}

export function testRule(rule, events, settings = {}) {
  return runRuleEngine(events, [{ ...rule, enabled: true }], settings);
}
