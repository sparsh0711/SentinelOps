import { normalizeEvent } from "./parsers.js";
import { runRuleEngine } from "./rule_engine.js";

const MITRE = {
  failed_login: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  brute_force: { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
  powershell: { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
  privilege: { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  suspicious_ip: { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
};

const powerShellPatterns = [
  /-enc(?:odedcommand)?\s+/i,
  /\biex\b|invoke-expression/i,
  /downloadstring|downloadfile|webclient|invoke-webrequest|\biwr\b/i,
  /frombase64string|amsiutils|invoke-mimikatz|sekurlsa|bypass/i,
];
const privilegeIds = new Set(["4672", "4728", "4732", "4756", "4698", "7045", "1102"]);

export function isPrivateIp(ip) {
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)
    || /^(::1|fe80:|f[cd][0-9a-f]{2}:)/i.test(ip);
}

function alert(type, severity, title, description, events) {
  const latest = events.at(-1) || {};
  return {
    id: `${type}-${events[0]?.id || "finding"}`,
    type,
    severity,
    title,
    description,
    events,
    sourceIp: latest.sourceIp || "unknown",
    user: latest.user || "unknown",
    host: latest.host || "unknown",
    timestamp: latest.timestamp || new Date().toISOString(),
    mitre: MITRE[type],
  };
}

export function analyzeEvents(rawEvents, rules = [], settings = {}) {
  const events = rawEvents.map(normalizeEvent).sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));
  if (rules.length) {
    return { events, ...runRuleEngine(events, rules, settings) };
  }
  const alerts = [];
  const failures = events.filter((event) => event.status === "failed" || event.eventId === "4625");
  const byIp = failures.reduce((map, event) => {
    if (event.sourceIp !== "unknown") map.set(event.sourceIp, [...(map.get(event.sourceIp) || []), event]);
    return map;
  }, new Map());

  for (const [ip, grouped] of byIp) {
    if (grouped.length >= 5) {
      alerts.push(alert("brute_force", "High", "Brute force login pattern detected", `${grouped.length} failed logins originated from ${ip}.`, grouped));
    } else if (grouped.length >= 2) {
      alerts.push(alert("failed_login", "Medium", "Repeated failed login attempts", `${grouped.length} authentication failures originated from ${ip}.`, grouped));
    }
    if (!isPrivateIp(ip) && grouped.length >= 3) {
      alerts.push(alert("suspicious_ip", "Medium", "Suspicious external IP activity", `${ip} generated repeated authentication failures.`, grouped));
    }
  }

  const isolated = failures.filter((event) => event.sourceIp === "unknown" || (byIp.get(event.sourceIp)?.length || 0) < 2);
  if (isolated.length) alerts.push(alert("failed_login", "Low", "Failed login attempts observed", `${isolated.length} isolated authentication failure${isolated.length === 1 ? "" : "s"} require context review.`, isolated));

  for (const event of events) {
    const execution = `${event.process} ${event.command} ${event.message}`;
    const matches = powerShellPatterns.filter((pattern) => pattern.test(execution));
    if ((/powershell/i.test(execution) || ["4103", "4104"].includes(event.eventId)) && matches.length) {
      alerts.push(alert("powershell", matches.length > 1 ? "High" : "Medium", "Suspicious PowerShell execution", `${matches.length} suspicious command indicator${matches.length === 1 ? "" : "s"} detected.`, [event]));
    }
    if (privilegeIds.has(event.eventId) || /domain admins|administrators group|sedebugprivilege|seimpersonateprivilege|audit log was cleared|new service installed/i.test(`${event.message} ${event.group} ${event.privileges}`)) {
      alerts.push(alert("privilege", ["4728", "4732", "4756", "7045", "1102"].includes(event.eventId) ? "High" : "Medium", "Possible privilege escalation", `Privileged activity was recorded on ${event.host}.`, [event]));
    }
  }

  const weights = { High: 18, Medium: 9, Low: 3 };
  const minimum = alerts.some((item) => item.severity === "High") ? 65 : alerts.some((item) => item.severity === "Medium") ? 30 : 0;
  const riskScore = Math.min(100, Math.max(minimum, alerts.reduce((sum, item) => sum + weights[item.severity], 0)));
  const riskLevel = riskScore >= 65 ? "High" : riskScore >= 30 ? "Medium" : "Low";
  return { events, alerts, riskScore, riskLevel };
}
