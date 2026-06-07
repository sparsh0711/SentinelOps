const MITRE = {
  failed_login: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  brute_force: { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
  suspicious_ip: { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
  powershell: { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
  privilege_escalation: { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  credential_compromise: { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
  attack_chain: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
};

const suspiciousPowerShellPatterns = [
  { re: /-enc(?:odedcommand)?\s+/i, label: "Encoded command" },
  { re: /\biex\b|invoke-expression/i, label: "Dynamic expression execution" },
  { re: /downloadstring|downloadfile|webclient|invoke-webrequest|\biwr\b/i, label: "Remote payload retrieval" },
  { re: /-w(?:indowstyle)?\s+hidden|-nop(?:rofile)?\b/i, label: "Hidden or profile-bypassed execution" },
  { re: /frombase64string|reflection\.assembly|amsiutils|bypass/i, label: "Obfuscation or defense bypass" },
  { re: /invoke-mimikatz|sekurlsa|credential/i, label: "Credential access tooling" },
];

const privilegeEventIds = new Set(["4672", "4728", "4732", "4756", "4698", "7045"]);
let state = {
  events: [],
  alerts: [],
  analysis: null,
  sourceName: "No logs loaded",
  riskScore: 0,
  riskLevel: "Low",
};
let backendOnline = false;
let liveCollectionTimer = null;
let collectionInProgress = false;

function getCustomRules() {
  try {
    const rules = JSON.parse(localStorage.getItem("sentinelops.customRules") || "[]");
    return Array.isArray(rules) ? rules : [];
  } catch {
    return [];
  }
}

function saveCustomRules(rules) {
  localStorage.setItem("sentinelops.customRules", JSON.stringify(rules));
}

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
const formatNumber = (value) => new Intl.NumberFormat().format(value);
const formatTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value || "Unknown") : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};
const shortTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};
const displaySourceIp = (value) => value === "unknown" ? "Not present" : value;

function firstValue(object, keys, fallback = "") {
  for (const key of keys) {
    if (object[key] !== undefined && object[key] !== null && object[key] !== "") return object[key];
    const found = Object.keys(object).find((candidate) => candidate.toLowerCase() === key.toLowerCase());
    if (found && object[found] !== undefined && object[found] !== null && object[found] !== "") return object[found];
  }
  return fallback;
}

function normalizeSourceIp(value) {
  const text = String(value ?? "").trim();
  if (!text || ["-", "::", "unknown", "n/a", "null", "0.0.0.0"].includes(text.toLowerCase())) return "unknown";
  const bracketless = text.replace(/^\[|\]$/g, "");
  const ipv4 = bracketless.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];
  if (ipv4) {
    const valid = ipv4.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255);
    return valid ? ipv4 : "unknown";
  }
  if (/^[0-9a-f:]+$/i.test(bracketless) && bracketless.includes(":")) return bracketless;
  return "unknown";
}

function normalizeEvent(raw, index) {
  const message = firstValue(raw, ["message", "description", "event_message", "Message"], "");
  const eventId = String(firstValue(raw, ["event_id", "eventid", "EventID", "id"], ""));
  const command = firstValue(raw, ["command", "commandline", "process_command_line", "CommandLine", "cmdline"], "");
  const process = firstValue(raw, ["process", "process_name", "new_process_name", "Image"], "");
  let status = String(firstValue(raw, ["status", "result", "outcome", "action"], "")).toLowerCase();
  if (!status) {
    if (eventId === "4625" || /failed|failure|invalid|denied/i.test(message)) status = "failed";
    else if (eventId === "4624" || /success|accepted/i.test(message)) status = "success";
    else status = "unknown";
  }
  const timestamp = firstValue(raw, ["timestamp", "time", "@timestamp", "datetime", "date", "TimeCreated"], new Date(Date.now() + index).toISOString());
  return {
    id: `event-${index}`,
    timestamp,
    eventId,
    recordId: String(firstValue(raw, ["record_id", "recordId", "RecordId"], "")),
    provider: String(firstValue(raw, ["provider", "provider_name", "ProviderName"], "")),
    user: String(firstValue(raw, ["user", "username", "account", "subject_user_name", "TargetUserName"], "unknown")),
    sourceIp: normalizeSourceIp(firstValue(raw, ["source_ip", "src_ip", "ip", "client_ip", "IpAddress", "SourceNetworkAddress", "ClientAddress", "SourceAddress", "RemoteAddress", "remote_addr"], "unknown")),
    host: String(firstValue(raw, ["host", "hostname", "computer", "device", "Computer"], "unknown")),
    status,
    message: String(message),
    command: String(command),
    process: String(process),
    targetUser: String(firstValue(raw, ["target_user", "member", "TargetUserName"], "")),
    group: String(firstValue(raw, ["group", "group_name", "TargetUserName"], "")),
    privileges: String(firstValue(raw, ["privileges", "privilege_list", "PrivilegeList"], "")),
    raw,
  };
}

function parseCsv(text) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) throw new Error("CSV input needs a header and at least one data row.");
  const parseLine = (line) => {
    const values = [];
    let current = "";
    let quoted = false;
    for (let i = 0; i < line.length; i += 1) {
      const char = line[i];
      if (char === '"' && line[i + 1] === '"' && quoted) { current += '"'; i += 1; }
      else if (char === '"') quoted = !quoted;
      else if (char === "," && !quoted) { values.push(current.trim()); current = ""; }
      else current += char;
    }
    values.push(current.trim());
    return values;
  };
  const headers = parseLine(lines[0]);
  return lines.slice(1).map((line) => Object.fromEntries(headers.map((header, index) => [header, parseLine(line)[index] || ""])));
}

function parsePlainText(text) {
  return text.trim().split(/\r?\n/).filter(Boolean).map((line) => {
    const ip = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || "unknown";
    const iso = line.match(/\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?/)?.[0];
    const user = line.match(/(?:user|for|account)[=:\s]+(?:invalid user\s+)?([^\s,;]+)/i)?.[1] || "unknown";
    return {
      timestamp: iso || new Date().toISOString(),
      source_ip: ip,
      user,
      status: /failed|failure|invalid|denied/i.test(line) ? "failed" : /accepted|success/i.test(line) ? "success" : "unknown",
      event_id: /powershell/i.test(line) ? 4688 : /failed|failure|invalid/i.test(line) ? 4625 : "",
      command: /powershell/i.test(line) ? line : "",
      message: line,
    };
  });
}

function parseLogs(text) {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Choose a real log file or paste real log data first.");
  try {
    const parsed = JSON.parse(trimmed);
    const rows = Array.isArray(parsed) ? parsed : parsed.events || parsed.logs || [parsed];
    if (!Array.isArray(rows)) throw new Error();
    return rows;
  } catch {
    const lines = trimmed.split(/\r?\n/).filter(Boolean);
    if (lines.every((line) => {
      try { JSON.parse(line); return true; } catch { return false; }
    })) return lines.map((line) => JSON.parse(line));
    if (lines[0]?.includes(",") && /timestamp|event|user|source|status|message/i.test(lines[0])) return parseCsv(trimmed);
    return parsePlainText(trimmed);
  }
}

function makeAlert(type, severity, title, description, events, extra = {}) {
  const mitre = extra.mitre || MITRE[type] || { id: "Custom", name: "Custom Detection", tactic: "Custom" };
  const latest = [...events].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0] || {};
  return {
    id: `alert-${type}-${Math.random().toString(36).slice(2, 8)}`,
    type, severity, title, description, mitre, events,
    timestamp: latest.timestamp || new Date().toISOString(),
    sourceIp: extra.sourceIp || latest.sourceIp || "unknown",
    user: extra.user || latest.user || "unknown",
    host: extra.host || latest.host || "unknown",
    count: events.length,
    stages: extra.stages || [],
    recommendation: extra.recommendation || "Validate the activity with the account owner, inspect related host telemetry, and contain the affected identity or endpoint if unauthorized.",
  };
}

function eventTime(event) {
  const value = new Date(event.timestamp).getTime();
  return Number.isFinite(value) ? value : 0;
}

function sameIdentityOrHost(left, right) {
  const sameUser = left.user !== "unknown" && left.user === right.user;
  const sameHost = left.host !== "unknown" && left.host === right.host;
  const sameIp = left.sourceIp !== "unknown" && left.sourceIp === right.sourceIp;
  return sameUser || sameHost || sameIp;
}

function isSuspiciousExecution(event) {
  const text = `${event.provider} ${event.process} ${event.command} ${event.message}`;
  const isPowerShell = /powershell/i.test(text) || ["4103", "4104"].includes(event.eventId);
  return isPowerShell && suspiciousPowerShellPatterns.some((pattern) => pattern.re.test(text));
}

function isPrivilegeActivity(event) {
  const text = `${event.message} ${event.command} ${event.group} ${event.privileges}`;
  return privilegeEventIds.has(event.eventId)
    || event.eventId === "1102"
    || /domain admins|administrators group|sudoers|setuid|sedebugprivilege|seimpersonateprivilege|audit log was cleared|new service installed/i.test(text);
}

function isSuccessfulAuthentication(event) {
  return event.eventId === "4624"
    || /successful (?:interactive |network |remote )?logon|accepted (?:password|publickey)|login success|authentication success/i.test(event.message);
}

function correlateAttackChains(events) {
  const correlations = [];
  const failures = events.filter((event) => event.status === "failed" || event.eventId === "4625");
  const successes = events.filter(isSuccessfulAuthentication);
  const executions = events.filter(isSuspiciousExecution);
  const privileges = events.filter(isPrivilegeActivity);
  const seen = new Set();

  for (const success of successes) {
    const successTime = eventTime(success);
    const precedingFailures = failures.filter((failure) => {
      const delta = successTime - eventTime(failure);
      return delta >= 0
        && delta <= 15 * 60 * 1000
        && failure.sourceIp !== "unknown"
        && failure.sourceIp === success.sourceIp;
    });
    if (precedingFailures.length < 3) continue;

    const execution = executions.find((event) => {
      const delta = eventTime(event) - successTime;
      return delta >= 0 && delta <= 30 * 60 * 1000 && sameIdentityOrHost(success, event);
    });
    const privilege = execution && privileges.find((event) => {
      const delta = eventTime(event) - eventTime(execution);
      return delta >= 0 && delta <= 60 * 60 * 1000 && sameIdentityOrHost(execution, event);
    });
    const key = `${success.sourceIp}|${success.user}|${success.host}|${success.timestamp}`;
    if (seen.has(key)) continue;
    seen.add(key);

    if (execution) {
      const chainEvents = [...precedingFailures, success, execution, ...(privilege ? [privilege] : [])];
      const stages = [
        { label: "Credential attack", detail: `${precedingFailures.length} failed logins`, timestamp: precedingFailures[0].timestamp },
        { label: "Account access", detail: `Successful login as ${success.user}`, timestamp: success.timestamp },
        { label: "Suspicious execution", detail: execution.process || "PowerShell", timestamp: execution.timestamp },
      ];
      if (privilege) stages.push({ label: "Privilege activity", detail: `Event ${privilege.eventId || "behavior match"}`, timestamp: privilege.timestamp });
      correlations.push(makeAlert(
        "attack_chain",
        "High",
        privilege ? "Credential compromise attack chain" : "Post-authentication execution chain",
        `${precedingFailures.length} failed logins were followed by a successful login and suspicious execution${privilege ? ", then privileged activity" : ""}.`,
        chainEvents,
        {
          sourceIp: success.sourceIp,
          user: success.user,
          host: success.host,
          stages,
          recommendation: "Treat this as a correlated incident: disable or reset the account, isolate the affected host, block the source, and preserve authentication, process, PowerShell, and privilege-change evidence.",
        },
      ));
    } else {
      correlations.push(makeAlert(
        "credential_compromise",
        "High",
        "Successful login after repeated failures",
        `${precedingFailures.length} failed logins from ${success.sourceIp} were followed by successful access as ${success.user}.`,
        [...precedingFailures, success],
        {
          sourceIp: success.sourceIp,
          user: success.user,
          host: success.host,
          stages: [
            { label: "Credential attack", detail: `${precedingFailures.length} failed logins`, timestamp: precedingFailures[0].timestamp },
            { label: "Account access", detail: `Successful login as ${success.user}`, timestamp: success.timestamp },
          ],
          recommendation: "Validate the successful login immediately, reset the affected credential, terminate active sessions, and review the host for post-authentication activity.",
        },
      ));
    }
  }
  return correlations;
}

function analyzeEvents(rawEvents) {
  const events = rawEvents.map(normalizeEvent).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  const alerts = [];
  const failed = events.filter((event) => event.status === "failed" || event.eventId === "4625" || /failed password|login failure|invalid credentials/i.test(event.message));

  const failedByIp = Map.groupBy ? Map.groupBy(failed, (event) => event.sourceIp) : failed.reduce((map, event) => map.set(event.sourceIp, [...(map.get(event.sourceIp) || []), event]), new Map());
  const bruteForceKeys = new Set();

  for (const [ip, grouped] of failedByIp) {
    if (ip === "unknown") continue;
    const sorted = grouped.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    let bestWindow = [];
    for (let start = 0; start < sorted.length; start += 1) {
      const window = sorted.filter((event) => {
        const delta = new Date(event.timestamp) - new Date(sorted[start].timestamp);
        return delta >= 0 && delta <= 5 * 60 * 1000;
      });
      if (window.length > bestWindow.length) bestWindow = window;
    }
    if (bestWindow.length >= 5) {
      const users = [...new Set(bestWindow.map((event) => event.user))];
      bruteForceKeys.add(ip);
      alerts.push(makeAlert(
        "brute_force",
        "High",
        users.length > 2 ? "Password spraying pattern detected" : "Brute force login pattern detected",
        `${bestWindow.length} failed logins from ${ip} within five minutes targeting ${users.length} account${users.length === 1 ? "" : "s"}.`,
        bestWindow,
        { sourceIp: ip, user: users.join(", "), recommendation: "Block or rate-limit the source, reset targeted credentials where appropriate, and review for a successful login immediately after the failures." },
      ));
    } else if (grouped.length >= 2) {
      alerts.push(makeAlert("failed_login", "Medium", "Repeated failed login attempts", `${grouped.length} authentication failures originated from ${ip}.`, grouped, { sourceIp: ip }));
    }
  }

  for (const rule of getCustomRules().filter((item) => item.enabled !== false)) {
    let matcher;
    try {
      matcher = rule.regex
        ? new RegExp(rule.pattern, "i")
        : { test: (value) => String(value).toLowerCase().includes(String(rule.pattern).toLowerCase()) };
    } catch {
      continue;
    }
    const matching = events.filter((event) => {
      const value = rule.field === "all"
        ? `${event.eventId} ${event.user} ${event.sourceIp} ${event.host} ${event.process} ${event.command} ${event.message}`
        : event[rule.field] || "";
      return matcher.test(String(value));
    });
    if (matching.length) {
      alerts.push(makeAlert(
        "custom",
        rule.severity,
        rule.name,
        `${matching.length} event${matching.length === 1 ? "" : "s"} matched the custom ${rule.regex ? "regular expression" : "keyword"} rule.`,
        matching,
        {
          mitre: {
            id: rule.mitreId || "Custom",
            name: rule.mitreName || "Custom Detection",
            tactic: "Custom",
          },
          recommendation: "Review the matching event evidence and refine this custom rule if the activity is expected.",
        },
      ));
    }
  }

  const isolatedFailed = failed.filter((event) => !bruteForceKeys.has(event.sourceIp) && (failedByIp.get(event.sourceIp)?.length || 0) < 2);
  if (isolatedFailed.length) {
    alerts.push(makeAlert("failed_login", "Low", "Failed login attempts observed", `${isolatedFailed.length} isolated authentication failure${isolatedFailed.length === 1 ? "" : "s"} require context review.`, isolatedFailed));
  }

  for (const event of events) {
    const commandText = `${event.provider} ${event.process} ${event.command} ${event.message}`;
    if (/powershell/i.test(commandText) || ["4103", "4104"].includes(event.eventId)) {
      const matches = suspiciousPowerShellPatterns.filter((pattern) => pattern.re.test(commandText));
      if (matches.length) {
        const severity = matches.length >= 2 || /invoke-mimikatz|amsiutils|downloadstring|frombase64string/i.test(commandText) ? "High" : "Medium";
        alerts.push(makeAlert("powershell", severity, "Suspicious PowerShell execution", `${matches.map((match) => match.label).join(", ")} detected on ${event.host}.`, [event], {
          recommendation: "Isolate the endpoint if the command is unauthorized, collect the PowerShell script block logs, and inspect child processes and network connections.",
        }));
      }
    }

    const privilegeText = `${event.message} ${event.command} ${event.group} ${event.privileges}`;
    if (privilegeEventIds.has(event.eventId) || /domain admins|administrators group|sudoers|setuid|sedebugprivilege|seimpersonateprivilege|audit log was cleared|new service installed/i.test(privilegeText)) {
      const severe = ["4728", "4732", "4756", "1102", "7045"].includes(event.eventId) || /domain admins|audit log was cleared|new service/i.test(privilegeText);
      alerts.push(makeAlert("privilege_escalation", severe ? "High" : "Medium", "Possible privilege escalation", `Privileged activity (${event.eventId || "behavioral match"}) was recorded for ${event.user} on ${event.host}.`, [event], {
        recommendation: "Confirm the change against an approved ticket, review the account's preceding activity, and revoke new privileges if the action is unauthorized.",
      }));
    }
  }

  for (const [ip, grouped] of failedByIp) {
    if (ip === "unknown" || isPrivateIp(ip)) continue;
    const successful = events.filter((event) => event.sourceIp === ip && isSuccessfulAuthentication(event));
    const linked = [...grouped, ...successful];
    if (successful.length || grouped.length >= 3) {
      alerts.push(makeAlert("suspicious_ip", successful.length ? "High" : "Medium", "Suspicious external IP activity", `${ip} generated ${grouped.length} failed and ${successful.length} successful authentication event${linked.length === 1 ? "" : "s"}.`, linked, { sourceIp: ip }));
    }
  }

  alerts.push(...correlateAttackChains(events));

  const severityWeight = { High: 18, Medium: 9, Low: 3 };
  const weighted = alerts.reduce((sum, alert) => sum + severityWeight[alert.severity], 0);
  const distinctTypes = new Set(alerts.map((alert) => alert.type)).size;
  const hasHigh = alerts.some((alert) => alert.severity === "High");
  const hasMedium = alerts.some((alert) => alert.severity === "Medium");
  const minimumScore = hasHigh ? 65 : hasMedium ? 30 : 0;
  const riskScore = Math.min(100, Math.max(minimumScore, Math.round(weighted + distinctTypes * 4)));
  const riskLevel = hasHigh || riskScore >= 65 ? "High" : hasMedium || riskScore >= 30 ? "Medium" : "Low";
  return { events, alerts: alerts.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || new Date(b.timestamp) - new Date(a.timestamp)), riskScore, riskLevel };
}

function isPrivateIp(ip) {
  if (ip === "unknown") return false;
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)
    || /^(::1|fe80:|f[cd][0-9a-f]{2}:)/i.test(ip);
}

function severityRank(severity) {
  return { Low: 1, Medium: 2, High: 3 }[severity] || 0;
}

function eventType(event) {
  if (event.eventId === "4625" || event.status === "failed") return "Authentication failure";
  if (event.eventId === "4624") return "Authentication success";
  if (event.eventId === "4688" || event.command) return "Process creation";
  if (privilegeEventIds.has(event.eventId) || event.eventId === "1102") return "Privilege / audit";
  return event.message ? event.message.slice(0, 42) : "Security event";
}

async function runAnalysis(rawEvents, sourceName = "Pasted logs", persist = true) {
  const result = analyzeEvents(rawEvents);
  state = { ...result, analysis: new Date(), sourceName };
  renderAll();
  if (persist && backendOnline) {
    try {
      await apiRequest("/api/analyses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sourceName: state.sourceName,
          events: state.events,
          alerts: state.alerts,
          riskScore: state.riskScore,
          riskLevel: state.riskLevel,
        }),
      });
      loadHistory();
    } catch (error) {
      showToast(`Analysis completed, but history was not saved: ${error.message}`);
    }
  }
  notifyHighSeverity();
}

function renderAll() {
  const { events, alerts, riskScore, riskLevel } = state;
  const severityCounts = { High: 0, Medium: 0, Low: 0 };
  alerts.forEach((alert) => { severityCounts[alert.severity] += 1; });
  const correlatedCount = alerts.filter((alert) => alert.stages?.length).length;
  const suspiciousIps = new Set(alerts.filter((alert) => alert.sourceIp !== "unknown" && ["suspicious_ip", "brute_force"].includes(alert.type)).map((alert) => alert.sourceIp));
  const observedIps = new Set(events.filter((event) => event.sourceIp !== "unknown").map((event) => event.sourceIp));

  $("#total-events").textContent = formatNumber(events.length);
  $("#total-alerts").textContent = formatNumber(alerts.length);
  $("#high-alert-count").textContent = `${severityCounts.High} high`;
  $("#suspicious-ips").textContent = suspiciousIps.size;
  $("#ip-summary").textContent = suspiciousIps.size
    ? `${[...suspiciousIps].filter((ip) => !isPrivateIp(ip)).length} external, ${observedIps.size} observed`
    : observedIps.size
      ? `${observedIps.size} source address${observedIps.size === 1 ? "" : "es"} observed; none suspicious`
      : "Source IP not present in these logs";
  $("#risk-score").textContent = riskScore;
  $("#risk-track-fill").style.width = `${riskScore}%`;
  $("#overall-risk-badge").textContent = riskLevel.toUpperCase();
  $("#overall-risk-badge").className = `risk-badge ${riskLevel.toLowerCase()}`;
  $("#risk-track-fill").style.background = riskLevel === "Low" ? "var(--low)" : riskLevel === "Medium" ? "var(--medium)" : "linear-gradient(90deg, var(--medium), var(--high))";
  $("#nav-alert-count").textContent = alerts.length;
  $("#analysis-range").textContent = state.sourceName;
  $("#last-analyzed").textContent = state.analysis ? "just now" : "not yet";
  $("#event-window").textContent = getEventWindow(events);
  $("#posture-summary").textContent = getPostureSummary(riskLevel, alerts.length, correlatedCount);
  $("#severity-high").textContent = severityCounts.High;
  $("#severity-medium").textContent = severityCounts.Medium;
  $("#severity-low").textContent = severityCounts.Low;
  $("#donut-total").textContent = alerts.length;
  $("#severity-donut").style.background = donutGradient(severityCounts, alerts.length);
  $("#export-report").disabled = events.length === 0;

  renderChart(events, alerts);
  renderPriorityAlerts(alerts);
  renderTopIps(events, alerts);
  renderMitreSummary(alerts);
  renderAlertsTable();
  renderEventsTable();
  renderMitreGrid(alerts);
}

function getEventWindow(events) {
  if (!events.length) return "No events loaded";
  const times = events.map((event) => new Date(event.timestamp)).filter((date) => !Number.isNaN(date.getTime())).sort((a, b) => a - b);
  if (!times.length) return `${events.length} normalized records`;
  const minutes = Math.max(1, Math.round((times.at(-1) - times[0]) / 60000));
  return `${minutes} minute analysis window`;
}

function getPostureSummary(level, count, correlatedCount = 0) {
  if (!count) return "No suspicious behavior was detected in the current dataset.";
  if (correlatedCount) return `${correlatedCount} correlated incident${correlatedCount === 1 ? "" : "s"} ${correlatedCount === 1 ? "links" : "link"} multiple stages of suspicious activity.`;
  if (level === "High") return "High-risk behavior requires immediate analyst review.";
  if (level === "Medium") return "Several findings warrant investigation and validation.";
  return "Low-risk findings detected; continue monitoring the environment.";
}

function donutGradient(counts, total) {
  if (!total) return "conic-gradient(rgba(255,255,255,.06) 0 100%)";
  const high = counts.High / total * 100;
  const medium = high + counts.Medium / total * 100;
  return `conic-gradient(var(--high) 0 ${high}%, var(--medium) ${high}% ${medium}%, var(--low) ${medium}% 100%)`;
}

function renderChart(events, alerts) {
  const svg = $("#activity-chart");
  if (!events.length) {
    svg.innerHTML = '<text x="380" y="135" text-anchor="middle" class="chart-label">Load logs to visualize security activity</text>';
    return;
  }
  const width = 760, height = 270, left = 35, right = 12, top = 15, bottom = 28;
  const timestamps = events.map((event) => new Date(event.timestamp).getTime()).filter(Number.isFinite);
  const minTime = Math.min(...timestamps), maxTime = Math.max(...timestamps);
  const bucketCount = Math.min(10, Math.max(5, Math.ceil(Math.sqrt(events.length))));
  const duration = Math.max(1, maxTime - minTime);
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    time: minTime + duration * index / Math.max(1, bucketCount - 1), events: 0, alerts: 0,
  }));
  events.forEach((event) => {
    const index = Math.min(bucketCount - 1, Math.floor((new Date(event.timestamp).getTime() - minTime) / duration * bucketCount));
    buckets[index].events += 1;
  });
  alerts.forEach((alert) => {
    const index = Math.min(bucketCount - 1, Math.floor((new Date(alert.timestamp).getTime() - minTime) / duration * bucketCount));
    buckets[index].alerts += 1;
  });
  const maxValue = Math.max(1, ...buckets.flatMap((bucket) => [bucket.events, bucket.alerts]));
  const x = (index) => left + index * (width - left - right) / Math.max(1, bucketCount - 1);
  const y = (value) => top + (maxValue - value) * (height - top - bottom) / maxValue;
  const line = (key) => buckets.map((bucket, index) => `${index ? "L" : "M"} ${x(index).toFixed(1)} ${y(bucket[key]).toFixed(1)}`).join(" ");
  const area = `${line("events")} L ${x(bucketCount - 1)} ${height - bottom} L ${x(0)} ${height - bottom} Z`;
  let markup = `<defs><linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#24b6ff" stop-opacity=".22"/><stop offset="100%" stop-color="#24b6ff" stop-opacity="0"/></linearGradient></defs>`;
  for (let i = 0; i <= 4; i += 1) {
    const gy = top + i * (height - top - bottom) / 4;
    markup += `<line x1="${left}" y1="${gy}" x2="${width-right}" y2="${gy}" class="chart-grid"/><text x="${left-10}" y="${gy+3}" text-anchor="end" class="chart-label">${Math.round(maxValue * (4-i) / 4)}</text>`;
  }
  markup += `<path d="${area}" class="chart-area"/><path d="${line("events")}" class="chart-line-events"/><path d="${line("alerts")}" class="chart-line-alerts"/>`;
  buckets.forEach((bucket, index) => {
    if (index % Math.ceil(bucketCount / 5) === 0 || index === bucketCount - 1) markup += `<text x="${x(index)}" y="${height-7}" text-anchor="middle" class="chart-label">${shortTime(bucket.time)}</text>`;
    markup += `<circle cx="${x(index)}" cy="${y(bucket.events)}" r="3" class="chart-point" stroke="var(--accent)"/><circle cx="${x(index)}" cy="${y(bucket.alerts)}" r="2.5" class="chart-point" stroke="var(--high)"/>`;
  });
  svg.innerHTML = markup;
}

function renderPriorityAlerts(alerts) {
  const target = $("#priority-alerts");
  if (!alerts.length) { target.innerHTML = '<div class="empty-state">No alerts detected in this dataset.</div>'; return; }
  target.innerHTML = alerts.slice(0, 4).map((alert) => `
    <div class="priority-item" data-alert-id="${alert.id}">
      <span class="priority-mark ${alert.severity}"></span>
      <div><h4>${escapeHtml(alert.title)}</h4><p>${escapeHtml(alert.description)}</p></div>
      <time>${shortTime(alert.timestamp)}</time>
    </div>`).join("");
}

function buildIpStats(events, alerts) {
  const stats = new Map();
  events.forEach((event) => {
    if (event.sourceIp === "unknown") return;
    const current = stats.get(event.sourceIp) || { ip: event.sourceIp, events: 0, failures: 0, alerts: 0, score: 0 };
    current.events += 1;
    if (event.status === "failed") current.failures += 1;
    stats.set(event.sourceIp, current);
  });
  alerts.forEach((alert) => {
    if (alert.sourceIp === "unknown") return;
    const current = stats.get(alert.sourceIp) || { ip: alert.sourceIp, events: 0, failures: 0, alerts: 0, score: 0 };
    current.alerts += 1;
    current.score += { High: 25, Medium: 12, Low: 4 }[alert.severity];
    stats.set(alert.sourceIp, current);
  });
  return [...stats.values()].map((item) => ({ ...item, score: Math.min(99, item.score + Math.min(20, item.failures * 2)) })).sort((a, b) => b.score - a.score || b.events - a.events);
}

function renderTopIps(events, alerts) {
  const ips = buildIpStats(events, alerts).filter((item) => item.score > 0).slice(0, 5);
  $("#top-ips").innerHTML = ips.length ? ips.map((item) => `
    <div class="ip-item">
      <div><span class="ip-address">${escapeHtml(item.ip)}</span><p>${item.failures} failures · ${item.alerts} alerts</p></div>
      <span class="ip-score">${item.score} risk</span>
    </div>`).join("") : '<div class="empty-state">No risky IP activity found.</div>';
}

function techniqueCounts(alerts) {
  const counts = new Map();
  alerts.forEach((alert) => {
    const key = alert.mitre.id;
    const current = counts.get(key) || { ...alert.mitre, count: 0, severities: [] };
    current.count += 1;
    current.severities.push(alert.severity);
    counts.set(key, current);
  });
  return [...counts.values()].sort((a, b) => b.count - a.count);
}

function renderMitreSummary(alerts) {
  const techniques = techniqueCounts(alerts).slice(0, 4);
  const max = Math.max(1, ...techniques.map((item) => item.count));
  $("#mitre-summary").innerHTML = techniques.length ? techniques.map((item) => `
    <div class="mitre-item">
      <div><strong>${escapeHtml(item.name)}</strong><span class="mitre-id">${item.id}</span></div>
      <div class="mitre-bar"><span style="width:${item.count / max * 100}%"></span></div>
    </div>`).join("") : '<div class="empty-state">No techniques mapped yet.</div>';
}

function renderAlertsTable() {
  const query = ($("#alert-search")?.value || "").toLowerCase();
  const severity = $("#severity-filter")?.value || "all";
  const filtered = state.alerts.filter((alert) => {
    const haystack = `${alert.title} ${alert.description} ${alert.user} ${alert.sourceIp} ${alert.mitre.id} ${alert.mitre.name}`.toLowerCase();
    return haystack.includes(query) && (severity === "all" || alert.severity === severity);
  });
  $("#alerts-table").innerHTML = filtered.length ? filtered.map((alert) => `
    <tr>
      <td><span class="severity-pill ${alert.severity}">${alert.severity}</span></td>
      <td><span class="finding-title">${escapeHtml(alert.title)}</span><span class="finding-desc">${escapeHtml(alert.description)}</span></td>
      <td><span class="mono">${escapeHtml(displaySourceIp(alert.sourceIp))}</span><br><span class="finding-desc">${escapeHtml(alert.user)}</span></td>
      <td><span class="mono">${alert.mitre.id}</span><br><span class="finding-desc">${escapeHtml(alert.mitre.name)}</span></td>
      <td>${formatTime(alert.timestamp)}</td>
      <td><button class="row-button" data-alert-id="${alert.id}">Investigate</button></td>
    </tr>`).join("") : '<tr><td colspan="6"><div class="empty-state">No alerts match the current filters.</div></td></tr>';
}

function renderEventsTable() {
  const query = ($("#event-search")?.value || "").toLowerCase();
  const filtered = state.events.filter((event) => `${event.timestamp} ${event.eventId} ${event.user} ${event.sourceIp} ${event.host} ${event.message} ${event.command}`.toLowerCase().includes(query));
  $("#event-result-count").textContent = `${filtered.length} event${filtered.length === 1 ? "" : "s"}`;
  $("#events-table").innerHTML = filtered.length ? [...filtered].reverse().map((event) => `
    <tr>
      <td>${formatTime(event.timestamp)}</td>
      <td><span class="finding-title">${escapeHtml(eventType(event))}</span><span class="finding-desc">${escapeHtml(event.eventId ? `Event ID ${event.eventId}` : event.message)}</span></td>
      <td>${escapeHtml(event.user)}</td>
      <td class="mono">${escapeHtml(displaySourceIp(event.sourceIp))}</td>
      <td>${escapeHtml(event.host)}</td>
      <td><span class="status-pill ${event.status}">${escapeHtml(event.status)}</span></td>
    </tr>`).join("") : '<tr><td colspan="6"><div class="empty-state">No events match your search.</div></td></tr>';
}

function renderMitreGrid(alerts) {
  const grouped = new Map();
  techniqueCounts(alerts).forEach((technique) => {
    if (!grouped.has(technique.tactic)) grouped.set(technique.tactic, []);
    grouped.get(technique.tactic).push(technique);
  });
  $("#mitre-grid").innerHTML = grouped.size ? [...grouped.entries()].map(([tactic, techniques]) => `
    <article class="mitre-card">
      <div class="mitre-card-header"><h3>${escapeHtml(tactic)}</h3><span>${techniques.reduce((sum, item) => sum + item.count, 0)} findings</span></div>
      ${techniques.map((item) => `<div class="technique"><strong>${escapeHtml(item.name)}</strong><span>${item.id}</span><span>${item.count} detection${item.count === 1 ? "" : "s"}</span></div>`).join("")}
    </article>`).join("") : '<article class="mitre-card"><div class="empty-state">Analyze logs to populate ATT&CK coverage.</div></article>';
}

function showAlertDetails(alertId) {
  const alert = state.alerts.find((item) => item.id === alertId);
  if (!alert) return;
  $("#detail-title").textContent = alert.title;
  const chainMarkup = alert.stages?.length ? `
    <div class="attack-chain">
      <h4>Correlated attack sequence</h4>
      ${alert.stages.map((stage) => `
        <div class="chain-stage">
          <i></i>
          <div><strong>${escapeHtml(stage.label)}</strong><span>${escapeHtml(stage.detail)}</span></div>
          <time>${formatTime(stage.timestamp)}</time>
        </div>`).join("")}
    </div>` : "";
  $("#detail-content").innerHTML = `
    <div class="detail-grid">
      <div class="detail-box"><span>Severity</span><strong><span class="severity-pill ${alert.severity}">${alert.severity}</span></strong></div>
      <div class="detail-box"><span>MITRE ATT&CK</span><strong>${alert.mitre.id} · ${escapeHtml(alert.mitre.name)}</strong></div>
      <div class="detail-box"><span>Source</span><strong>${escapeHtml(displaySourceIp(alert.sourceIp))} · ${escapeHtml(alert.user)}</strong></div>
      <div class="detail-box"><span>Affected host</span><strong>${escapeHtml(alert.host)}</strong></div>
    </div>
    <div class="evidence-block"><h4>Finding</h4><pre>${escapeHtml(alert.description)}</pre></div>
    ${chainMarkup}
    <div class="evidence-block"><h4>Evidence (${alert.events.length} event${alert.events.length === 1 ? "" : "s"})</h4><pre>${escapeHtml(JSON.stringify(alert.events.map((event) => event.raw), null, 2))}</pre></div>
    <div class="recommendation"><strong>Recommended response:</strong> ${escapeHtml(alert.recommendation)}</div>`;
  openModal($("#detail-modal"));
}

function switchView(viewName) {
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `${viewName}-view`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === viewName));
  const labels = {
    overview: ["Overview", "Security overview"],
    alerts: ["Alert queue", "Alert queue"],
    events: ["Event explorer", "Event explorer"],
    mitre: ["MITRE matrix", "MITRE ATT&CK mapping"],
    history: ["Analysis history", "Analysis history"],
    rules: ["Detection rules", "Detection rules"],
  };
  $("#view-breadcrumb").textContent = labels[viewName][0];
  $("#page-title").textContent = labels[viewName][1];
  if (viewName === "history") loadHistory();
  if (viewName === "rules") renderCustomRules();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function openModal(modal) { modal.classList.add("open"); modal.setAttribute("aria-hidden", "false"); }
function closeModal(modal) { modal.classList.remove("open"); modal.setAttribute("aria-hidden", "true"); }

function showToast(message) {
  $("#toast-message").textContent = message;
  $("#toast").classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => $("#toast").classList.remove("show"), 3200);
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, options);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("The local service returned an invalid response.");
  }
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
  return payload;
}

async function checkBackend() {
  const dot = $("#backend-dot");
  try {
    const status = await apiRequest("/api/status");
    backendOnline = Boolean(status.online);
    dot.classList.remove("offline", "browser-only");
    $("#backend-status").textContent = status.windowsCollection
      ? "Local service online. Windows collection is available."
      : "Local service online, but Windows collection is unavailable on this OS.";
    $("#collect-windows").disabled = !status.windowsCollection;
    loadHistory();
  } catch {
    backendOnline = false;
    dot.classList.add(location.protocol === "file:" ? "browser-only" : "offline");
    $("#backend-status").textContent = location.protocol === "file:"
      ? "Run start.ps1 to enable EVTX, live collection, and history."
      : "Local service offline. Run start.ps1 and refresh.";
    $("#collect-windows").disabled = true;
  }
}

function rawEventKey(event, index) {
  const recordId = firstValue(event, ["record_id", "recordId", "RecordId"], "");
  const provider = firstValue(event, ["provider", "provider_name", "ProviderName"], "");
  const host = firstValue(event, ["host", "hostname", "computer", "Computer"], "");
  if (recordId !== "") return `${provider}|${host}|${recordId}`;
  const fallback = [
    firstValue(event, ["timestamp", "time", "@timestamp", "datetime"], ""),
    firstValue(event, ["event_id", "eventid", "EventID"], ""),
    firstValue(event, ["user", "username", "account"], ""),
    firstValue(event, ["source_ip", "src_ip", "ip"], ""),
    firstValue(event, ["process", "process_name", "Image"], ""),
    firstValue(event, ["command", "commandline", "CommandLine"], ""),
    firstValue(event, ["message", "description"], ""),
  ].join("|");
  return fallback.replaceAll("|", "") ? fallback : `event-${index}`;
}

function mergeEventBatches(existingEvents, incomingEvents, limit = 5000) {
  const combined = [
    ...existingEvents.map((event) => event.raw || event),
    ...incomingEvents,
  ];
  const unique = new Map();
  combined.forEach((event, index) => unique.set(rawEventKey(event, index), event));
  return [...unique.values()]
    .sort((left, right) => {
      const leftTime = new Date(firstValue(left, ["timestamp", "time", "@timestamp", "datetime"], 0)).getTime();
      const rightTime = new Date(firstValue(right, ["timestamp", "time", "@timestamp", "datetime"], 0)).getTime();
      return leftTime - rightTime;
    })
    .slice(-limit);
}

async function collectWindowsEvents(background = false) {
  if (!backendOnline || collectionInProgress) return;
  collectionInProgress = true;
  const button = $("#collect-windows");
  button.disabled = true;
  button.textContent = "Collecting...";
  $("#analysis-error").textContent = "";
  try {
    const channel = $("#windows-channel").value;
    const maximum = $("#windows-max-events").value;
    const incremental = $("#incremental-collection").checked;
    const payload = await apiRequest(`/api/windows-events?channel=${encodeURIComponent(channel)}&max=${maximum}&incremental=${incremental}`);
    $("#checkpoint-status").textContent = payload.checkpoint
      ? `Checkpoint ${payload.checkpoint.toLocaleString()} · ${payload.newCount} new records${payload.checkpointReset ? " · log rollover detected" : ""}`
      : "No event records were available.";
    if (!payload.events.length) {
      if (!background) showToast("No new Windows events were found.");
      return;
    }
    const sameLiveSource = incremental && state.sourceName === payload.sourceName;
    const inputEvents = sameLiveSource
      ? mergeEventBatches(state.events, payload.events)
      : payload.events;
    await runAnalysis(inputEvents, payload.sourceName);
    if (!background) {
      closeModal($("#analyzer-modal"));
      switchView("overview");
    }
    showToast(`${payload.newCount} new Windows event${payload.newCount === 1 ? "" : "s"} analyzed. ${state.events.length} retained.`);
  } catch (error) {
    $("#analysis-error").textContent = `${error.message} Administrator access may be required for Security logs.`;
  } finally {
    collectionInProgress = false;
    button.disabled = false;
    button.textContent = "Collect";
  }
}

function toggleAutoCollection() {
  clearInterval(liveCollectionTimer);
  liveCollectionTimer = null;
  if (!$("#auto-collect").checked) {
    $("#incremental-collection").disabled = false;
    showToast("Automatic Windows log collection stopped.");
    return;
  }
  if (!backendOnline) {
    $("#auto-collect").checked = false;
    showToast("Start the local service before enabling automatic collection.");
    return;
  }
  $("#incremental-collection").checked = true;
  $("#incremental-collection").disabled = true;
  collectWindowsEvents(true);
  liveCollectionTimer = setInterval(() => collectWindowsEvents(true), 60 * 1000);
  showToast("Windows logs will refresh every 60 seconds.");
}

async function resetWindowsCheckpoint() {
  if (!backendOnline) return;
  const channel = $("#windows-channel").value;
  try {
    await apiRequest("/api/windows-checkpoint/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channel }),
    });
    $("#checkpoint-status").textContent = `Checkpoint reset for ${channel}.`;
    showToast(`The ${channel} checkpoint was reset.`);
  } catch (error) {
    showToast(error.message);
  }
}

async function loadHistory() {
  const target = $("#history-table");
  if (!backendOnline) {
    target.innerHTML = '<tr><td colspan="6"><div class="empty-state">Run start.ps1 to store analysis history.</div></td></tr>';
    return;
  }
  try {
    const payload = await apiRequest("/api/analyses");
    target.innerHTML = payload.analyses.length ? payload.analyses.map((analysis) => `
      <tr>
        <td>${formatTime(analysis.created_at)}</td>
        <td><span class="finding-title">${escapeHtml(analysis.source_name)}</span></td>
        <td>${formatNumber(analysis.event_count)}</td>
        <td>${formatNumber(analysis.alert_count)}</td>
        <td><span class="severity-pill ${escapeHtml(analysis.risk_level)}">${escapeHtml(analysis.risk_level)} - ${analysis.risk_score}</span></td>
        <td><button class="row-button" data-history-id="${analysis.id}">Open</button></td>
      </tr>`).join("") : '<tr><td colspan="6"><div class="empty-state">No saved analyses yet.</div></td></tr>';
  } catch (error) {
    target.innerHTML = `<tr><td colspan="6"><div class="empty-state">${escapeHtml(error.message)}</div></td></tr>`;
  }
}

async function openHistoryAnalysis(id) {
  try {
    const payload = await apiRequest(`/api/analyses/${id}`);
    state = {
      events: payload.events || [],
      alerts: payload.alerts || [],
      riskScore: payload.riskScore || 0,
      riskLevel: payload.riskLevel || "Low",
      sourceName: payload.sourceName || "Saved analysis",
      analysis: new Date(),
    };
    renderAll();
    switchView("overview");
    showToast("Saved analysis opened.");
  } catch (error) {
    showToast(error.message);
  }
}

function renderCustomRules() {
  const rules = getCustomRules();
  $("#custom-rules-list").innerHTML = rules.length ? rules.map((rule) => `
    <div class="custom-rule">
      <div>
        <strong><span class="severity-pill ${escapeHtml(rule.severity)}">${escapeHtml(rule.severity)}</span> ${escapeHtml(rule.name)}</strong>
        <span>${escapeHtml(rule.field)} ${rule.regex ? "matches regex" : "contains"}: ${escapeHtml(rule.pattern)} - ${escapeHtml(rule.mitreId || "Custom")}</span>
      </div>
      <button class="delete-rule" data-rule-id="${escapeHtml(rule.id)}">Delete</button>
    </div>`).join("") : '<div class="empty-state">No custom detection rules have been created.</div>';
}

function addCustomRule(event) {
  event.preventDefault();
  const pattern = $("#rule-pattern").value.trim();
  const regex = $("#rule-regex").checked;
  try {
    if (regex) new RegExp(pattern, "i");
    const rules = getCustomRules();
    rules.push({
      id: `rule-${Date.now()}`,
      name: $("#rule-name").value.trim(),
      field: $("#rule-field").value,
      pattern,
      regex,
      severity: $("#rule-severity").value,
      mitreId: $("#rule-mitre-id").value.trim(),
      mitreName: $("#rule-mitre-name").value.trim(),
      enabled: true,
    });
    saveCustomRules(rules);
    event.target.reset();
    $("#rule-error").textContent = "";
    renderCustomRules();
    showToast("Custom detection rule added.");
  } catch {
    $("#rule-error").textContent = "The regular expression is invalid.";
  }
}

function deleteCustomRule(id) {
  saveCustomRules(getCustomRules().filter((rule) => rule.id !== id));
  renderCustomRules();
}

function downloadFile(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function exportReport() {
  if (!state.events.length) return;
  const format = $("#export-format").value;
  const timestamp = new Date().toISOString().replaceAll(":", "-").slice(0, 19);
  if (format === "json") {
    downloadFile(`sentinelops-${timestamp}.json`, JSON.stringify({
      generatedAt: new Date().toISOString(),
      sourceName: state.sourceName,
      riskScore: state.riskScore,
      riskLevel: state.riskLevel,
      events: state.events,
      alerts: state.alerts,
    }, null, 2), "application/json");
  } else if (format === "csv") {
    const rows = [["Severity", "Finding", "Description", "Source IP", "User", "Host", "MITRE ID", "MITRE Technique", "Timestamp"]];
    state.alerts.forEach((alert) => rows.push([alert.severity, alert.title, alert.description, alert.sourceIp, alert.user, alert.host, alert.mitre.id, alert.mitre.name, alert.timestamp]));
    downloadFile(`sentinelops-alerts-${timestamp}.csv`, rows.map((row) => row.map(csvCell).join(",")).join("\r\n"), "text/csv");
  } else {
    const report = `<!doctype html><html><head><meta charset="utf-8"><title>SentinelOps Report</title><style>body{font:14px Arial;color:#17212b;margin:40px}h1{margin-bottom:4px}.summary{display:flex;gap:12px;margin:24px 0}.card{border:1px solid #ccd6df;padding:14px;min-width:120px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ccd6df;padding:8px;text-align:left}th{background:#eef3f6}.High{color:#b42335}.Medium{color:#9a5a00}.Low{color:#087a50}</style></head><body><h1>SentinelOps Security Report</h1><p>${escapeHtml(state.sourceName)} - Generated ${escapeHtml(new Date().toLocaleString())}</p><div class="summary"><div class="card"><b>Events</b><br>${state.events.length}</div><div class="card"><b>Alerts</b><br>${state.alerts.length}</div><div class="card"><b>Risk</b><br><span class="${state.riskLevel}">${state.riskLevel} ${state.riskScore}/100</span></div></div><table><thead><tr><th>Severity</th><th>Finding</th><th>Source</th><th>MITRE</th><th>Time</th></tr></thead><tbody>${state.alerts.map((alert) => `<tr><td class="${alert.severity}">${escapeHtml(alert.severity)}</td><td><b>${escapeHtml(alert.title)}</b><br>${escapeHtml(alert.description)}</td><td>${escapeHtml(alert.sourceIp)}<br>${escapeHtml(alert.user)}</td><td>${escapeHtml(alert.mitre.id)} ${escapeHtml(alert.mitre.name)}</td><td>${escapeHtml(formatTime(alert.timestamp))}</td></tr>`).join("")}</tbody></table><script>window.onload=()=>window.print()</script></body></html>`;
    const reportWindow = window.open("", "_blank");
    reportWindow.document.write(report);
    reportWindow.document.close();
  }
}

function notifyHighSeverity() {
  const highCount = state.alerts.filter((alert) => alert.severity === "High").length;
  if (highCount && "Notification" in window && Notification.permission === "granted") {
    new Notification("SentinelOps high-severity findings", {
      body: `${highCount} high-severity alert${highCount === 1 ? "" : "s"} detected in ${state.sourceName}.`,
    });
  }
}

async function enableNotifications() {
  if (!("Notification" in window)) {
    showToast("Desktop notifications are not supported by this browser.");
    return;
  }
  const permission = await Notification.requestPermission();
  showToast(permission === "granted" ? "High-severity notifications enabled." : "Notification permission was not granted.");
}

async function handleFile(file) {
  if (!file) return;
  if (file.name.toLowerCase().endsWith(".evtx")) {
    if (!backendOnline) {
      $("#analysis-error").textContent = "EVTX requires the local service. Run start.ps1, then open http://127.0.0.1:8080.";
      return;
    }
    $("#file-label").textContent = `${file.name} - uploading and parsing`;
    $("#analysis-error").textContent = "";
    try {
      const maximum = $("#windows-max-events").value;
      const payload = await apiRequest(`/api/import-evtx?max=${maximum}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(file.name) },
        body: file,
      });
      await runAnalysis(payload.events, payload.sourceName);
      closeModal($("#analyzer-modal"));
      switchView("overview");
      showToast(`${state.events.length} EVTX events were parsed and analyzed.`);
    } catch (error) {
      $("#analysis-error").textContent = error.message;
    }
    return;
  }
  const text = await file.text();
  $("#log-input").value = text;
  $("#file-label").textContent = `${file.name} - ${(file.size / 1024).toFixed(1)} KB`;
  $("#analysis-error").textContent = "";
}

function init() {
  renderAll();
  renderCustomRules();
  checkBackend();

  $$(".nav-item").forEach((item) => item.addEventListener("click", () => switchView(item.dataset.view)));
  $$("[data-switch-view]").forEach((item) => item.addEventListener("click", () => switchView(item.dataset.switchView)));
  $("#open-analyzer").addEventListener("click", () => openModal($("#analyzer-modal")));
  $(".close-modal").addEventListener("click", () => closeModal($("#analyzer-modal")));
  $(".close-detail").addEventListener("click", () => closeModal($("#detail-modal")));
  $$(".modal-backdrop").forEach((modal) => modal.addEventListener("click", (event) => { if (event.target === modal) closeModal(modal); }));
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") $$(".modal-backdrop.open").forEach(closeModal); });

  $("#run-analysis").addEventListener("click", async () => {
    try {
      const raw = parseLogs($("#log-input").value);
      const label = $("#file-label").textContent;
      await runAnalysis(raw, label.includes(" - ") ? label.split(" - ")[0].trim() : "Pasted logs");
      closeModal($("#analyzer-modal"));
      showToast(`${state.events.length} events produced ${state.alerts.length} security alerts.`);
      $("#log-input").value = "";
      $("#file-label").textContent = "EVTX, JSON, JSONL, CSV, LOG, or TXT";
      $("#analysis-error").textContent = "";
      switchView("overview");
    } catch (error) {
      $("#analysis-error").textContent = error.message || "The log format could not be parsed.";
    }
  });
  $("#file-input").addEventListener("change", (event) => handleFile(event.target.files[0]));
  const dropZone = $("#drop-zone");
  ["dragenter", "dragover"].forEach((name) => dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((name) => dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.remove("dragging"); }));
  dropZone.addEventListener("drop", (event) => handleFile(event.dataTransfer.files[0]));
  $("#alert-search").addEventListener("input", renderAlertsTable);
  $("#severity-filter").addEventListener("change", renderAlertsTable);
  $("#event-search").addEventListener("input", renderEventsTable);
  $("#collect-windows").addEventListener("click", () => collectWindowsEvents(false));
  $("#auto-collect").addEventListener("change", toggleAutoCollection);
  $("#reset-checkpoint").addEventListener("click", resetWindowsCheckpoint);
  $("#windows-channel").addEventListener("change", () => {
    $("#checkpoint-status").textContent = "Checkpoint status will update after collection.";
  });
  $("#refresh-history").addEventListener("click", loadHistory);
  $("#rule-form").addEventListener("submit", addCustomRule);
  $("#enable-notifications").addEventListener("click", enableNotifications);
  $("#export-report").addEventListener("click", exportReport);
  document.addEventListener("click", (event) => {
    const alertTrigger = event.target.closest("[data-alert-id]");
    if (alertTrigger) showAlertDetails(alertTrigger.dataset.alertId);
    const historyTrigger = event.target.closest("[data-history-id]");
    if (historyTrigger) openHistoryAnalysis(historyTrigger.dataset.historyId);
    const ruleTrigger = event.target.closest("[data-rule-id]");
    if (ruleTrigger) deleteCustomRule(ruleTrigger.dataset.ruleId);
  });
  $("#theme-toggle").addEventListener("click", () => document.body.classList.toggle("light"));
}

init();
