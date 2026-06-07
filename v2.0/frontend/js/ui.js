const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
const displayIp = (ip) => ip === "unknown" ? "Not present" : ip;
const formatTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};
const lines = (value) => value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);

function renderEvents(events) {
  const query = $("#event-search").value.toLowerCase();
  const filtered = events.filter((event) => `${event.eventId} ${event.user} ${event.sourceIp} ${event.host} ${event.message}`.toLowerCase().includes(query));
  $("#event-summary").textContent = `${filtered.length} of ${events.length} events`;
  $("#events").innerHTML = filtered.length ? [...filtered].reverse().map((event) => `
    <tr>
      <td>${escapeHtml(formatTime(event.timestamp))}</td>
      <td><strong>${escapeHtml(event.eventId || "Event")}</strong><br>${escapeHtml(event.message.slice(0, 60))}</td>
      <td>${escapeHtml(event.user)}</td>
      <td>${escapeHtml(displayIp(event.sourceIp))}</td>
      <td>${escapeHtml(event.host)}</td>
      <td><span class="status ${escapeHtml(event.status)}">${escapeHtml(event.status)}</span></td>
    </tr>`).join("") : '<tr><td colspan="6" class="empty-cell">No matching events.</td></tr>';
}

export function render(state) {
  $("#source-name").textContent = state.sourceName;
  $("#event-count").textContent = state.events.length;
  $("#alert-count").textContent = state.alerts.length;
  $("#high-count").textContent = `${state.alerts.filter((alert) => alert.severity === "High").length} high severity`;
  $("#ip-count").textContent = new Set(state.events.filter((event) => event.sourceIp !== "unknown").map((event) => event.sourceIp)).size;
  $("#mitre-count").textContent = new Set(state.alerts.map((alert) => alert.mitre.id)).size;
  $("#risk-score").textContent = state.riskScore;
  $("#risk-level").textContent = state.riskLevel.toUpperCase();
  $("#risk-level").className = state.riskLevel.toLowerCase();
  $("#posture").textContent = state.riskLevel === "High" ? "Immediate analyst review required" : state.riskLevel === "Medium" ? "Suspicious activity requires review" : "No high-risk pattern detected";

  $("#alerts").className = state.alerts.length ? "list" : "list empty";
  $("#alerts").innerHTML = state.alerts.length ? state.alerts.slice(0, 6).map((item) => `
    <div class="alert ${item.severity.toLowerCase()}"><span class="badge">${item.severity}</span><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.description)}</span><span class="confidence">${item.confidence ?? 50}% confidence</span><span class="alert-details">${escapeHtml((item.explanation || []).join(" | "))}</span></div>`).join("") : "No alerts detected.";

  const techniques = [...new Map(state.alerts.map((item) => [item.mitre.id, item.mitre])).values()];
  $("#mitre").className = techniques.length ? "list" : "list empty";
  $("#mitre").innerHTML = techniques.length ? techniques.map((item) => `
    <div class="technique"><span class="badge">${escapeHtml(item.id)}</span><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.tactic)}</span></div>`).join("") : "No techniques detected.";
  renderEvents(state.events);
  renderRules(state);
}

export function bindUi(store, handlers) {
  const modal = $("#import-modal");
  $("#open-import").addEventListener("click", () => { modal.hidden = false; });
  $("#close-import").addEventListener("click", () => { modal.hidden = true; });
  $("#file-input").addEventListener("change", (event) => {
    $("#file-name").textContent = event.target.files[0]?.name || "No file selected";
  });
  $("#run-analysis").addEventListener("click", async () => {
    $("#error").textContent = "";
    try {
      await handlers.analyze($("#file-input").files[0], $("#log-input").value);
      modal.hidden = true;
      $("#log-input").value = "";
      $("#file-input").value = "";
      $("#file-name").textContent = "No file selected";
    } catch (error) {
      $("#error").textContent = error.message;
    }
  });
  $("#event-search").addEventListener("input", () => render(store.get()));
  document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === `${button.dataset.view}-view`));
    document.querySelectorAll("[data-view]").forEach((item) => item.classList.toggle("active", item === button));
  }));
  $("#rule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#rule-error").textContent = "";
    try {
      const thresholdCount = Number($("#rule-threshold-count").value);
      const operator = $("#rule-operator").value;
      const rawValue = $("#rule-value").value;
      const value = operator === "in"
        ? rawValue.split(",").map((item) => item.trim()).filter(Boolean)
        : operator === "exists" ? rawValue.toLowerCase() !== "false" : rawValue;
      await handlers.saveRule({
        id: $("#rule-id").value.trim(),
        title: $("#rule-title").value.trim(),
        description: $("#rule-description").value.trim(),
        status: "experimental",
        level: $("#rule-level").value,
        enabled: true,
        confidence: Number($("#rule-confidence").value),
        logsource: { product: "windows", category: "custom" },
        match: { all: [{ field: $("#rule-field").value, operator, value }] },
        threshold: thresholdCount ? {
          count: thresholdCount,
          groupBy: $("#rule-group").value || "host",
          windowSeconds: Number($("#rule-window").value) || 300,
        } : null,
        mitre: {
          id: $("#rule-mitre-id").value.trim(),
          name: $("#rule-mitre-name").value.trim(),
          tactic: "Custom",
        },
        tags: [],
        falsepositives: [],
      });
      event.target.reset();
      $("#rule-confidence").value = 70;
      $("#rule-window").value = 300;
    } catch (error) {
      $("#rule-error").textContent = error.message;
    }
  });
  $("#rule-list").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-rule-action]");
    if (!button) return;
    try {
      if (button.dataset.ruleAction === "toggle") {
        await handlers.toggleRule(button.dataset.ruleId, button.dataset.enabled !== "true");
      }
      if (button.dataset.ruleAction === "delete") await handlers.deleteRule(button.dataset.ruleId);
      if (button.dataset.ruleAction === "override") {
        const card = button.closest(".rule-card");
        const count = Number(card.querySelector("[data-override-count]")?.value);
        const windowSeconds = Number(card.querySelector("[data-override-window]")?.value);
        await handlers.saveRuleOverride(
          button.dataset.ruleId,
          card.querySelector("[data-override-severity]").value,
          count ? { count, windowSeconds: windowSeconds || 300 } : null,
        );
      }
    } catch (error) {
      $("#rule-error").textContent = error.message;
    }
  });
  $("#settings-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const current = store.get().detectionSettings;
    await handlers.saveSettings({
      ...current,
      allowlists: {
        users: lines($("#allow-users").value),
        hosts: lines($("#allow-hosts").value),
        sourceIps: lines($("#allow-ips").value),
        processes: lines($("#allow-processes").value),
      },
      suppressionWindowSeconds: Number($("#suppression-window").value) || 300,
    });
  });
  $("#test-rule-button").addEventListener("click", () => {
    try {
      handlers.testSelectedRule($("#test-rule").value, $("#test-events").value);
    } catch (error) {
      $("#test-result").textContent = error.message;
    }
  });
  $("#rule-import").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      await handlers.importRules(Array.isArray(parsed) ? parsed : [parsed]);
    } catch (error) {
      $("#rule-error").textContent = `Rule import failed: ${error.message}`;
    } finally {
      event.target.value = "";
    }
  });
}

export function renderBackendStatus(online, version = "") {
  $("#service-dot").className = online ? "online" : "offline";
  $("#service-label").textContent = online ? `Online ${version}` : "Service offline";
}

function renderRules(state) {
  if (!$("#rule-list")) return;
  $("#rule-count").textContent = state.rules.length;
  $("#rule-list").className = state.rules.length ? "rule-list" : "rule-list empty";
  $("#rule-list").innerHTML = state.rules.length ? state.rules.map((rule) => `
    <div class="rule-card ${rule.enabled ? "" : "disabled"}">
      <div class="rule-card-head"><div><strong>${escapeHtml(rule.title)}</strong><span>${escapeHtml(rule.id)} - ${escapeHtml(rule.mitre?.id || "No MITRE")}</span></div><span class="badge">${escapeHtml(rule.level)}</span></div>
      <span>${escapeHtml(rule.description)}</span>
      <span>${rule.confidence ?? 50}% confidence${rule.threshold ? ` - ${rule.threshold.count} events / ${rule.threshold.windowSeconds}s by ${escapeHtml(rule.threshold.groupBy)}` : ""}</span>
      <div class="rule-card-actions">
        <button data-rule-action="toggle" data-rule-id="${escapeHtml(rule.id)}" data-enabled="${rule.enabled}">${rule.enabled ? "Disable" : "Enable"}</button>
        ${rule.source === "custom" ? `<button data-rule-action="delete" data-rule-id="${escapeHtml(rule.id)}">Delete</button>` : ""}
      </div>
      <div class="rule-overrides">
        <label>Severity<select data-override-severity><option ${effectiveSeverity(state, rule) === "Low" ? "selected" : ""}>Low</option><option ${effectiveSeverity(state, rule) === "Medium" ? "selected" : ""}>Medium</option><option ${effectiveSeverity(state, rule) === "High" ? "selected" : ""}>High</option></select></label>
        <label>Count<input data-override-count type="number" min="1" value="${state.detectionSettings.thresholdOverrides?.[rule.id]?.count || rule.threshold?.count || ""}" ${rule.threshold ? "" : "disabled"} /></label>
        <label>Window<input data-override-window type="number" min="1" value="${state.detectionSettings.thresholdOverrides?.[rule.id]?.windowSeconds || rule.threshold?.windowSeconds || ""}" ${rule.threshold ? "" : "disabled"} /></label>
        <button data-rule-action="override" data-rule-id="${escapeHtml(rule.id)}">Apply</button>
      </div>
    </div>`).join("") : "No rules loaded.";
  const selected = $("#test-rule").value;
  $("#test-rule").innerHTML = state.rules.map((rule) => `<option value="${escapeHtml(rule.id)}">${escapeHtml(rule.title)}</option>`).join("");
  if (selected && state.rules.some((rule) => rule.id === selected)) $("#test-rule").value = selected;
  const allowlists = state.detectionSettings.allowlists || {};
  $("#allow-users").value = (allowlists.users || []).join("\n");
  $("#allow-hosts").value = (allowlists.hosts || []).join("\n");
  $("#allow-ips").value = (allowlists.sourceIps || []).join("\n");
  $("#allow-processes").value = (allowlists.processes || []).join("\n");
  $("#suppression-window").value = state.detectionSettings.suppressionWindowSeconds || 300;
}

function effectiveSeverity(state, rule) {
  return state.detectionSettings.severityOverrides?.[rule.id] || rule.level;
}

export function renderRuleTest(result) {
  const target = $("#test-result");
  target.className = "test-result";
  target.innerHTML = result.alerts.length
    ? `<strong>${result.alerts.length} alert${result.alerts.length === 1 ? "" : "s"} matched</strong><span>${escapeHtml(result.alerts.flatMap((alert) => alert.explanation).join(" | "))}</span>`
    : "<strong>No match</strong><span>The supplied events did not satisfy this rule.</span>";
}
