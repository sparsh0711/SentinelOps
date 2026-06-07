const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
const displayIp = (ip) => ip === "unknown" ? "Not present" : ip;
const formatTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};

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
    <div class="alert ${item.severity.toLowerCase()}"><span class="badge">${item.severity}</span><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.description)}</span></div>`).join("") : "No alerts detected.";

  const techniques = [...new Map(state.alerts.map((item) => [item.mitre.id, item.mitre])).values()];
  $("#mitre").className = techniques.length ? "list" : "list empty";
  $("#mitre").innerHTML = techniques.length ? techniques.map((item) => `
    <div class="technique"><span class="badge">${escapeHtml(item.id)}</span><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.tactic)}</span></div>`).join("") : "No techniques detected.";
  renderEvents(state.events);
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
}

export function renderBackendStatus(online, version = "") {
  $("#service-dot").className = online ? "online" : "offline";
  $("#service-label").textContent = online ? `Online ${version}` : "Service offline";
}
