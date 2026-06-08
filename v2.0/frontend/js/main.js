import { api } from "./api.js";
import { analyzeEvents } from "./detections.js";
import { normalizeEvent, parseLogs } from "./parsers.js";
import { testRule } from "./rule_engine.js";
import { createStore } from "./state.js";
import { bindUi, render, renderBackendStatus, renderRuleTest } from "./ui.js";

const store = createStore();
store.subscribe(render);
render(store.get());

async function analyze(file, pastedText) {
  let rawEvents;
  let sourceName;
  if (file?.name.toLowerCase().endsWith(".evtx")) {
    if (!store.get().backendOnline) throw new Error("EVTX requires the local v2 service.");
    const payload = await api.importEvtx(file);
    rawEvents = payload.events;
    sourceName = payload.sourceName;
  } else if (file) {
    rawEvents = parseLogs(await file.text());
    sourceName = file.name;
  } else {
    rawEvents = parseLogs(pastedText);
    sourceName = "Pasted logs";
  }

  const result = analyzeEvents(rawEvents, store.get().rules, store.get().detectionSettings);
  const analysis = { ...result, sourceName };
  store.set(analysis);
  if (store.get().backendOnline) {
    try { await api.saveAnalysis(analysis); } catch (error) { console.warn(error.message); }
  }
}

async function refreshRules() {
  const [rulePayload, settings] = await Promise.all([api.listRules(), api.getDetectionSettings()]);
  store.set({ rules: rulePayload.rules, detectionSettings: settings });
}

async function refreshIncidents(status = store.get().incidentFilter) {
  if (!store.get().backendOnline) return;
  const payload = await api.listIncidents(status);
  const current = store.get().selectedIncident;
  store.set({
    incidents: payload.incidents,
    incidentFilter: status,
    selectedIncident: current && payload.incidents.some((item) => item.id === current.id)
      ? current
      : null,
    incidentError: "",
  });
}

async function saveRule(rule) {
  await api.saveRule(rule);
  await refreshRules();
}

async function toggleRule(id, enabled) {
  await api.toggleRule(id, enabled);
  await refreshRules();
}

async function deleteRule(id) {
  await api.deleteRule(id);
  await refreshRules();
}

async function saveSettings(settings) {
  const saved = await api.saveDetectionSettings(settings);
  store.set({ detectionSettings: saved });
}

async function saveRuleOverride(ruleId, severity, threshold) {
  const current = store.get().detectionSettings;
  const severityOverrides = { ...(current.severityOverrides || {}), [ruleId]: severity };
  const thresholdOverrides = { ...(current.thresholdOverrides || {}) };
  if (threshold) thresholdOverrides[ruleId] = threshold;
  else delete thresholdOverrides[ruleId];
  await saveSettings({ ...current, severityOverrides, thresholdOverrides });
}

async function importRules(rules) {
  for (const rule of rules) await api.saveRule(rule);
  await refreshRules();
}

async function createIncidentFromAlert(alertId) {
  if (!store.get().backendOnline) throw new Error("Start the local v2 service before creating incidents.");
  const state = store.get();
  const alert = state.alerts.find((item) => item.id === alertId);
  if (!alert) throw new Error("That alert is no longer available.");
  const incident = await api.createIncident({
    sourceName: state.sourceName,
    riskScore: state.riskScore,
    alert: {
      ...alert,
      riskScore: alert.riskScore ?? state.riskScore,
      events: (alert.events || []).slice(0, 20),
    },
  });
  const listing = await api.listIncidents(state.incidentFilter);
  store.set({ incidents: listing.incidents, selectedIncident: incident, incidentError: "" });
}

async function selectIncident(id) {
  if (!id) return;
  const incident = await api.getIncident(id);
  store.set({ selectedIncident: incident, incidentError: "" });
}

async function updateIncident(id, patch) {
  const incident = await api.updateIncident(id, patch);
  const listing = await api.listIncidents(store.get().incidentFilter);
  store.set({ selectedIncident: incident, incidents: listing.incidents, incidentError: "" });
}

async function addIncidentNote(id, note) {
  const incident = await api.addIncidentNote(id, note);
  const listing = await api.listIncidents(store.get().incidentFilter);
  store.set({ selectedIncident: incident, incidents: listing.incidents, incidentError: "" });
}

function testSelectedRule(ruleId, text) {
  const rule = store.get().rules.find((item) => item.id === ruleId);
  if (!rule) throw new Error("Choose a detection rule.");
  const events = parseLogs(text).map(normalizeEvent);
  renderRuleTest(testRule(rule, events, store.get().detectionSettings));
}

bindUi(store, {
  analyze,
  saveRule,
  toggleRule,
  deleteRule,
  saveSettings,
  saveRuleOverride,
  importRules,
  refreshIncidents,
  createIncidentFromAlert,
  selectIncident,
  updateIncident,
  addIncidentNote,
  testSelectedRule,
});

try {
  const status = await api.status();
  store.set({ backendOnline: true });
  renderBackendStatus(true, status.version);
  await Promise.all([refreshRules(), refreshIncidents()]);
} catch {
  renderBackendStatus(false);
}
