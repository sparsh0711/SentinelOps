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
  store.set({ incidents: payload.incidents, incidentFilter: status, selectedIncident: current && payload.incidents.some((item) => item.id === current.id) ? current : null, incidentError: "" });
}

async function saveRule(rule) { await api.saveRule(rule); await refreshRules(); }
async function toggleRule(id, enabled) { await api.toggleRule(id, enabled); await refreshRules(); }
async function deleteRule(id) { await api.deleteRule(id); await refreshRules(); }
async function saveSettings(settings) { store.set({ detectionSettings: await api.saveDetectionSettings(settings) }); }
async function saveRuleOverride(ruleId, severity, threshold) {
  const current = store.get().detectionSettings;
  const severityOverrides = { ...(current.severityOverrides || {}), [ruleId]: severity };
  const thresholdOverrides = { ...(current.thresholdOverrides || {}) };
  if (threshold) thresholdOverrides[ruleId] = threshold; else delete thresholdOverrides[ruleId];
  await saveSettings({ ...current, severityOverrides, thresholdOverrides });
}
async function importRules(rules) { for (const rule of rules) await api.saveRule(rule); await refreshRules(); }

async function createIncidentFromAlert(alertId) {
  const state = store.get();
  if (!state.backendOnline) throw new Error("Start the local v2 service before creating incidents.");
  const alert = state.alerts.find((item) => item.id === alertId);
  if (!alert) throw new Error("That alert is no longer available.");
  const incident = await api.createIncident({ sourceName: state.sourceName, riskScore: state.riskScore, alert: { ...alert, riskScore: alert.riskScore ?? state.riskScore, events: (alert.events || []).slice(0, 20) } });
  const listing = await api.listIncidents(state.incidentFilter);
  store.set({ incidents: listing.incidents, selectedIncident: incident, incidentError: "" });
}

async function createCorrelatedIncident() {
  const state = store.get();
  if (!state.backendOnline) throw new Error("Start the local v2 service before creating incidents.");
  if (!state.alerts.length) throw new Error("Analyze logs before creating a correlated incident.");
  const severityRank = { Low: 1, Medium: 2, High: 3 };
  const primary = [...state.alerts].sort((a, b) => severityRank[b.severity] - severityRank[a.severity])[0];
  const incident = await api.createIncident({ title: `Correlated activity: ${state.alerts.length} security alerts`, sourceName: state.sourceName, riskScore: state.riskScore, severity: state.riskLevel, alerts: state.alerts.map((alert) => ({ ...alert, events: (alert.events || []).slice(0, 30) })), alert: primary, evidence: state.events.slice(0, 200) });
  const listing = await api.listIncidents(state.incidentFilter);
  store.set({ incidents: listing.incidents, selectedIncident: incident, incidentError: "" });
}

async function selectIncident(id) { if (id) store.set({ selectedIncident: await api.getIncident(id), incidentError: "" }); }
async function updateIncident(id, patch) { const incident = await api.updateIncident(id, patch); const listing = await api.listIncidents(store.get().incidentFilter); store.set({ selectedIncident: incident, incidents: listing.incidents, incidentError: "" }); }
async function addIncidentNote(id, note) { const incident = await api.addIncidentNote(id, note); const listing = await api.listIncidents(store.get().incidentFilter); store.set({ selectedIncident: incident, incidents: listing.incidents, incidentError: "" }); }
async function generateIncidentSummary(id) {
  store.set({ summaryGenerating: true, incidentError: "" });
  try { await api.generateIncidentSummary(id); store.set({ selectedIncident: await api.getIncident(id), summaryGenerating: false }); }
  catch (error) { store.set({ summaryGenerating: false, incidentError: error.message }); throw error; }
}
function testSelectedRule(ruleId, text) { const rule = store.get().rules.find((item) => item.id === ruleId); if (!rule) throw new Error("Choose a detection rule."); renderRuleTest(testRule(rule, parseLogs(text).map(normalizeEvent), store.get().detectionSettings)); }

bindUi(store, { analyze, saveRule, toggleRule, deleteRule, saveSettings, saveRuleOverride, importRules, refreshIncidents, createIncidentFromAlert, createCorrelatedIncident, selectIncident, updateIncident, addIncidentNote, generateIncidentSummary, testSelectedRule });
try { const status = await api.status(); store.set({ backendOnline: true, aiSummary: status.aiSummary || store.get().aiSummary }); renderBackendStatus(true, status.version); await Promise.all([refreshRules(), refreshIncidents()]); }
catch { renderBackendStatus(false); }
