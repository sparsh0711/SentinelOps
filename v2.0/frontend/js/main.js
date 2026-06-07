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
  testSelectedRule,
});

try {
  const status = await api.status();
  store.set({ backendOnline: true });
  renderBackendStatus(true, status.version);
  await refreshRules();
} catch {
  renderBackendStatus(false);
}
