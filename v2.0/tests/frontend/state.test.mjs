import test from "node:test";
import assert from "node:assert/strict";

import { createStore } from "../../frontend/js/state.js";

test("store publishes immutable top-level state updates", () => {
  const store = createStore();
  const initial = store.get();
  let observed;
  store.subscribe((state) => { observed = state; });
  store.set({ riskScore: 65, riskLevel: "High" });
  assert.notEqual(store.get(), initial);
  assert.equal(observed.riskLevel, "High");
  assert.equal(store.get().sourceName, "No logs loaded");
});

test("detection settings are part of default state", () => {
  const store = createStore();
  assert.deepEqual(store.get().detectionSettings.allowlists.users, []);
  assert.equal(store.get().detectionSettings.suppressionWindowSeconds, 300);
});

test("incident workflow state starts empty", () => {
  const store = createStore();
  assert.deepEqual(store.get().incidents, []);
  assert.equal(store.get().selectedIncident, null);
  assert.equal(store.get().incidentFilter, "");
  assert.equal(store.get().summaryGenerating, false);
  assert.equal(store.get().aiSummary.dataLeavesDevice, false);
});
