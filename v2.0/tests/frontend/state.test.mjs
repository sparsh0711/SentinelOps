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
