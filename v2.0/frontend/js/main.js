import { api } from "./api.js";
import { analyzeEvents } from "./detections.js";
import { parseLogs } from "./parsers.js";
import { createStore } from "./state.js";
import { bindUi, render, renderBackendStatus } from "./ui.js";

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

  const result = analyzeEvents(rawEvents);
  const analysis = { ...result, sourceName };
  store.set(analysis);
  if (store.get().backendOnline) {
    try { await api.saveAnalysis(analysis); } catch (error) { console.warn(error.message); }
  }
}

bindUi(store, { analyze });

try {
  const status = await api.status();
  store.set({ backendOnline: true });
  renderBackendStatus(true, status.version);
} catch {
  renderBackendStatus(false);
}
