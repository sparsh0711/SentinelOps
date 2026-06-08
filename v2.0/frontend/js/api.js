import { API_BASE } from "./config.js";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("The local service returned an invalid response.");
  }
  if (!response.ok) {
    throw new Error(payload.error?.message || `Request failed (${response.status}).`);
  }
  return payload;
}

export const api = {
  status: () => request("/status"),
  saveAnalysis: (analysis) => request("/analyses", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(analysis),
  }),
  importEvtx: (file, maximum = 5000) => request(`/imports/evtx?max=${maximum}`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(file.name) },
    body: file,
  }),
  listRules: () => request("/rules"),
  saveRule: (rule) => request("/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rule),
  }),
  toggleRule: (id, enabled) => request("/rules/toggle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, enabled }),
  }),
  deleteRule: (id) => request("/rules/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id }),
  }),
  getDetectionSettings: () => request("/detection-settings"),
  saveDetectionSettings: (settings) => request("/detection-settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(settings),
  }),
  listIncidents: (status = "") => request(`/incidents${status ? `?status=${encodeURIComponent(status)}` : ""}`),
  getIncident: (id) => request(`/incidents/${encodeURIComponent(id)}`),
  createIncident: (incident) => request("/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(incident),
  }),
  updateIncident: (id, patch) => request(`/incidents/${encodeURIComponent(id)}/update`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  }),
  addIncidentNote: (id, note) => request(`/incidents/${encodeURIComponent(id)}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(note),
  }),
};
