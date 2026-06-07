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
};
