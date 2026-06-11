const initialState = () => ({
  sourceName: "No logs loaded", events: [], alerts: [], riskScore: 0, riskLevel: "Low", backendOnline: false, rules: [], incidents: [], selectedIncident: null, incidentFilter: "", incidentError: "", summaryGenerating: false,
  aiSummary: { configured: false, provider: "local-evidence", model: "deterministic-v1", dataLeavesDevice: false },
  hunts: [], huntRuns: [], selectedHunt: "failed-login-hunt", huntResult: null, iocs: [], iocResult: null, attackHeatmap: [], investigationTimeline: [], phase6Error: "",
  detectionSettings: { allowlists: { users: [], hosts: [], sourceIps: [], processes: [] }, suppressionWindowSeconds: 300, severityOverrides: {}, thresholdOverrides: {} },
});
export function createStore(seed = {}) { let state={...initialState(),...seed};const listeners=new Set();return {get:()=>state,set:(patch)=>{state={...state,...patch};listeners.forEach(listener=>listener(state));return state},subscribe:(listener)=>{listeners.add(listener);return()=>listeners.delete(listener)}}; }
