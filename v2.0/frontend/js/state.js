const initialState = () => ({
  sourceName: "No logs loaded",
  events: [],
  alerts: [],
  riskScore: 0,
  riskLevel: "Low",
  backendOnline: false,
  rules: [],
  detectionSettings: {
    allowlists: { users: [], hosts: [], sourceIps: [], processes: [] },
    suppressionWindowSeconds: 300,
    severityOverrides: {},
    thresholdOverrides: {},
  },
});

export function createStore(seed = {}) {
  let state = { ...initialState(), ...seed };
  const listeners = new Set();
  return {
    get: () => state,
    set: (patch) => {
      state = { ...state, ...patch };
      listeners.forEach((listener) => listener(state));
      return state;
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
