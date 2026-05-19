const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!resp.ok) throw new Error(`API ${path} → ${resp.status}`);
  return resp.json() as Promise<T>;
}

export const api = {
  getAlerts: (params?: { limit?: number; severity?: string }) => {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.severity) qs.set("severity", params.severity);
    return apiFetch<unknown[]>(`/api/alerts?${qs}`);
  },

  getAlert: (id: string) => apiFetch<unknown>(`/api/alerts/${id}`),

  markFalsePositive: (id: string, detectors: string[]) =>
    apiFetch<{ ok: boolean }>(`/api/alerts/${id}/false_positive`, {
      method: "POST",
      body: JSON.stringify({ detectors }),
    }),

  startCapture: (iface: string, bpfFilter: string) =>
    apiFetch<{ ok: boolean }>("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({ interface: iface, bpf_filter: bpfFilter }),
    }),

  stopCapture: () =>
    apiFetch<{ ok: boolean }>("/api/capture/stop", { method: "POST" }),

  getStats: () => apiFetch<Record<string, number>>("/api/stats"),

  getActiveFlows: () => apiFetch<unknown[]>("/api/flows/active"),

  getSimilar: (alertId: string, top = 5) =>
    apiFetch<{ similar_alerts: unknown[] }>(`/api/similar/${alertId}?top=${top}`),
};
