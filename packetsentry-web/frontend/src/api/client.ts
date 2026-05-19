// packetsentry-web/frontend/src/api/client.ts
import { useAuthStore } from "../store/authStore";

const BASE = (import.meta.env.VITE_API_URL ?? "http://localhost:8000").replace(/\/$/, "");

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = useAuthStore.getState().token;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const resp = await fetch(`${BASE}${path}`, { headers, ...init });
  if (resp.status === 401) {
    const store = useAuthStore.getState();
    if (store.isAuthenticated) {
      store.logout();
      window.location.href = "/";
    }
    throw new Error("Unauthenticated");
  }
  if (!resp.ok) throw new Error(`API ${path} → ${resp.status}`);
  return resp.json() as Promise<T>;
}

export const api = {
  // Auth
  login: (password: string) =>
    apiFetch<{ access_token: string; role: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ password }),
    }),
  demoToken: () =>
    apiFetch<{ access_token: string; role: string }>("/auth/demo-token"),

  // Alerts (real or demo)
  getAlerts: (params?: { limit?: number; severity?: string }) => {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.severity) qs.set("severity", params.severity);
    const isDemo = useAuthStore.getState().isDemo;
    return apiFetch<unknown[]>(
      isDemo ? "/api/demo/alerts" : `/api/alerts?${qs}`
    );
  },

  getAlert: (id: string) => apiFetch<unknown>(`/api/alerts/${id}`),

  markFalsePositive: (id: string, detectors: string[]) =>
    apiFetch<{ ok: boolean }>(`/api/alerts/${id}/false_positive`, {
      method: "POST",
      body: JSON.stringify({ detectors }),
    }),

  // Stats (real or demo)
  getStats: () => {
    const isDemo = useAuthStore.getState().isDemo;
    return apiFetch<Record<string, number>>(
      isDemo ? "/api/demo/stats" : "/api/stats"
    );
  },

  startCapture: (iface: string, bpfFilter: string) =>
    apiFetch<{ ok: boolean }>("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({ interface: iface, bpf_filter: bpfFilter }),
    }),

  stopCapture: () =>
    apiFetch<{ ok: boolean }>("/api/capture/stop", { method: "POST" }),

  getActiveFlows: () => apiFetch<unknown[]>("/api/flows/active"),

  getSimilar: (alertId: string, top = 5) =>
    apiFetch<{ similar_alerts: unknown[] }>(`/api/similar/${alertId}?top=${top}`),

  // Simulate
  simulateBurst: (count: number, attackType?: string) =>
    apiFetch<{ ok: boolean; generated: number; alerts: unknown[] }>("/api/simulate", {
      method: "POST",
      body: JSON.stringify({ count, attack_type: attackType ?? null }),
    }),

  simulateStart: (interval: number, attackType?: string) =>
    apiFetch<{ ok: boolean; started?: boolean; already_running?: boolean }>("/api/simulate/start", {
      method: "POST",
      body: JSON.stringify({ interval, attack_type: attackType ?? null }),
    }),

  simulateStop: () =>
    apiFetch<{ ok: boolean; stopped?: boolean }>("/api/simulate/stop", { method: "POST" }),

  simulateStatus: () =>
    apiFetch<{ running: boolean }>("/api/simulate/status"),

  getAttackTypes: () =>
    apiFetch<{ attack_types: { id: string; label: string }[] }>("/api/simulate/attack-types"),
};
