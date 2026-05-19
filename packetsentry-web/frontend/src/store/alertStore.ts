import { create } from "zustand";

export interface AlertEvent {
  id: string;
  rule: string;
  severity: "CRITICAL" | "HIGH" | "MED" | "LOW";
  confidence: number;
  src_ip: string;
  dst_ip: string;
  port: number;
  detectors: string[];
  shap: Record<string, number>;
  ts: number;
}

export interface Flow {
  src_ip: string;
  dst_ip: string;
  proto: string;
  score: number;
  severity: string;
  detectors: string[];
  bytes: number;
}

interface AlertState {
  alerts: AlertEvent[];
  selectedAlert: AlertEvent | null;
  activeFilter: string | null;
  flows: Flow[];
  setSelectedAlert: (a: AlertEvent | null) => void;
  addAlert: (a: AlertEvent) => void;
  setActiveFilter: (f: string | null) => void;
  setFlows: (f: Flow[]) => void;
}

export const useAlertStore = create<AlertState>((set) => ({
  alerts: [],
  selectedAlert: null,
  activeFilter: null,
  flows: [],
  setSelectedAlert: (a) => set({ selectedAlert: a }),
  addAlert: (a) =>
    set((s) => ({
      alerts: [a, ...s.alerts].slice(0, 500),  // newest first, cap 500
    })),
  setActiveFilter: (f) => set({ activeFilter: f }),
  setFlows: (flows) => set({ flows }),
}));
