import { create } from "zustand";

export interface PacketEvent {
  ts: number;
  src: string;
  dst: string;
  proto: string;
  length: number;
  flags: string;
  flow_score: number;
  flagged: boolean;
}

export interface StatsUpdate {
  pps: number;
  flows: number;
  ensemble_conf: number;
  active_alerts: number;
}

interface CaptureState {
  running: boolean;
  interface: string;
  bpfFilter: string;
  stats: StatsUpdate;
  packets: PacketEvent[];  // last 500
  setRunning: (v: boolean) => void;
  setInterface: (v: string) => void;
  setBpfFilter: (v: string) => void;
  updateStats: (s: StatsUpdate) => void;
  addPacket: (p: PacketEvent) => void;
  clearPackets: () => void;
}

export const useCaptureStore = create<CaptureState>((set) => ({
  running: false,
  interface: "eth0",
  bpfFilter: "",
  stats: { pps: 0, flows: 0, ensemble_conf: 0, active_alerts: 0 },
  packets: [],
  setRunning: (running) => set({ running }),
  setInterface: (i) => set({ interface: i }),
  setBpfFilter: (f) => set({ bpfFilter: f }),
  updateStats: (stats) => set({ stats }),
  addPacket: (p) =>
    set((s) => ({
      packets: [...s.packets.slice(-499), p],  // keep last 500
    })),
  clearPackets: () => set({ packets: [] }),
}));
