import { create } from "zustand";

export type Screen = "overview" | "live" | "alerts" | "settings";

interface UIState {
  activeScreen: Screen;
  sidebarOpen: boolean;
  setScreen: (s: Screen) => void;
  setSidebarOpen: (v: boolean) => void;
}

export const useUIStore = create<UIState>((set) => ({
  activeScreen: "overview",
  sidebarOpen: false,
  setScreen: (activeScreen) => set({ activeScreen }),
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
}));
