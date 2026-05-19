// packetsentry-web/frontend/src/store/authStore.ts
import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthState {
  token: string | null;
  role: "admin" | "demo" | null;
  isAuthenticated: boolean;
  isDemo: boolean;
  login: (token: string, role: "admin" | "demo") => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      role: null,
      isAuthenticated: false,
      isDemo: false,
      login: (token, role) =>
        set({ token, role, isAuthenticated: true, isDemo: role === "demo" }),
      logout: () =>
        set({ token: null, role: null, isAuthenticated: false, isDemo: false }),
    }),
    {
      name: "packetsentry-auth",
      // Only persist token + role across page refreshes
      partialize: (s: AuthState) => ({ token: s.token, role: s.role }),
      onRehydrateStorage: () => (state) => {
        // Recompute derived booleans after rehydration
        if (state?.token && state?.role) {
          state.isAuthenticated = true;
          state.isDemo = state.role === "demo";
        }
      },
    }
  )
);
