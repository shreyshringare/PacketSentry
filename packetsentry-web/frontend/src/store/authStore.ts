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
      name: "packetsentry-auth-v2",
      // Demo sessions are ephemeral — only persist admin tokens across page loads
      partialize: (s: AuthState) =>
        s.role === "admin"
          ? { token: s.token, role: s.role }
          : { token: null, role: null },
      onRehydrateStorage: () => (state) => {
        if (state?.token && state?.role === "admin") {
          state.isAuthenticated = true;
          state.isDemo = false;
        }
      },
    }
  )
);
