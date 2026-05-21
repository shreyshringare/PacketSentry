import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TopNav } from "./components/TopNav";
import { Footer } from "./components/Footer";
import { Overview } from "./screens/Overview";
import { LiveCapture } from "./screens/LiveCapture";
import { AlertDetail } from "./screens/AlertDetail";
import { Settings } from "./screens/Settings";
import { Landing } from "./screens/Landing";
import { Login } from "./screens/Login";
import { useUIStore } from "./store/uiStore";
import { useAuthStore } from "./store/authStore";
import { useAlertStore } from "./store/alertStore";
import { useCaptureStore } from "./store/captureStore";
import { useWebSocket } from "./hooks/useWebSocket";
import { api } from "./api/client";
import { MOCK_ALERTS, MOCK_FLOWS, MOCK_STATS } from "./mockData";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: true,
    },
  },
});

function useDemoAlerts() {
  const isDemo = useAuthStore((s) => s.isDemo);
  const addAlert = useAlertStore((s) => s.addAlert);
  const setFlows = useAlertStore((s) => s.setFlows);
  const updateStats = useCaptureStore((s) => s.updateStats);

  React.useEffect(() => {
    if (!isDemo) return;
    api.getAlerts().then((rows) => {
      // Map REST alert shape → AlertEvent shape (newest first)
      const alerts = (rows as any[]).reverse().map((r: any) => ({
        id: r.id ?? r.alert_id,
        rule: r.rule ?? "Unknown",
        severity: r.severity ?? "LOW",
        confidence: r.confidence ?? 0,
        src_ip: r.src_ip ?? "0.0.0.0",
        dst_ip: r.dst_ip ?? "0.0.0.0",
        port: r.dst_port ?? r.port ?? 0,
        detectors: r.detectors ?? [],
        shap: typeof r.shap_explanation === "string"
          ? JSON.parse(r.shap_explanation || "{}")
          : (r.shap_explanation ?? {}),
        ts: r.ts ?? Math.floor(new Date(r.timestamp ?? Date.now()).getTime() / 1000),
      }));
      alerts.forEach(addAlert);
    }).catch(() => {
      // Backend offline — load pre-recorded mock data so demo dashboard is populated
      MOCK_ALERTS.forEach(addAlert);
      setFlows(MOCK_FLOWS);
      updateStats(MOCK_STATS);
    });
  }, [isDemo]);
}

function Dashboard() {
  useWebSocket();
  useDemoAlerts();
  const activeScreen = useUIStore((s) => s.activeScreen);
  const isDemo = useAuthStore((s) => s.isDemo);

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-[#C0C0C0]">
      <TopNav />
      {isDemo && (
        <div className="bg-black text-[#00FF41] font-mono text-[10px] text-center py-0.5 tracking-widest shrink-0">
          [DEMO MODE] READ-ONLY // PRE-RECORDED DATA
        </div>
      )}
      {activeScreen === "overview" && <Overview />}
      {activeScreen === "live" && <LiveCapture />}
      {activeScreen === "alerts" && <AlertDetail />}
      {activeScreen === "settings" && <Settings />}
      <Footer variant="dashboard" />
    </div>
  );
}

function AppContent() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const hasHydrated = useAuthStore((s) => s._hasHydrated);
  const [view, setView] = React.useState<"landing" | "login">("landing");

  // Wait for persisted auth to rehydrate before deciding which screen to show.
  // Without this, returning admin users see a flash of landing page; with it,
  // fresh visitors always land on the landing page (not the dashboard).
  if (!hasHydrated) return null;

  if (isAuthenticated) return <Dashboard />;
  if (view === "login") return <Login onBack={() => setView("landing")} />;
  return <Landing onLogin={() => setView("login")} />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
