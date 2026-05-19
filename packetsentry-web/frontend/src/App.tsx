import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TopNav } from "./components/TopNav";
import { Overview } from "./screens/Overview";
import { LiveCapture } from "./screens/LiveCapture";
import { AlertDetail } from "./screens/AlertDetail";
import { Settings } from "./screens/Settings";
import { Landing } from "./screens/Landing";
import { Login } from "./screens/Login";
import { useUIStore } from "./store/uiStore";
import { useAuthStore } from "./store/authStore";
import { useWebSocket } from "./hooks/useWebSocket";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: true,
    },
  },
});

function Dashboard() {
  useWebSocket();
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
    </div>
  );
}

function AppContent() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const token = useAuthStore((s) => s.token);

  // No token at all → landing page
  if (!token) return <Landing />;
  // Token exists but not yet validated → show login
  if (!isAuthenticated) return <Login />;
  // Authenticated (admin or demo) → dashboard
  return <Dashboard />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
