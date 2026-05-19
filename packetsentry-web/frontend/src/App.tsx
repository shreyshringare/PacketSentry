import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TopNav } from "./components/TopNav";
import { Overview } from "./screens/Overview";
import { LiveCapture } from "./screens/LiveCapture";
import { AlertDetail } from "./screens/AlertDetail";
import { Settings } from "./screens/Settings";
import { useUIStore } from "./store/uiStore";
import { useWebSocket } from "./hooks/useWebSocket";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: true,
    },
  },
});

function AppContent() {
  useWebSocket();  // connect once at app root
  const activeScreen = useUIStore((s) => s.activeScreen);

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-gray-50">
      <TopNav />
      {activeScreen === "overview" && <Overview />}
      {activeScreen === "live" && <LiveCapture />}
      {activeScreen === "alerts" && <AlertDetail />}
      {activeScreen === "settings" && <Settings />}
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
