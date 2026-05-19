import { ShieldCheck } from "lucide-react";
import { useCaptureStore } from "../store/captureStore";
import { useUIStore, type Screen } from "../store/uiStore";

const TABS: { id: Screen; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "live", label: "Live Capture" },
  { id: "alerts", label: "Alerts" },
  { id: "settings", label: "Settings" },
];

export function TopNav() {
  const { activeScreen, setScreen } = useUIStore();
  const running = useCaptureStore((s) => s.running);

  return (
    <header className="h-11 border-b border-gray-200 bg-white flex items-center justify-between px-4 shrink-0">
      <div className="flex items-center gap-2">
        <ShieldCheck size={18} className="text-blue-600" />
        <span className="font-semibold text-sm tracking-wide">PacketSentry</span>
      </div>

      <nav className="flex items-center gap-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setScreen(tab.id)}
            className={[
              "px-3 py-1 text-xs font-medium rounded-md transition-colors",
              activeScreen === tab.id
                ? "bg-gray-100 text-gray-900 border-b-2 border-blue-600"
                : "text-gray-500 hover:text-gray-800 hover:bg-gray-50",
            ].join(" ")}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="flex items-center gap-1.5 text-xs">
        <span
          className={[
            "inline-block w-2 h-2 rounded-full",
            running ? "bg-green-500 animate-pulse" : "bg-gray-400",
          ].join(" ")}
        />
        <span className="text-gray-500">{running ? "LIVE" : "idle"}</span>
      </div>
    </header>
  );
}
