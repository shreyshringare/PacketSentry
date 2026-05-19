import React from "react";
import { useCaptureStore } from "../store/captureStore";
import { useUIStore, type Screen } from "../store/uiStore";
import { PixelShield, PixelConsole, PixelAlert, PixelSettings } from "./PixelIcons";

const TABS: { id: Screen; label: string; icon: React.ComponentType<any> }[] = [
  { id: "overview", label: "Overview", icon: PixelShield },
  { id: "live", label: "Live Capture", icon: PixelConsole },
  { id: "alerts", label: "Alerts", icon: PixelAlert },
  { id: "settings", label: "Settings", icon: PixelSettings },
];

export function TopNav() {
  const { activeScreen, setScreen } = useUIStore();
  const running = useCaptureStore((s) => s.running);

  return (
    <header className="h-11 border-b border-gray-200 bg-white flex items-center justify-between px-4 shrink-0">
      <div className="flex items-center gap-2">
        <PixelShield size={18} className="text-blue-600" />
        <span className="font-semibold text-sm tracking-wide">PacketSentry</span>
      </div>

      <nav className="flex items-center gap-1">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeScreen === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setScreen(tab.id)}
              className={[
                "px-3 py-1 text-xs font-medium rounded-md transition-all flex items-center gap-1.5",
                isActive
                  ? "bg-gray-100 text-gray-900 shadow-sm"
                  : "text-gray-500 hover:text-gray-800 hover:bg-gray-50",
              ].join(" ")}
            >
              <Icon size={14} className={isActive ? "text-blue-600" : "text-gray-400"} />
              {tab.label}
            </button>
          );
        })}
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
