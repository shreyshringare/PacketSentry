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
    <header className="h-11 border-b-2 border-black bg-white flex items-center justify-between px-4 shrink-0">
      <div className="flex items-center gap-2">
        <PixelShield size={18} className="text-gray-900" />
        <span className="font-bold text-sm tracking-wide">PacketSentry</span>
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
                "px-3 py-1 text-xs font-bold rounded-none transition-colors duration-100 flex items-center gap-1.5 uppercase tracking-wide border-2",
                isActive
                  ? "bg-black text-[#00FF41] border-black"
                  : "bg-transparent text-gray-600 border-transparent hover:border-black hover:text-black hover:bg-white",
              ].join(" ")}
            >
              <Icon size={14} className={isActive ? "text-[#00FF41]" : "text-gray-400"} />
              {tab.label}
            </button>
          );
        })}
      </nav>

      <div className="flex items-center gap-1.5 text-xs font-mono font-bold">
        <span
          className={[
            "inline-block w-2 h-2 rounded-full",
            running ? "bg-[#00FF41] animate-pulse" : "bg-gray-400",
          ].join(" ")}
        />
        <span className={running ? "text-[#00FF41]" : "text-gray-500"}>
          {running ? "LIVE" : "idle"}
        </span>
      </div>
    </header>
  );
}
