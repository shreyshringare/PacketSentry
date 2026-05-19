import React from "react";
import { useCaptureStore } from "../store/captureStore";
import { useAlertStore } from "../store/alertStore";
import { PixelShield, PixelAlert, PixelPulse, PixelBranch } from "./PixelIcons";

function Card({
  label,
  value,
  sub,
  accent,
  icon: Icon,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: "red" | "amber" | "green";
  icon?: React.ComponentType<any>;
}) {
  const valCls =
    accent === "red"
      ? "text-red-600"
      : accent === "amber"
      ? "text-amber-500"
      : accent === "green"
      ? "text-green-600"
      : "text-gray-900";

  return (
    <div className="bg-white rounded-none border-2 border-black px-4 py-3 flex items-center justify-between shadow-brutalist">
      <div>
        <div className="text-xs text-gray-500 uppercase tracking-wide font-bold">{label}</div>
        <div className={`text-3xl font-black mt-0.5 ${valCls}`}>{value}</div>
        {sub && <div className="text-xs text-gray-400 mt-0.5 font-mono">{sub}</div>}
      </div>
      {Icon && (
        <div className="p-2 bg-black rounded-none shrink-0">
          <Icon size={24} className="text-white" />
        </div>
      )}
    </div>
  );
}

export function StatCards() {
  const stats = useCaptureStore((s) => s.stats);
  const alerts = useAlertStore((s) => s.alerts);

  const critCount = alerts.filter((a) => a.severity === "CRITICAL").length;
  const confPercent = Math.round(stats.ensemble_conf * 100);
  const confAccent =
    stats.ensemble_conf >= 0.8
      ? "red"
      : stats.ensemble_conf >= 0.5
      ? "amber"
      : "green";

  return (
    <div className="grid grid-cols-4 gap-3 p-3">
      <Card
        label="Packets / min"
        value={(stats.pps * 60).toLocaleString()}
        sub={`${stats.pps} pps`}
        accent={stats.pps > 5000 ? "red" : "green"}
        icon={PixelPulse}
      />
      <Card
        label="Active Alerts"
        value={stats.active_alerts}
        sub={critCount > 0 ? `${critCount} critical` : "none critical"}
        accent={stats.active_alerts > 0 ? "red" : "green"}
        icon={PixelAlert}
      />
      <Card
        label="Ensemble Confidence"
        value={`${confPercent}%`}
        sub={stats.ensemble_conf >= 0.5 ? "above threshold" : "below threshold"}
        accent={confAccent}
        icon={PixelShield}
      />
      <Card
        label="Flows Tracked"
        value={stats.flows.toLocaleString()}
        sub="60s window"
        accent="green"
        icon={PixelBranch}
      />
    </div>
  );
}
