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

  const deterministicCount = alerts.filter((a) => a.rule === "Signature Match").length;
  const anomalyCount = alerts.filter((a) => a.rule !== "Signature Match").length;

  return (
    <div className="grid grid-cols-4 gap-3 p-3">
      <Card
        label="Active Flows"
        value={stats.flows.toLocaleString()}
        sub={`${stats.pps} pps throughput`}
        accent="green"
        icon={PixelBranch}
      />
      <Card
        label="Gate 1: Rules"
        value={deterministicCount}
        sub="Deterministic Blocks"
        accent={deterministicCount > 0 ? "red" : "green"}
        icon={PixelShield}
      />
      <Card
        label="Gate 2: ML Models"
        value={anomalyCount}
        sub="Probabilistic Anomalies"
        accent={anomalyCount > 0 ? "amber" : "green"}
        icon={PixelAlert}
      />
      <Card
        label="System Confidence"
        value={`${Math.round(stats.ensemble_conf * 100)}%`}
        sub={stats.ensemble_conf >= 0.5 ? "Anomalous threshold" : "Stable threshold"}
        accent={stats.ensemble_conf >= 0.8 ? "red" : stats.ensemble_conf >= 0.5 ? "amber" : "green"}
        icon={PixelPulse}
      />
    </div>
  );
}
