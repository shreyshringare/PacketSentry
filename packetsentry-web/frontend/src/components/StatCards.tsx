import { useCaptureStore } from "../store/captureStore";
import { useAlertStore } from "../store/alertStore";

function Card({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: "red" | "amber" | "green";
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
    <div className="bg-white rounded-lg border border-gray-200 px-4 py-3">
      <div className="text-xs text-gray-500 uppercase tracking-wide">{label}</div>
      <div className={`text-2xl font-bold mt-0.5 ${valCls}`}>{value}</div>
      {sub && <div className="text-xs text-gray-400 mt-0.5">{sub}</div>}
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
        accent={stats.pps > 5000 ? "red" : undefined}
      />
      <Card
        label="Active Alerts"
        value={stats.active_alerts}
        sub={critCount > 0 ? `${critCount} critical` : "none critical"}
        accent={stats.active_alerts > 0 ? "red" : "green"}
      />
      <Card
        label="Ensemble Confidence"
        value={`${confPercent}%`}
        sub={stats.ensemble_conf >= 0.5 ? "above threshold" : "below threshold"}
        accent={confAccent}
      />
      <Card
        label="Flows Tracked"
        value={stats.flows.toLocaleString()}
        sub="60s window"
        accent="green"
      />
    </div>
  );
}
