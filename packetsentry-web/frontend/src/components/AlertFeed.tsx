import { useAlertStore, type AlertEvent } from "../store/alertStore";
import { useUIStore } from "../store/uiStore";

const SEV_CLS: Record<string, string> = {
  CRITICAL: "border-l-red-500 bg-red-50",
  HIGH: "border-l-amber-500 bg-amber-50",
  MED: "border-l-blue-500 bg-blue-50",
  LOW: "border-l-gray-300 bg-white",
};

const BADGE_CLS: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-amber-500 text-black",
  MED: "bg-blue-600 text-white",
  LOW: "bg-gray-200 text-gray-700",
};

function AlertRow({ alert }: { alert: AlertEvent }) {
  const { setSelectedAlert } = useAlertStore();
  const { setScreen } = useUIStore();

  const topShap = Object.entries(alert.shap)
    .sort(([, a], [, b]) => Math.abs(b) - Math.abs(a))
    .slice(0, 3)
    .map(([k, v]) => `${k} ${v > 0 ? "+" : ""}${v.toFixed(2)}`)
    .join(" | ");

  return (
    <div
      className={`border-l-4 border-b-2 border-b-black px-3 py-2 cursor-pointer hover:bg-black hover:text-white transition-colors duration-100 ${
        SEV_CLS[alert.severity] ?? "bg-white border-l-gray-300"
      }`}
      onClick={() => {
        setSelectedAlert(alert);
        setScreen("alerts");
      }}
    >
      <div className="flex justify-between items-start">
        <div className="flex items-center gap-1.5">
          <span
            className={`text-[10px] px-1.5 py-0.5 rounded-none font-bold uppercase tracking-wide ${
              BADGE_CLS[alert.severity]
            }`}
          >
            {alert.severity}
          </span>
          <span className="text-xs font-bold text-gray-800">{alert.rule}</span>
        </div>
        <span className="text-[10px] text-gray-400 font-mono">
          {new Date(alert.ts * 1000).toLocaleTimeString()}
        </span>
      </div>
      <div className="text-[11px] font-mono text-gray-600 mt-0.5">
        {alert.src_ip} → {alert.dst_ip}:{alert.port}
      </div>
      <div className="text-[10px] text-gray-400 mt-0.5 font-mono">
        conf: <strong>{alert.confidence.toFixed(2)}</strong> | {alert.detectors.length}/7 models
      </div>
      {topShap && (
        <div className="text-[10px] text-gray-400 mt-0.5 italic">{topShap}</div>
      )}
    </div>
  );
}

export function AlertFeed() {
  const alerts = useAlertStore((s) => s.alerts);

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b-2 border-black bg-white">
        <span className="text-xs font-black text-gray-900 uppercase tracking-wide">
          Alert Feed
        </span>
        {alerts.length > 0 && (
          <span className="ml-2 text-[10px] bg-red-600 text-white px-1.5 py-0.5 rounded-none font-bold">
            {alerts.length}
          </span>
        )}
      </div>
      <div className="flex-1 overflow-y-auto">
        {alerts.length === 0 ? (
          <div className="p-6 text-center text-xs text-gray-500 font-mono terminal-cursor">
            &gt; Awaiting threats...
          </div>
        ) : (
          alerts.map((a) => <AlertRow key={a.id} alert={a} />)
        )}
      </div>
    </div>
  );
}
