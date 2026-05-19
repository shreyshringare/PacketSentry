import { StatCards } from "../components/StatCards";
import { FlowTable } from "../components/FlowTable";
import { EnsemblePanel } from "../components/EnsemblePanel";
import { AlertFeed } from "../components/AlertFeed";
import { ThroughputChart } from "../components/ThroughputChart";
import { useAlertStore } from "../store/alertStore";
import { useCaptureStore } from "../store/captureStore";

export function Overview() {
  const selectedAlert = useAlertStore((s) => s.selectedAlert);
  const stats = useCaptureStore((s) => s.stats);

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <StatCards />
      <div className="px-3 pb-1">
        <ThroughputChart />
      </div>
      <div className="flex flex-1 overflow-hidden gap-3 px-3 pb-3">
        {/* Left: flow table + ensemble */}
        <div className="flex-1 flex flex-col gap-3 overflow-hidden min-w-0">
          <div className="bg-white rounded-lg border border-gray-200 flex-1 overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-100 text-xs font-semibold text-gray-600 uppercase tracking-wide">
              Active Flows
            </div>
            <div className="overflow-auto flex-1">
              <FlowTable />
            </div>
          </div>
          <EnsemblePanel scores={selectedAlert?.shap ? undefined : undefined} />
        </div>
        {/* Right: alert feed */}
        <div className="w-72 bg-white rounded-lg border border-gray-200 overflow-hidden">
          <AlertFeed />
        </div>
      </div>
    </div>
  );
}
