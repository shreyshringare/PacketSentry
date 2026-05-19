import { X, Copy, Check } from "lucide-react";
import { useState } from "react";
import { useAlertStore } from "../store/alertStore";
import { ShapWaterfall } from "../components/ShapWaterfall";
import { EnsemblePanel } from "../components/EnsemblePanel";
import { SimilarAlerts } from "../components/SimilarAlerts";
import { api } from "../api/client";

export function AlertDetail() {
  const { selectedAlert, setSelectedAlert } = useAlertStore();
  const [fpDone, setFpDone] = useState(false);

  if (!selectedAlert) {
    return (
      <div className="flex-1 flex items-center justify-center text-sm text-gray-400">
        Select an alert to view details
      </div>
    );
  }

  const handleFP = async () => {
    try {
      await api.markFalsePositive(selectedAlert.id, selectedAlert.detectors);
      setFpDone(true);
      setTimeout(() => setFpDone(false), 3000);
    } catch (e) {
      console.error("FP marking failed:", e);
    }
  };

  const copyIP = (text: string) => navigator.clipboard.writeText(text);

  const SEV_CLS: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-700",
    HIGH: "bg-amber-100 text-amber-700",
    MED: "bg-blue-100 text-blue-700",
    LOW: "bg-gray-100 text-gray-600",
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 px-4 py-3 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_CLS[selectedAlert.severity]}`}>
              {selectedAlert.severity}
            </span>
            <h2 className="text-sm font-semibold text-gray-900">{selectedAlert.rule}</h2>
          </div>
          <div className="flex items-center gap-2 mt-1 font-mono text-xs text-gray-500">
            <span>{selectedAlert.src_ip}</span>
            <span>→</span>
            <span>{selectedAlert.dst_ip}:{selectedAlert.port}</span>
            <button onClick={() => copyIP(selectedAlert.src_ip)} className="hover:text-blue-500">
              <Copy size={10} />
            </button>
          </div>
          <div className="text-xs text-gray-400 mt-0.5">
            conf: <strong>{selectedAlert.confidence.toFixed(3)}</strong> |{" "}
            {selectedAlert.detectors.length}/7 models |{" "}
            {new Date(selectedAlert.ts * 1000).toLocaleString()}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleFP}
            disabled={fpDone}
            className={`text-xs px-3 py-1.5 rounded border transition-all ${
              fpDone
                ? "border-green-300 text-green-600 bg-green-50"
                : "border-gray-200 text-gray-600 hover:border-red-300 hover:text-red-600"
            }`}
          >
            {fpDone ? <span className="flex items-center gap-1"><Check size={10} /> Marked</span> : "Mark as False Positive"}
          </button>
          <button
            onClick={() => setSelectedAlert(null)}
            className="text-gray-400 hover:text-gray-600"
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="flex flex-1 overflow-hidden gap-4 p-4">
        {/* Left: SHAP waterfall */}
        <div className="flex-1 bg-white rounded-lg border border-gray-200 p-4">
          <ShapWaterfall shap={selectedAlert.shap} />
        </div>
        {/* Right: ensemble + similar */}
        <div className="w-72 flex flex-col gap-4">
          <EnsemblePanel scores={selectedAlert.shap} />
          <div className="bg-white rounded-lg border border-gray-200 p-3">
            <SimilarAlerts alertId={selectedAlert.id} />
          </div>
        </div>
      </div>
    </div>
  );
}
