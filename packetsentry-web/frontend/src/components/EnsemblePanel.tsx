import { useCaptureStore } from "../store/captureStore";

const MODEL_CONFIG = [
  { key: "aho_corasick", label: "Aho-Corasick", color: "#7C3AED" },
  { key: "xgboost", label: "XGBoost (SHAP)", color: "#0891B2" },
  { key: "gnn_detector", label: "GNN (GraphSAGE)", color: "#EA580C" },
  { key: "transformer_ae", label: "Transformer AE", color: "#2563EB" },
  { key: "isolation_forest", label: "Isolation Forest", color: "#D97706" },
  { key: "zscore", label: "Z-Score", color: "#6B7280" },
  { key: "random_forest", label: "Random Forest", color: "#6B7280" },
];

// Default weights from EnsembleArbiter
const DEFAULT_WEIGHTS: Record<string, number> = {
  aho_corasick: 0.20,
  xgboost: 0.22,
  gnn_detector: 0.15,
  transformer_ae: 0.15,
  isolation_forest: 0.12,
  zscore: 0.08,
  random_forest: 0.08,
};

export function EnsemblePanel({ scores }: { scores?: Record<string, number> }) {
  const stats = useCaptureStore((s) => s.stats);
  const conf = stats.ensemble_conf;
  const confCls = conf >= 0.8 ? "text-red-600" : conf >= 0.5 ? "text-amber-500" : "text-green-600";

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-3">
      <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
        Ensemble Model Scores
      </div>
      <div className="space-y-1.5">
        {MODEL_CONFIG.map(({ key, label, color }) => {
          const score = scores?.[key] ?? 0;
          const weight = DEFAULT_WEIGHTS[key] ?? 0;
          return (
            <div key={key} className="flex items-center gap-2">
              <div className="text-[10px] text-gray-500 w-32 truncate">{label}</div>
              <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-300 ease-out"
                  style={{
                    width: `${score * 100}%`,
                    backgroundColor: color,
                  }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-600 w-8 text-right">
                {score.toFixed(2)}
              </div>
              <div className="text-[9px] text-gray-400 w-8 text-right">
                w={weight.toFixed(2)}
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-2 pt-2 border-t border-gray-100 flex justify-between items-center">
        <span className="text-[10px] text-gray-500">Weighted confidence</span>
        <span className={`text-sm font-bold ${confCls}`}>{conf.toFixed(3)}</span>
      </div>
    </div>
  );
}
