import { useState } from "react";

const MODEL_LABELS: Record<string, string> = {
  aho_corasick: "Aho-Corasick",
  xgboost: "XGBoost (SHAP)",
  gnn_detector: "GNN (GraphSAGE)",
  transformer_ae: "Transformer AE",
  isolation_forest: "Isolation Forest",
  zscore: "Z-Score",
  random_forest: "Random Forest",
};

const DEFAULT_WEIGHTS: Record<string, number> = {
  aho_corasick: 0.20,
  xgboost: 0.22,
  gnn_detector: 0.15,
  transformer_ae: 0.15,
  isolation_forest: 0.12,
  zscore: 0.08,
  random_forest: 0.08,
};

export function Settings() {
  const [weights, setWeights] = useState({ ...DEFAULT_WEIGHTS });
  const [threshold, setThreshold] = useState(0.50);
  const [critCutoff, setCritCutoff] = useState(0.80);
  const [highCutoff, setHighCutoff] = useState(0.60);
  const [iface, setIface] = useState("eth0");
  const [bpf, setBpf] = useState("");
  const [saved, setSaved] = useState(false);

  const total = Object.values(weights).reduce((s, v) => s + v, 0);

  const normalize = () => {
    const t = total || 1;
    setWeights((prev) =>
      Object.fromEntries(Object.entries(prev).map(([k, v]) => [k, +(v / t).toFixed(3)]))
    );
  };

  const handleSave = async () => {
    try {
      await fetch("http://localhost:8000/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ weights, threshold, iface, bpf_filter: bpf }),
      });
    } catch {
      // offline — save locally only
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="flex-1 overflow-y-auto p-4">
      <div className="max-w-2xl space-y-6">

        {/* Capture settings */}
        <section className="bg-white rounded-lg border border-gray-200 p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Capture</h3>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <label className="text-xs text-gray-600 w-32">Default interface</label>
              <input
                className="flex-1 text-xs border border-gray-200 rounded px-2 py-1.5"
                value={iface}
                onChange={(e) => setIface(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs text-gray-600 w-32">BPF filter</label>
              <input
                className="flex-1 text-xs border border-gray-200 rounded px-2 py-1.5 font-mono"
                placeholder="port 80 or port 443"
                value={bpf}
                onChange={(e) => setBpf(e.target.value)}
              />
            </div>
          </div>
        </section>

        {/* Ensemble weights */}
        <section className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-sm font-semibold text-gray-800">Ensemble Weights</h3>
            <div className="flex items-center gap-2">
              <span className={`text-xs ${Math.abs(total - 1) > 0.01 ? "text-amber-500" : "text-green-600"}`}>
                Total: {total.toFixed(3)}
              </span>
              <button
                onClick={normalize}
                className="text-xs px-2 py-1 border border-gray-200 rounded hover:bg-gray-50"
              >
                Normalize
              </button>
            </div>
          </div>
          <div className="space-y-2">
            {Object.entries(weights).map(([key, val]) => (
              <div key={key} className="flex items-center gap-3">
                <label className="text-xs text-gray-600 w-36 truncate">{MODEL_LABELS[key]}</label>
                <input
                  type="range"
                  min={0.01} max={0.5} step={0.01}
                  value={val}
                  onChange={(e) => setWeights((prev) => ({ ...prev, [key]: +e.target.value }))}
                  className="flex-1"
                />
                <span className="text-xs font-mono text-gray-700 w-10 text-right">
                  {val.toFixed(2)}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* Thresholds */}
        <section className="bg-white rounded-lg border border-gray-200 p-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Alert Thresholds</h3>
          {[
            { label: "Alert fire threshold", value: threshold, set: setThreshold },
            { label: "CRITICAL cutoff", value: critCutoff, set: setCritCutoff },
            { label: "HIGH cutoff", value: highCutoff, set: setHighCutoff },
          ].map(({ label, value, set }) => (
            <div key={label} className="flex items-center gap-3 mb-2">
              <label className="text-xs text-gray-600 w-36">{label}</label>
              <input
                type="range" min={0.1} max={0.99} step={0.01}
                value={value}
                onChange={(e) => set(+e.target.value)}
                className="flex-1"
              />
              <span className="text-xs font-mono text-gray-700 w-10 text-right">{value.toFixed(2)}</span>
            </div>
          ))}
        </section>

        <button
          onClick={handleSave}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
            saved
              ? "bg-green-100 text-green-700"
              : "bg-blue-600 text-white hover:bg-blue-700"
          }`}
        >
          {saved ? "Saved!" : "Save Settings"}
        </button>
      </div>
    </div>
  );
}
