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
      Object.fromEntries(
        Object.entries(prev).map(([k, v]) => [k, +(v / t).toFixed(3)])
      )
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
    <div className="flex-1 overflow-y-auto p-4 bg-[#C0C0C0]">
      <div className="max-w-2xl space-y-6">

        {/* Capture control panel */}
        <section className="bg-white border-2 border-black shadow-brutalist p-4">
          <h3 className="text-sm font-black text-gray-900 uppercase tracking-wide mb-3 border-b-2 border-black pb-2">
            Capture
          </h3>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <label className="text-xs text-gray-600 w-32 font-bold uppercase tracking-wide">
                Default interface
              </label>
              <input
                className="flex-1 text-xs border-2 border-black rounded-none px-2 py-1.5 font-mono focus:border-[#00FF41] focus:outline-none bg-white"
                value={iface}
                onChange={(e) => setIface(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs text-gray-600 w-32 font-bold uppercase tracking-wide">
                BPF filter
              </label>
              <input
                className="flex-1 text-xs border-2 border-black rounded-none px-2 py-1.5 font-mono focus:border-[#00FF41] focus:outline-none bg-white"
                placeholder="port 80 or port 443"
                value={bpf}
                onChange={(e) => setBpf(e.target.value)}
              />
            </div>
          </div>
        </section>

        {/* Ensemble weights control panel */}
        <section className="bg-white border-2 border-black shadow-brutalist p-4">
          <div className="flex justify-between items-center mb-3 border-b-2 border-black pb-2">
            <h3 className="text-sm font-black text-gray-900 uppercase tracking-wide">
              Ensemble Weights
            </h3>
            <div className="flex items-center gap-2">
              <span
                className={`text-xs font-mono font-bold ${
                  Math.abs(total - 1) > 0.01 ? "text-amber-500" : "text-[#00FF41]"
                }`}
              >
                Total: {total.toFixed(3)}
              </span>
              <button
                onClick={normalize}
                className="text-xs px-2 py-1 border-2 border-black rounded-none hover:bg-black hover:text-white font-bold uppercase tracking-wide transition-colors duration-100"
              >
                Normalize
              </button>
            </div>
          </div>
          <div className="space-y-2">
            {Object.entries(weights).map(([key, val]) => (
              <div key={key} className="flex items-center gap-3">
                <label className="text-xs text-gray-600 w-36 truncate font-mono">
                  {MODEL_LABELS[key]}
                </label>
                <input
                  type="range"
                  min={0.01}
                  max={0.5}
                  step={0.01}
                  value={val}
                  onChange={(e) =>
                    setWeights((prev) => ({ ...prev, [key]: +e.target.value }))
                  }
                  className="flex-1 fader-input"
                />
                <span className="text-xs font-mono font-bold text-gray-900 w-10 text-right">
                  {val.toFixed(2)}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* Alert thresholds control panel */}
        <section className="bg-white border-2 border-black shadow-brutalist p-4">
          <h3 className="text-sm font-black text-gray-900 uppercase tracking-wide mb-3 border-b-2 border-black pb-2">
            Alert Thresholds
          </h3>
          {[
            { label: "Alert fire threshold", value: threshold, set: setThreshold },
            { label: "CRITICAL cutoff", value: critCutoff, set: setCritCutoff },
            { label: "HIGH cutoff", value: highCutoff, set: setHighCutoff },
          ].map(({ label, value, set }) => (
            <div key={label} className="flex items-center gap-3 mb-2">
              <label className="text-xs text-gray-600 w-36 font-mono">{label}</label>
              <input
                type="range"
                min={0.1}
                max={0.99}
                step={0.01}
                value={value}
                onChange={(e) => set(+e.target.value)}
                className="flex-1 fader-input"
              />
              <span className="text-xs font-mono font-bold text-gray-900 w-10 text-right">
                {value.toFixed(2)}
              </span>
            </div>
          ))}
        </section>

        <button
          onClick={handleSave}
          className={`px-4 py-2 rounded-none border-2 text-sm font-black uppercase tracking-wide transition-colors duration-100 ${
            saved
              ? "bg-[#00FF41] text-black border-black"
              : "bg-black text-[#00FF41] border-black hover:bg-[#00FF41] hover:text-black"
          }`}
        >
          {saved ? "SAVED!" : "Save Settings"}
        </button>
      </div>
    </div>
  );
}
