import { useState } from "react";
import { StatCards } from "../components/StatCards";
import { FlowTable } from "../components/FlowTable";
import { EnsemblePanel } from "../components/EnsemblePanel";
import { AlertFeed } from "../components/AlertFeed";
import { ThroughputChart } from "../components/ThroughputChart";
import { useAlertStore } from "../store/alertStore";
import { api } from "../api/client";

const ATTACK_TYPES = [
  { id: "port_scan",    label: "Port Scan" },
  { id: "dos",          label: "DoS Flood" },
  { id: "sql_injection",label: "SQL Injection" },
  { id: "brute_force",  label: "Brute Force" },
  { id: "data_exfil",   label: "Data Exfil" },
];

export function Overview() {
  const selectedAlert = useAlertStore((s) => s.selectedAlert);
  const [simLoading, setSimLoading] = useState(false);
  const [simStatus, setSimStatus] = useState<string>("");
  const [selectedAttack, setSelectedAttack] = useState<string>("random");

  async function handleSimulate() {
    setSimLoading(true);
    setSimStatus("");
    try {
      const attackType = selectedAttack === "random" ? undefined : selectedAttack;
      const result = await api.simulateBurst(5, attackType);
      setSimStatus(`✓ ${result.generated} alerts injected`);
      setTimeout(() => setSimStatus(""), 4000);
    } catch {
      setSimStatus("✗ Backend offline");
      setTimeout(() => setSimStatus(""), 4000);
    } finally {
      setSimLoading(false);
    }
  }

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <StatCards />

      {/* ── Simulate bar ──────────────────────────────── */}
      <div className="px-3 py-1.5 flex items-center gap-2 border-b border-gray-200">
        <span className="font-mono text-[9px] text-gray-400 uppercase tracking-widest shrink-0">
          [SIM]
        </span>
        <select
          value={selectedAttack}
          onChange={(e) => setSelectedAttack(e.target.value)}
          className="border border-black font-mono text-[10px] px-2 py-0.5 bg-white uppercase tracking-wide focus:outline-none"
        >
          <option value="random">Random</option>
          {ATTACK_TYPES.map((a) => (
            <option key={a.id} value={a.id}>{a.label}</option>
          ))}
        </select>
        <button
          onClick={handleSimulate}
          disabled={simLoading}
          className="border-2 border-black bg-black text-[#00FF41] font-black text-[10px] uppercase tracking-widest px-3 py-0.5 hover:bg-[#00FF41] hover:text-black disabled:opacity-50 transition-colors duration-100"
        >
          {simLoading ? "..." : "Inject Attack"}
        </button>
        {simStatus && (
          <span className="font-mono text-[10px] text-gray-500">{simStatus}</span>
        )}
      </div>

      <div className="px-3 pb-1 pt-1">
        <ThroughputChart />
      </div>
      <div className="flex flex-1 overflow-hidden gap-3 px-3 pb-3">
        {/* Left: flow table + ensemble */}
        <div className="flex-1 flex flex-col gap-3 overflow-hidden min-w-0">
          <div className="bg-white border-2 border-black shadow-brutalist flex-1 overflow-hidden">
            <div className="px-3 py-2 border-b-2 border-black text-xs font-black text-gray-900 uppercase tracking-wide">
              Active Flows
            </div>
            <div className="overflow-auto flex-1">
              <FlowTable />
            </div>
          </div>
          <EnsemblePanel scores={selectedAlert?.shap ? undefined : undefined} />
        </div>
        {/* Right: alert feed */}
        <div className="w-72 bg-white border-2 border-black shadow-brutalist overflow-hidden">
          <AlertFeed />
        </div>
      </div>
    </div>
  );
}
