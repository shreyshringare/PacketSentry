import { useState } from "react";
import { Play, Square } from "lucide-react";
import { useCaptureStore } from "../store/captureStore";
import { PacketStream } from "../components/PacketStream";
import { PolarRadar } from "../components/PolarRadar";
import { ThroughputChart } from "../components/ThroughputChart";
import { useAlertStore } from "../store/alertStore";
import { api } from "../api/client";

const INTERFACES = ["eth0", "eth1", "wlan0", "lo"];
const PROTO_FILTERS = ["TCP", "UDP", "DNS", "HTTP"];

export function LiveCapture() {
  const { running, setRunning, interface: iface, setInterface, bpfFilter, setBpfFilter } = useCaptureStore();
  const [activeProtos, setActiveProtos] = useState<Set<string>>(new Set());
  const selectedAlert = useAlertStore((s) => s.selectedAlert);
  const stats = useCaptureStore((s) => s.stats);

  const toggleProto = (p: string) => {
    setActiveProtos((prev) => {
      const next = new Set(prev);
      next.has(p) ? next.delete(p) : next.add(p);
      return next;
    });
  };

  const handleStart = async () => {
    try {
      await api.startCapture(iface, bpfFilter);
      setRunning(true);
    } catch (e) {
      console.error("Start capture failed:", e);
    }
  };

  const handleStop = async () => {
    try {
      await api.stopCapture();
      setRunning(false);
    } catch (e) {
      console.error("Stop capture failed:", e);
    }
  };

  return (
    <div className="flex flex-col flex-1 overflow-hidden p-3 gap-3">
      {/* Toolbar */}
      <div className="bg-white rounded-lg border border-gray-200 p-3 flex items-center gap-3 flex-wrap">
        <select
          className="text-xs border border-gray-200 rounded px-2 py-1.5 bg-white"
          value={iface}
          onChange={(e) => setInterface(e.target.value)}
          disabled={running}
        >
          {INTERFACES.map((i) => <option key={i}>{i}</option>)}
        </select>

        <div className="flex gap-1">
          {PROTO_FILTERS.map((p) => (
            <button
              key={p}
              onClick={() => toggleProto(p)}
              className={`px-2 py-1 text-[10px] rounded font-medium transition-colors ${
                activeProtos.has(p)
                  ? "bg-green-100 text-green-700"
                  : "bg-gray-100 text-gray-500 hover:bg-gray-200"
              }`}
            >
              {p}
            </button>
          ))}
        </div>

        <input
          className="flex-1 min-w-32 text-xs border border-gray-200 rounded px-2 py-1.5 font-mono"
          placeholder="BPF filter: port 80 or port 443"
          value={bpfFilter}
          onChange={(e) => setBpfFilter(e.target.value)}
          disabled={running}
        />

        {!running ? (
          <button
            onClick={handleStart}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 text-white text-xs rounded font-medium hover:bg-green-700"
          >
            <Play size={12} /> Start
          </button>
        ) : (
          <button
            onClick={handleStop}
            className="flex items-center gap-1.5 px-3 py-1.5 border border-red-400 text-red-600 text-xs rounded font-medium hover:bg-red-50"
          >
            <Square size={12} /> Stop
          </button>
        )}

        {running && (
          <span className="text-xs text-gray-500 font-mono">{stats.pps} pps</span>
        )}
      </div>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden gap-3">
        {/* Left: packet stream */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          <PacketStream />
          <ThroughputChart />
        </div>
        {/* Right: polar radar */}
        <div className="w-64 bg-white rounded-lg border border-gray-200 p-3 flex flex-col items-center">
          <div className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-2 self-start">
            Threat Radar
          </div>
          <PolarRadar scores={selectedAlert?.shap ?? {}} />
          <div className="text-[10px] text-gray-400 mt-2 text-center">
            7 detectors | updates every 2s
          </div>
        </div>
      </div>
    </div>
  );
}
