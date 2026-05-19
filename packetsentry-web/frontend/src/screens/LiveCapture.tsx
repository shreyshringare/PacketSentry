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
  const { running, setRunning, interface: iface, setInterface, bpfFilter, setBpfFilter } =
    useCaptureStore();
  const [activeProtos, setActiveProtos] = useState<Set<string>>(new Set());
  const [dropdownOpen, setDropdownOpen] = useState(false);
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
      <div className="bg-white border-2 border-black p-3 flex items-center gap-3 flex-wrap">
        {/* Custom interface dropdown */}
        <div className="relative">
          <button
            className="text-xs border-2 border-black px-2 py-1.5 bg-white font-mono flex items-center gap-1 hover:bg-black hover:text-white transition-colors duration-100 disabled:opacity-50"
            onClick={() => !running && setDropdownOpen((o) => !o)}
            disabled={running}
          >
            {iface} <span className="text-[10px]">▼</span>
          </button>
          {dropdownOpen && (
            <div className="absolute top-full left-0 z-50 border-2 border-black bg-white shadow-brutalist">
              {INTERFACES.map((i) => (
                <div
                  key={i}
                  onClick={() => {
                    setInterface(i);
                    setDropdownOpen(false);
                  }}
                  className="px-3 py-1.5 text-xs font-mono cursor-pointer hover:bg-black hover:text-white"
                >
                  {i}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Protocol filter toggles */}
        <div className="flex gap-1">
          {PROTO_FILTERS.map((p) => (
            <button
              key={p}
              onClick={() => toggleProto(p)}
              className={`px-2 py-1 text-[10px] rounded-none font-bold uppercase tracking-wide border-2 transition-colors duration-100 ${
                activeProtos.has(p)
                  ? "bg-black text-[#00FF41] border-black"
                  : "bg-white text-gray-700 border-black hover:bg-black hover:text-white"
              }`}
            >
              {p}
            </button>
          ))}
        </div>

        {/* Terminal BPF prompt */}
        <div className="flex-1 min-w-32 flex items-center border-2 border-black bg-black px-2 py-1.5">
          <span className="text-[#00FF41] font-mono text-xs shrink-0 mr-1 select-none">
            root@packetsentry:~$
          </span>
          <input
            className="flex-1 bg-transparent text-[#00FF41] font-mono text-xs outline-none placeholder-gray-600"
            placeholder="port 80 or port 443"
            value={bpfFilter}
            onChange={(e) => setBpfFilter(e.target.value)}
            disabled={running}
          />
        </div>

        {!running ? (
          <button
            onClick={handleStart}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-black text-[#00FF41] border-2 border-black rounded-none font-bold uppercase tracking-wide text-xs hover:bg-[#00FF41] hover:text-black transition-colors duration-100"
          >
            <Play size={12} /> Start
          </button>
        ) : (
          <button
            onClick={handleStop}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white text-red-600 border-2 border-red-600 rounded-none font-bold uppercase tracking-wide text-xs hover:bg-red-600 hover:text-white transition-colors duration-100"
          >
            <Square size={12} /> Stop
          </button>
        )}

        {running && (
          <span className="text-xs text-[#00FF41] font-mono font-bold">{stats.pps} pps</span>
        )}
      </div>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden gap-3">
        {/* Left: packet stream + throughput */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          <PacketStream />
          <ThroughputChart />
        </div>
        {/* Right: polar radar */}
        <div className="w-64 bg-white border-2 border-black shadow-brutalist p-3 flex flex-col items-center">
          <div className="text-xs font-black text-gray-900 uppercase tracking-wide mb-2 self-start border-b-2 border-black w-full pb-1">
            Threat Radar
          </div>
          <PolarRadar scores={selectedAlert?.shap ?? {}} />
          <div className="text-[10px] text-gray-400 mt-2 text-center font-mono">
            7 detectors | updates every 2s
          </div>
        </div>
      </div>
    </div>
  );
}
