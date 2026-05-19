import { useAlertStore } from "../store/alertStore";

const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700",
  HIGH: "bg-amber-100 text-amber-700",
  MED: "bg-blue-100 text-blue-700",
  LOW: "bg-green-100 text-green-700",
};

function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 0.8 ? "bg-red-500" : score >= 0.5 ? "bg-amber-400" : "bg-green-400";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score * 100}%` }} />
      </div>
      <span
        className={`text-xs font-mono ${
          score >= 0.8 ? "text-red-600" : score >= 0.5 ? "text-amber-500" : "text-gray-500"
        }`}
      >
        {score.toFixed(2)}
      </span>
    </div>
  );
}

export function FlowTable() {
  const flows = useAlertStore((s) => s.flows);

  return (
    <div className="overflow-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-gray-50 border-b border-gray-200">
            {["Src IP", "Dst IP", "Proto", "Score", "Severity", "Detectors"].map((h) => (
              <th key={h} className="px-3 py-2 text-left text-gray-500 font-medium uppercase tracking-wide text-[10px]">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {flows.slice(0, 50).map((flow, i) => (
            <tr
              key={i}
              className="border-b border-gray-100 hover:bg-gray-50 cursor-pointer"
              onClick={() => {
                // Flow → AlertEvent stub click handler (Phase 3: full flow detail)
              }}
            >
              <td className="px-3 py-1.5 font-mono text-[11px]">{flow.src_ip}</td>
              <td className="px-3 py-1.5 font-mono text-[11px]">{flow.dst_ip}</td>
              <td className="px-3 py-1.5 text-gray-500">{flow.proto}</td>
              <td className="px-3 py-1.5"><ScoreBar score={flow.score} /></td>
              <td className="px-3 py-1.5">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${SEVERITY_CLS[flow.severity] ?? "bg-gray-100 text-gray-600"}`}>
                  {flow.severity}
                </span>
              </td>
              <td className="px-3 py-1.5 text-gray-400 text-[10px]">
                {flow.detectors.join(", ")}
              </td>
            </tr>
          ))}
          {flows.length === 0 && (
            <tr>
              <td colSpan={6} className="px-3 py-6 text-center text-gray-400 text-xs">
                No active flows — start capture to see live data
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
