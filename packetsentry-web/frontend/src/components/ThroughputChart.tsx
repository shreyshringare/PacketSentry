import { useEffect, useState } from "react";
import { useCaptureStore } from "../store/captureStore";
import {
  ComposedChart,
  Line,
  Area,
  ResponsiveContainer,
  YAxis,
  CartesianGrid,
  ReferenceLine,
  Tooltip,
} from "recharts";

const MAX_POINTS = 60;

function emptyHistory() {
  return Array.from({ length: MAX_POINTS }, () => ({ pps: 0, conf: 0 }));
}

export function ThroughputChart() {
  const pps = useCaptureStore((s) => s.stats.pps);
  const conf = useCaptureStore((s) => s.stats.ensemble_conf); // 0.0–1.0
  const [data, setData] = useState(emptyHistory);

  useEffect(() => {
    setData((prev) => [
      ...prev.slice(-(MAX_POINTS - 1)),
      { pps, conf: conf * 100 }, // conf as 0–100 so both series share y-axis scale
    ]);
  }, [pps, conf]);

  const peakPps = Math.max(...data.map((d) => d.pps), 1);
  const latestConf = (data[data.length - 1]?.conf ?? 0).toFixed(0);
  const latestPps = (data[data.length - 1]?.pps ?? 0).toFixed(0);

  return (
    <div className="w-full bg-black border-2 border-black" style={{ height: 80 }}>
      {/* label row */}
      <div className="flex items-center gap-4 px-2 pt-0.5">
        <span className="font-mono text-[8px] uppercase tracking-widest text-gray-500">
          30s window
        </span>
        <span className="flex items-center gap-1 font-mono text-[9px]">
          <span style={{ color: "#378ADD" }}>■</span>
          <span className="text-gray-400">PPS</span>
          <span style={{ color: "#378ADD" }} className="font-black">{latestPps}</span>
        </span>
        <span className="flex items-center gap-1 font-mono text-[9px]">
          <span style={{ color: "#00FF41" }}>■</span>
          <span className="text-gray-400">THREAT%</span>
          <span style={{ color: "#00FF41" }} className="font-black">{latestConf}%</span>
        </span>
      </div>

      {/* chart */}
      <div style={{ height: 52 }}>
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 2, right: 4, left: 0, bottom: 0 }}>
            <CartesianGrid
              strokeDasharray="2 4"
              stroke="#222"
              vertical={false}
            />
            <YAxis
              domain={[0, Math.max(peakPps * 1.2, 10)]}
              hide
            />
            {/* reference line at y=0 so empty chart isn't invisible */}
            <ReferenceLine y={0} stroke="#333" strokeWidth={1} />
            <Tooltip
              contentStyle={{
                background: "#111",
                border: "1px solid #333",
                borderRadius: 0,
                fontFamily: "monospace",
                fontSize: 10,
                color: "#ccc",
              }}
              formatter={(value: number, name: string) =>
                name === "conf"
                  ? [`${value.toFixed(1)}%`, "Threat conf"]
                  : [`${value.toFixed(0)}/s`, "PPS"]
              }
              labelFormatter={() => ""}
              isAnimationActive={false}
            />
            {/* filled area for threat confidence */}
            <Area
              type="monotone"
              dataKey="conf"
              stroke="#00FF41"
              strokeWidth={1}
              fill="#00FF41"
              fillOpacity={0.08}
              dot={false}
              isAnimationActive={false}
            />
            {/* line for PPS */}
            <Line
              type="monotone"
              dataKey="pps"
              stroke="#378ADD"
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
