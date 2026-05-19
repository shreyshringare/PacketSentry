import { useEffect, useState } from "react";
import { useCaptureStore } from "../store/captureStore";
import { LineChart, Line, ResponsiveContainer, YAxis } from "recharts";

const MAX_POINTS = 60;  // 60 seconds of data

export function ThroughputChart() {
  const pps = useCaptureStore((s) => s.stats.pps);
  const [data, setData] = useState<{ v: number }[]>(
    Array.from({ length: MAX_POINTS }, () => ({ v: 0 }))
  );

  useEffect(() => {
    setData((prev) => {
      const next = [...prev.slice(-(MAX_POINTS - 1)), { v: pps }];
      return next;
    });
  }, [pps]);

  return (
    <div className="h-14 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <YAxis domain={[0, "auto"]} hide />
          <Line
            type="monotone"
            dataKey="v"
            stroke="#378ADD"
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
