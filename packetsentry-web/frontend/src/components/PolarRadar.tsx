import { useMemo } from "react";

const MODELS = [
  "Aho-Corasick",
  "XGBoost",
  "GNN",
  "Transformer AE",
  "Isolation Forest",
  "Z-Score",
  "Random Forest",
];

const CX = 120;
const CY = 120;
const R = 90;
const N = MODELS.length;

function polarToXY(angle: number, r: number): [number, number] {
  return [
    CX + r * Math.cos(angle - Math.PI / 2),
    CY + r * Math.sin(angle - Math.PI / 2),
  ];
}

function buildPath(scores: number[]): string {
  return scores
    .map((score, i) => {
      const angle = (2 * Math.PI * i) / N;
      const [x, y] = polarToXY(angle, score * R);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ") + " Z";
}

export function PolarRadar({ scores }: { scores: Record<string, number> }) {
  const modelKeys = [
    "aho_corasick", "xgboost", "gnn_detector",
    "transformer_ae", "isolation_forest", "zscore", "random_forest",
  ];

  const scoreArr = modelKeys.map((k) => scores[k] ?? 0);
  const baselineArr = Array(N).fill(0.05);

  const gridLines = [0.25, 0.5, 0.75, 1.0];

  const axes = useMemo(
    () =>
      MODELS.map((label, i) => {
        const angle = (2 * Math.PI * i) / N;
        const [x1, y1] = polarToXY(angle, R);
        const [lx, ly] = polarToXY(angle, R + 18);
        return { label, x1, y1, lx, ly };
      }),
    []
  );

  return (
    <svg width={240} height={240} viewBox={`0 0 240 240`} className="overflow-visible">
      {/* Grid circles */}
      {gridLines.map((r) => (
        <circle
          key={r}
          cx={CX} cy={CY} r={r * R}
          fill="none" stroke="#e5e7eb" strokeWidth={0.8}
        />
      ))}

      {/* Axis lines */}
      {axes.map(({ x1, y1 }, i) => (
        <line key={i} x1={CX} y1={CY} x2={x1} y2={y1} stroke="#d1d5db" strokeWidth={0.8} />
      ))}

      {/* Baseline polygon (teal, small) */}
      <path
        d={buildPath(baselineArr)}
        fill="rgba(20,184,166,0.15)"
        stroke="#14B8A6"
        strokeWidth={1}
      />

      {/* Alert polygon (purple) */}
      <path
        d={buildPath(scoreArr)}
        fill="rgba(124,58,237,0.2)"
        stroke="#7C3AED"
        strokeWidth={1.5}
        style={{ transition: "d 300ms ease" }}
      />

      {/* Labels */}
      {axes.map(({ label, lx, ly }, i) => (
        <text
          key={i}
          x={lx} y={ly}
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize={8}
          fill="#6b7280"
        >
          {label}
        </text>
      ))}
    </svg>
  );
}
