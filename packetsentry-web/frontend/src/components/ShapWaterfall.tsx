import { useEffect, useState } from "react";

interface ShapFeature {
  name: string;
  value: number;
}

function ShapBar({ name, value, delay }: ShapFeature & { delay: number }) {
  const [width, setWidth] = useState(0);
  const maxWidth = 120;

  useEffect(() => {
    const t = setTimeout(() => setWidth(Math.abs(value) * maxWidth), delay);
    return () => clearTimeout(t);
  }, [value, delay]);

  const isPositive = value >= 0;
  const color = isPositive ? "#2563EB" : "#DC2626";
  const label = `${isPositive ? "+" : ""}${value.toFixed(3)}`;

  return (
    <div className="flex items-center gap-2 py-0.5">
      <div className="text-[10px] font-mono text-gray-600 w-32 text-right truncate">{name}</div>
      <div className="flex items-center gap-1">
        {!isPositive && (
          <div
            className="h-3 rounded-sm transition-all duration-500 ease-out"
            style={{ width, backgroundColor: color, transitionDelay: `${delay}ms` }}
          />
        )}
        <div className="w-px h-5 bg-gray-300" />
        {isPositive && (
          <div
            className="h-3 rounded-sm transition-all duration-500 ease-out"
            style={{ width, backgroundColor: color, transitionDelay: `${delay}ms` }}
          />
        )}
      </div>
      <div
        className="text-[10px] font-mono"
        style={{ color }}
      >
        {label}
      </div>
    </div>
  );
}

export function ShapWaterfall({ shap }: { shap: Record<string, number> }) {
  const features: ShapFeature[] = Object.entries(shap)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 8);

  if (features.length === 0) {
    return (
      <div className="text-xs text-gray-400 py-4 text-center">
        No SHAP data available
      </div>
    );
  }

  return (
    <div>
      <div className="text-xs font-semibold text-gray-700 mb-2">
        Why did the ensemble fire?
      </div>
      <div className="text-[10px] text-gray-400 mb-3">
        ← normal &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; attack →
      </div>
      {features.map((f, i) => (
        <ShapBar key={f.name} {...f} delay={i * 30} />
      ))}
    </div>
  );
}
