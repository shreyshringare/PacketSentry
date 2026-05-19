import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

interface SimilarAlert {
  alert_id: string;
  similarity: number;
  rule: string;
  severity: string;
  src_ip: string;
  timestamp: string;
}

export function SimilarAlerts({ alertId }: { alertId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["similar", alertId],
    queryFn: () => api.getSimilar(alertId, 3),
    staleTime: 60_000,
  });

  const items = (data?.similar_alerts ?? []) as SimilarAlert[];

  if (isLoading) {
    return <div className="text-xs text-gray-400 py-2">Loading similar alerts…</div>;
  }

  if (items.length === 0) {
    return (
      <div className="text-xs text-gray-400 py-2">
        No similar alerts in ChromaDB
      </div>
    );
  }

  return (
    <div>
      <div className="text-xs font-semibold text-gray-700 mb-2">Similar Past Alerts</div>
      <div className="grid grid-cols-3 gap-2">
        {items.map((item, i) => (
          <div key={i} className="border border-gray-200 rounded-lg p-2 text-xs">
            <div
              className="h-1 rounded-full bg-blue-500 mb-2"
              style={{ width: `${Math.round(item.similarity * 100)}%` }}
            />
            <div className="font-medium text-gray-800 text-[11px]">{item.rule ?? "Unknown"}</div>
            <div className="text-gray-400 text-[10px] mt-0.5">
              {Math.round((item.similarity ?? 0) * 100)}% similar
            </div>
            <div className="font-mono text-[10px] text-gray-500 mt-0.5">
              {item.src_ip}
            </div>
            <div className="text-[10px] text-gray-400 mt-0.5">
              {item.timestamp ? new Date(item.timestamp).toLocaleDateString() : "—"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
