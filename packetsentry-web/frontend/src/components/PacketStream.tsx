import { useRef } from "react";
import { List } from "react-window";
import { useCaptureStore } from "../store/captureStore";

const ITEM_HEIGHT = 22;
const MAX_VISIBLE = 20;

interface RowDataProps {
  packets: any[];
}

function Row({ index, style, packets }: any) {
  const pkt = packets[index];
  if (!pkt) return null;
  const rowCls = pkt.flagged
    ? "text-red-500"
    : pkt.flow_score >= 0.5
    ? "text-amber-500"
    : "text-gray-400";

  return (
    <div
      style={style}
      className={`px-3 font-mono text-[11px] flex items-center gap-2 ${rowCls}`}
    >
      <span className="text-gray-500 w-16 shrink-0">
        {new Date(pkt.ts * 1000).toLocaleTimeString()}
      </span>
      <span className="w-32 truncate">{pkt.src}</span>
      <span className="text-gray-500">→</span>
      <span className="w-32 truncate">{pkt.dst}</span>
      <span className="w-10">{pkt.proto}</span>
      <span className="w-12 text-right">{pkt.length}B</span>
      {pkt.flags && (
        <span className="text-[10px] bg-[#00FF41] text-black font-bold px-1">
          {pkt.flags}
        </span>
      )}
    </div>
  );
}

export function PacketStream() {
  const packets = useCaptureStore((s) => s.packets);
  const listRef = useRef<any>(null);

  const height = Math.min(packets.length, MAX_VISIBLE) * ITEM_HEIGHT || ITEM_HEIGHT * 5;

  return (
    <div className="flex-1 min-h-0 bg-gray-900 border-2 border-black crt-scanlines p-2 overflow-hidden flex flex-col">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b-2 border-gray-700 text-[10px] font-bold text-[#00FF41] uppercase tracking-wider shrink-0">
        <span className="w-16">Time</span>
        <span className="w-32">Source</span>
        <span className="w-32">Destination</span>
        <span className="w-10">Proto</span>
        <span className="w-12 text-right">Length</span>
        <span>Flags</span>
      </div>
      <div className="flex-1 overflow-hidden min-h-0 mt-2">
        <List<RowDataProps>
          style={{ height }}
          rowCount={packets.length}
          rowHeight={ITEM_HEIGHT}
          rowComponent={Row}
          rowProps={{ packets }}
          listRef={listRef}
        />
      </div>
    </div>
  );
}
