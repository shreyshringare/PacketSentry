import { useRef } from "react";
import { FixedSizeList, type ListChildComponentProps } from "react-window";
import { useCaptureStore, type PacketEvent } from "../store/captureStore";

const ITEM_HEIGHT = 22;
const MAX_VISIBLE = 20;

function Row({ index, style, data }: ListChildComponentProps<PacketEvent[]>) {
  const pkt = data[index];
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
      {pkt.flags && <span className="text-[10px] bg-gray-100 px-1 rounded">{pkt.flags}</span>}
    </div>
  );
}

export function PacketStream() {
  const packets = useCaptureStore((s) => s.packets);
  const listRef = useRef<FixedSizeList>(null);

  const height = Math.min(packets.length, MAX_VISIBLE) * ITEM_HEIGHT || ITEM_HEIGHT * 5;

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden bg-gray-900">
      <div className="bg-gray-800 px-3 py-1.5 text-[10px] text-gray-400 uppercase tracking-wide">
        Packet Stream — last {packets.length} packets
      </div>
      {packets.length === 0 ? (
        <div className="px-3 py-4 text-[11px] text-gray-500 font-mono">
          Waiting for packets…
        </div>
      ) : (
        <FixedSizeList
          ref={listRef}
          height={height}
          itemCount={packets.length}
          itemSize={ITEM_HEIGHT}
          itemData={packets}
          width="100%"
        >
          {Row}
        </FixedSizeList>
      )}
    </div>
  );
}
