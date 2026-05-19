import { useEffect, useRef } from "react";
import { useCaptureStore } from "../store/captureStore";
import { useAlertStore } from "../store/alertStore";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws";
const MAX_RETRIES = 10;

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const updateStats = useCaptureStore((s) => s.updateStats);
  const addPacket = useCaptureStore((s) => s.addPacket);
  const addAlert = useAlertStore((s) => s.addAlert);
  const setFlows = useAlertStore((s) => s.setFlows);

  useEffect(() => {
    let reconnectTimeout: ReturnType<typeof setTimeout>;

    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        retriesRef.current = 0;
        // Send ping every 30s to keep alive
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send("ping");
        }, 30_000);
        (ws as any)._pingInterval = pingInterval;
      };

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          switch (msg.type) {
            case "packet_event":
              addPacket(msg);
              break;
            case "alert_event":
              addAlert(msg);
              break;
            case "stats_update":
              updateStats(msg);
              break;
            case "flow_update":
              setFlows(msg.flows ?? []);
              break;
          }
        } catch {
          // malformed message — ignore
        }
      };

      ws.onclose = () => {
        clearInterval((ws as any)._pingInterval);
        if (retriesRef.current < MAX_RETRIES) {
          const delay = Math.min(2000 * (retriesRef.current + 1), 30_000);
          retriesRef.current++;
          reconnectTimeout = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => ws.close();
    }

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      wsRef.current?.close();
    };
  }, []);
}
