// packetsentry-web/frontend/src/mockData.ts
// Pre-recorded demo data — loads when backend is offline

import type { AlertEvent, Flow } from "./store/alertStore";
import type { PacketEvent, StatsUpdate } from "./store/captureStore";

const now = Math.floor(Date.now() / 1000);

export const MOCK_ALERTS: AlertEvent[] = [
  {
    id: "demo-001",
    rule: "PORT_SCAN_DETECTED",
    severity: "HIGH",
    confidence: 0.91,
    src_ip: "192.168.1.47",
    dst_ip: "10.0.0.1",
    port: 22,
    detectors: ["XGBoost", "GNN", "AhoCorasick"],
    shap: { packet_rate: 0.42, syn_ratio: 0.31, dst_port_entropy: 0.18, flow_duration: -0.08 },
    ts: now - 12,
  },
  {
    id: "demo-002",
    rule: "DNS_TUNNELING",
    severity: "CRITICAL",
    confidence: 0.97,
    src_ip: "172.16.5.23",
    dst_ip: "8.8.8.8",
    port: 53,
    detectors: ["XGBoost", "TransformerAE", "ZScore"],
    shap: { dns_query_length: 0.55, query_entropy: 0.38, subdomain_depth: 0.22, ttl_variance: 0.12 },
    ts: now - 38,
  },
  {
    id: "demo-003",
    rule: "BRUTE_FORCE_SSH",
    severity: "HIGH",
    confidence: 0.88,
    src_ip: "203.0.113.77",
    dst_ip: "10.0.0.5",
    port: 22,
    detectors: ["XGBoost", "IsolationForest"],
    shap: { failed_auth_rate: 0.61, connection_rate: 0.27, src_ip_reputation: 0.19, payload_size: -0.05 },
    ts: now - 74,
  },
  {
    id: "demo-004",
    rule: "SQL_INJECTION_ATTEMPT",
    severity: "CRITICAL",
    confidence: 0.99,
    src_ip: "198.51.100.14",
    dst_ip: "10.0.0.8",
    port: 3306,
    detectors: ["AhoCorasick", "XGBoost"],
    shap: { payload_signature: 0.72, dst_port: 0.18, connection_state: 0.11, bytes_out: -0.03 },
    ts: now - 120,
  },
  {
    id: "demo-005",
    rule: "DDOS_SYN_FLOOD",
    severity: "CRITICAL",
    confidence: 0.95,
    src_ip: "45.33.32.156",
    dst_ip: "10.0.0.1",
    port: 80,
    detectors: ["XGBoost", "GNN", "ZScore", "TransformerAE"],
    shap: { syn_rate: 0.58, unique_src_ips: 0.29, packet_size_variance: 0.13, ack_ratio: -0.11 },
    ts: now - 195,
  },
  {
    id: "demo-006",
    rule: "LATERAL_MOVEMENT",
    severity: "HIGH",
    confidence: 0.82,
    src_ip: "10.0.0.22",
    dst_ip: "10.0.0.45",
    port: 445,
    detectors: ["GNN", "TransformerAE"],
    shap: { internal_hop_count: 0.44, smb_command_diversity: 0.33, time_of_day: 0.21, bytes_transferred: 0.09 },
    ts: now - 310,
  },
  {
    id: "demo-007",
    rule: "DATA_EXFILTRATION",
    severity: "HIGH",
    confidence: 0.86,
    src_ip: "10.0.0.31",
    dst_ip: "185.220.101.45",
    port: 443,
    detectors: ["XGBoost", "TransformerAE", "IsolationForest"],
    shap: { upload_volume: 0.67, dst_geo_risk: 0.24, session_duration: 0.15, protocol_anomaly: 0.08 },
    ts: now - 480,
  },
  {
    id: "demo-008",
    rule: "ANOMALOUS_BEACON",
    severity: "MED",
    confidence: 0.74,
    src_ip: "10.0.0.15",
    dst_ip: "104.21.44.89",
    port: 8080,
    detectors: ["TransformerAE", "ZScore"],
    shap: { connection_periodicity: 0.51, jitter: -0.22, payload_entropy: 0.18, request_interval: 0.14 },
    ts: now - 650,
  },
  {
    id: "demo-009",
    rule: "TOR_EXIT_NODE",
    severity: "MED",
    confidence: 0.79,
    src_ip: "185.220.101.33",
    dst_ip: "10.0.0.9",
    port: 9001,
    detectors: ["AhoCorasick", "XGBoost"],
    shap: { known_tor_ip: 0.63, port_signature: 0.24, tls_fingerprint: 0.17, packet_timing: -0.06 },
    ts: now - 820,
  },
  {
    id: "demo-010",
    rule: "PORT_SCAN_DETECTED",
    severity: "LOW",
    confidence: 0.61,
    src_ip: "192.168.1.102",
    dst_ip: "192.168.1.1",
    port: 8443,
    detectors: ["IsolationForest"],
    shap: { dst_port_entropy: 0.38, scan_velocity: 0.29, rst_count: 0.15, flow_duration: -0.12 },
    ts: now - 1100,
  },
];

export const MOCK_FLOWS: Flow[] = [
  { src_ip: "192.168.1.47",   dst_ip: "10.0.0.1",        proto: "TCP", score: 0.91, severity: "HIGH",     detectors: ["XGBoost", "GNN"],            bytes: 14320 },
  { src_ip: "172.16.5.23",    dst_ip: "8.8.8.8",          proto: "UDP", score: 0.97, severity: "CRITICAL", detectors: ["XGBoost", "TransformerAE"],   bytes: 4210  },
  { src_ip: "203.0.113.77",   dst_ip: "10.0.0.5",        proto: "TCP", score: 0.88, severity: "HIGH",     detectors: ["XGBoost"],                    bytes: 8840  },
  { src_ip: "10.0.0.22",      dst_ip: "10.0.0.45",       proto: "TCP", score: 0.82, severity: "HIGH",     detectors: ["GNN", "TransformerAE"],       bytes: 55200 },
  { src_ip: "10.0.0.31",      dst_ip: "185.220.101.45",  proto: "TCP", score: 0.86, severity: "HIGH",     detectors: ["XGBoost", "IsolationForest"], bytes: 982400 },
  { src_ip: "10.0.0.15",      dst_ip: "104.21.44.89",    proto: "TCP", score: 0.74, severity: "MED",      detectors: ["TransformerAE"],              bytes: 3120  },
  { src_ip: "192.168.1.102",  dst_ip: "192.168.1.1",     proto: "TCP", score: 0.61, severity: "LOW",      detectors: ["IsolationForest"],            bytes: 1840  },
];

export const MOCK_PACKETS: PacketEvent[] = Array.from({ length: 40 }, (_, i) => {
  const protos = ["TCP", "UDP", "DNS", "TCP", "TCP"];
  const pairs: [string, string][] = [
    ["192.168.1.47", "10.0.0.1"],
    ["172.16.5.23", "8.8.8.8"],
    ["203.0.113.77", "10.0.0.5"],
    ["10.0.0.22", "10.0.0.45"],
    ["10.0.0.15", "104.21.44.89"],
  ];
  const [src, dst] = pairs[i % pairs.length];
  const flagged = i % 7 === 0 || i % 11 === 0;
  return {
    ts: now - (40 - i) * 3,
    src,
    dst,
    proto: protos[i % protos.length],
    length: 64 + Math.floor(Math.abs(Math.sin(i * 1.7)) * 1400),
    flags: i % 5 === 0 ? "SYN" : i % 3 === 0 ? "ACK" : "PSH+ACK",
    flow_score: flagged ? 0.7 + Math.abs(Math.sin(i)) * 0.29 : Math.abs(Math.sin(i)) * 0.35,
    flagged,
  };
});

export const MOCK_STATS: StatsUpdate = {
  pps: 847,
  flows: MOCK_FLOWS.length,
  ensemble_conf: 0.89,
  active_alerts: MOCK_ALERTS.filter((a) => a.severity === "CRITICAL" || a.severity === "HIGH").length,
};
