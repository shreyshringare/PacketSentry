# PacketSentry — Architecture

## Detection Pipeline

Every packet flows through a two-gate architecture before an alert is raised.

```
Raw Packet
    │
    ▼
scapy_to_parsed()          # Scapy → ParsedPacket (protocol-agnostic)
    │
    ▼
FlowTracker                # Groups packets into bidirectional flows
    │                        Timeout = 60 s. Returns None until flow completes.
    │ (on flow completion)
    ▼
┌─────────────────────────────────────────┐
│  GATE 1 — Deterministic (Aho-Corasick)  │
│                                         │
│  Scans raw payload bytes against 97     │
│  OWASP signatures (SQLi, XSS, RCE,      │
│  Log4Shell, Shellshock, DNS tunnel…).   │
│                                         │
│  Match → confidence = 1.0, skip Gate 2  │
│  No match → fall through                │
└─────────────────────────────────────────┘
    │ (no signature match)
    ▼
FeatureExtractor           # Flow → 23 statistical features
FeaturePreprocessor        # Online StandardScaler (fits on first 50 flows)
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  GATE 2 — Probabilistic Ensemble (7 models)                  │
│                                                              │
│  XGBoost          supervised, CICIDS-2017 trained            │
│  RandomForest     baseline comparison, same training data    │
│  IsolationForest  unsupervised, self-trains on live baseline │
│  TransformerAE    multi-head self-attention, temporal        │
│  GNN (GraphSAGE)  topology-aware, from scratch               │
│  ZScore           Welford online stats, zero memory          │
│  AhoCorasick      0.0 here (already handled in Gate 1)       │
│                                                              │
│  Each model: score(features) → float [0.0, 1.0]             │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
EnsembleArbiter            # Confidence-weighted vote
    │
    ▼
AlertEngine                # Dedup on (src_ip, dst_ip, dst_port)
                             DuckDB store + ChromaDB vector index
```

---

## Why Two Gates?

**Gate 1 is O(n) and certain.** Aho-Corasick matches all 97 patterns in a single pass over the payload. If `SELECT * FROM users WHERE '1'='1` appears verbatim, no statistical model is needed — it's an attack. Gate 1 fires with `confidence = 1.0` and skips the entire ML stack, keeping latency sub-millisecond for signature matches.

**Gate 2 handles what signatures can't.** Statistical anomalies — a port scan with no payload, a DDoS flood, a slow-drip data exfiltration — produce no matching bytes. Gate 2 sees 23 flow-level features (packet rate, byte ratio, flag distribution) and runs them through seven models simultaneously.

---

## Why Seven Models?

Each model catches a different attack class:

| Model | What it catches best |
|-------|---------------------|
| XGBoost | Known attack patterns from labeled CICIDS-2017 data |
| RandomForest | Same, used as calibration baseline for ensemble weight tuning |
| IsolationForest | Volumetric anomalies — traffic outside the learned baseline |
| TransformerAE | Temporal sequences — repeated probes, slow scans, C2 beaconing |
| GNN (GraphSAGE) | Topology attacks — port scan fan-out, DDoS fan-in, invisible to per-flow models |
| ZScore | Sudden statistical spikes on individual features |
| AhoCorasick | Byte-level signatures (handled in Gate 1; score always 0.0 in Gate 2) |

A single model optimised for port scans will miss SQL injection. An ensemble that agrees across multiple independent methods produces far fewer false positives than any individual model.

---

## Adaptive Ensemble Weights

The `EnsembleArbiter` starts all detectors at equal weight. Weights update on every `feedback()` call:

**False positive reported:**
```
target = initial_weight × (1 − fp_rate)
weight = max(_MIN_WEIGHT, target)
```
A detector that frequently fires on benign traffic has its weight reduced proportionally to its false-positive rate.

**True positive confirmed:**
```
weight = min(initial_weight, weight + RECOVERY_RATE × (initial_weight − weight))
```
`RECOVERY_RATE = 0.05`. Each confirmed true positive nudges the weight 5% of the way back toward its initial value. Without recovery, a detector that had a bad day (e.g. IsolationForest during a traffic pattern change) would be permanently crippled even after it stabilises. Recovery ensures the ensemble self-corrects over time.

**Why not just use fp_rate directly?**
`weight = 1 − fp_rate` has no memory of improvement. If fp_rate drops from 0.40 to 0.05, the weight jumps immediately to 0.95 — overshooting. The nudge-based recovery is smoother and rewards sustained good performance rather than reacting to single-sample noise.

---

## Severity Scale

Single source of truth: `packetsentry/alerts/severity.py`

| Confidence | Severity |
|-----------|----------|
| ≥ 0.90 | CRITICAL |
| ≥ 0.75 | HIGH |
| ≥ 0.60 | MED |
| < 0.60 | LOW |

Used by: `AlertEngine` (runtime), `evaluate_all.py` (offline eval), `cli.py` (display), `backend/main.py` and `backend/routers/simulate.py` (web API).

---

## SHAP Explainability

Every Gate 2 alert includes a SHAP feature attribution vector from XGBoost's `TreeExplainer`. The 23 features are ranked by absolute SHAP value and stored alongside the alert in DuckDB.

```
packetsentry explain <alert_id>

Feature          SHAP Value  Direction
bytes_per_second  +0.3821    ↑ attack
packet_count      +0.2104    ↑ attack
same_srv_rate     −0.1837    ↓ normal
dst_port          +0.0923    ↑ attack
```

This means every alert answers *why* it fired, not just *that* it fired. No black-box decisions.

---

## Data Flow: PCAP Replay vs Live Capture

Both paths converge at `DetectionPipeline.ingest(ParsedPacket)`:

```
Live capture:   libpcap → Scapy → scapy_to_parsed() → ingest()
PCAP replay:    PcapReader / sniff(offline, bpf_filter) → scapy_to_parsed() → ingest()
```

The pipeline has no knowledge of how the packet arrived. This means the same model weights, same feature extraction, and same alert logic apply to both live and replay modes.
