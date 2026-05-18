# 🛡️ PacketSentry

**AI-Powered Network Intrusion Detection System — Built From Scratch**

A production-grade NIDS featuring a 7-model ML ensemble, real-time packet capture, SHAP-explainable alerts, and a Textual terminal dashboard. Every core algorithm (Aho-Corasick, GraphSAGE GNN) is implemented from scratch — zero black-box dependencies.

[![Tests](https://img.shields.io/badge/tests-241%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.12+-blue)]()
[![Models](https://img.shields.io/badge/ensemble-7%20models-orange)]()

---

## Architecture

```
Live Traffic / PCAP File
        ↓
  Scapy Capture → Flow Tracker → 23-Feature Extractor
        ↓
  ┌─────────────────────────────────────────────────────┐
  │            7-Model Detection Ensemble               │
  │                                                     │
  │  Aho-Corasick ──── XGBoost+SHAP ──── Random Forest │
  │  (signatures)      (supervised)       (baseline)    │
  │                                                     │
  │  Isolation Forest ── Transformer AE ── GNN ── ZScore│
  │  (unsupervised)     (temporal)     (topology) (stats)│
  └──────────────────────┬──────────────────────────────┘
                         ↓
              Ensemble Arbiter (weighted vote)
                         ↓
         ┌───────────────┴───────────────┐
    DuckDB Store                   ChromaDB Memory
    (alert history)                (attack fingerprints)
                         ↓
              Textual TUI Dashboard
```

---

## 7-Model Ensemble

| Model | Weight | Type | What It Catches | From Scratch? |
|-------|--------|------|-----------------|---------------|
| **Aho-Corasick** | 0.20 | Signature | SQLi, XSS, path traversal — known CVE patterns | ✅ Yes |
| **XGBoost** | 0.22 | Supervised | Learned attack features (NSL-KDD trained, 97% precision) | — |
| **Random Forest** | 0.08 | Supervised | Baseline comparison model | — |
| **Isolation Forest** | 0.12 | Unsupervised | Statistical outliers from your network's baseline | — |
| **Transformer AE** | 0.15 | Temporal | Slow port scans, C2 beaconing, DDoS ramp-ups | — |
| **GNN (GraphSAGE)** | 0.15 | Topology | DDoS fan-out, port scan star patterns, C2 infrastructure | ✅ Yes |
| **Z-Score** | 0.08 | Statistical | Per-feature Welford online anomaly detection | — |

Every alert includes **SHAP feature attribution** — no black-box decisions.

---

## Key Features

### 🔬 From-Scratch Algorithms
- **Aho-Corasick**: Trie + BFS failure function — O(n) multi-pattern matching regardless of signature count
- **GraphSAGE GNN**: Message passing via pure matrix ops — no PyTorch Geometric dependency. Models traffic as a dynamic graph (IPs as nodes, flows as edges)

### 🧠 Self-Training Detectors
- Isolation Forest, Transformer AE, and GNN all **self-train** during a warmup period — no labeled data required for anomaly detection
- The ensemble's FP feedback loop **self-calibrates** detector weights over time

### 🔍 Explainable AI
- **SHAP TreeExplainer** on every XGBoost alert
- Top-5 contributing features shown per alert (e.g., "dst_bytes ↑0.42, flag_syn ↑0.31")
- GDPR "right to explanation" compliant

### 💾 Dual Storage Architecture
- **DuckDB**: Fast analytical queries — "show all HIGH alerts from 192.168.x.x in the last hour"
- **ChromaDB**: Vector similarity — "have we seen an attack that looks like this before?"

### 📊 Real-Time Dashboard
- Textual TUI with live packet rate, flow count, and alert panel
- Severity-coded alerts (🔴 CRITICAL → ⚪ LOW) with SHAP explanations

---

## Quick Start

### Prerequisites
- Python 3.12+
- **Windows**: [Npcap](https://npcap.com) for live capture (not needed for PCAP replay)
- **Linux**: `sudo` or `CAP_NET_RAW` capability for live capture

### Install

```bash
git clone https://github.com/yourusername/PacketSentry.git
cd PacketSentry
pip install -e .
```

### Run Tests

```bash
python -m pytest tests/ -q
# 241 passed ✅
```

### Usage

```bash
# Replay a PCAP file (no admin required)
packetsentry replay attack.pcap --speed 0.0

# Live capture with TUI dashboard (requires Npcap/admin)
packetsentry live --interface "Wi-Fi"

# View alert history
packetsentry alerts --last 50

# Benchmark Aho-Corasick vs regex
packetsentry bench --patterns 1000 --text-size 10MB
```

### Train XGBoost on NSL-KDD

```bash
# Download NSL-KDD dataset to data/nslkdd/
# (KDDTrain+.txt and KDDTest+.txt)
python scripts/train_xgboost.py --dataset data/nslkdd/ --output models/
```

---

## Project Structure

```
packetsentry/
├── capture/
│   ├── pipeline.py          # End-to-end orchestrator
│   ├── live.py              # Scapy sniff loop
│   └── replay.py            # PCAP replay with speed control
├── detection/
│   ├── aho_corasick.py      # FROM SCRATCH — Trie + BFS failure links
│   ├── xgboost_detector.py  # Primary classifier + SHAP
│   ├── random_forest.py     # Baseline comparison
│   ├── transformer_ae.py    # Temporal anomaly (self-attention)
│   ├── gnn_detector.py      # FROM SCRATCH — GraphSAGE topology detector
│   ├── isolation_forest.py  # Unsupervised, self-trains
│   ├── zscore.py            # Welford online z-score
│   ├── ensemble.py          # 7-model weighted arbiter + FP feedback
│   └── explainer.py         # SHAP TreeExplainer wrapper
├── features/
│   ├── flow_tracker.py      # Bidirectional flow grouping
│   ├── extractor.py         # 23 NSL-KDD aligned features
│   └── preprocessor.py      # StandardScaler + persistence
├── storage/
│   ├── embedding.py         # 64-dim Transformer hidden state
│   └── vector_store.py      # ChromaDB cosine similarity
├── alerts/
│   ├── engine.py            # Deduplication + severity + routing
│   └── store.py             # DuckDB persistence
├── tui/
│   └── dashboard.py         # Textual real-time TUI
├── dissector/               # Protocol parsers (Ethernet/IP/TCP/UDP/DNS)
└── cli.py                   # Typer CLI entrypoint
```

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Capture | Scapy | Python-native pcap, cross-platform |
| Signatures | Aho-Corasick (scratch) | O(n) multi-pattern — 1 or 10,000 patterns, same speed |
| ML Primary | XGBoost + SHAP | Industry standard for tabular + explainability |
| Temporal | Transformer AE (PyTorch) | Self-attention captures long-range dependencies |
| Topology | GraphSAGE GNN (scratch) | E-GraphSAGE-inspired, catches DDoS/scan patterns |
| Unsupervised | Isolation Forest | Self-trains on your network's baseline |
| Vector Memory | ChromaDB | Cosine similarity over 64-dim attack fingerprints |
| Alert Store | DuckDB | In-process OLAP — 10x faster than SQLite for analytics |
| Dashboard | Textual | Rich terminal UI with reactive updates |
| CLI | Typer | Type-hint driven, auto-generated help |
| Training | Optuna + SMOTE | Bayesian HPO + class imbalance handling |

---

## Test Suite

```
Phase 1 — Scaffold + Aho-Corasick ........... 73 tests ✅
Phase 2 — Dissectors + Features ............. 64 tests ✅
Phase 3 — ML Ensemble (XGB/RF/IF/ZS) ....... 55 tests ✅
Phase 4 — Transformer AE + GNN + Storage .... 42 tests ✅
Phase 5 — Pipeline + Capture ................ 7 tests  ✅
─────────────────────────────────────────────────────────
Total                                        241 tests ✅
```

---

## Research References

| Paper | Year | Relevance |
|-------|------|-----------|
| E-GraphSAGE (Lo et al.) | 2022 | Edge-centric GNN for flow-based NIDS — inspired our GNN |
| DIGNN-A (Liu & Guo) | 2025 | Dynamic graph + multi-head attention, 99.96% on UNSW-NB15 |
| E-GraphSAGE++ | 2024 | Improved edge features + scalability for real-time |
| GConvTrans | 2024 | Hybrid GNN+Transformer — validates our dual approach |

---

## License

MIT
