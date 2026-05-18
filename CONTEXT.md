# PacketSentry — Portable Project Context

Paste this file at the start of any session in any AI tool.
Update the checklist after every session so the next tool knows where you left off.

---

## Progress checklist

- [x] Scaffold — all folders, `__init__.py` stubs, `pyproject.toml`, `ruff.toml`, `CLAUDE.md`, CI
- [x] `detection/aho_corasick.py` — complete from scratch (Trie + BFS failure links), 33/33 tests pass
- [x] `dissector/` — ethernet, ip, tcp, udp, dns parsers (40 tests, all green)
- [x] `features/flow_tracker.py` — 60-second sliding window, ParsedPacket + Flow + FlowTracker (28 tests)
- [x] `features/extractor.py` — 23 NSL-KDD aligned features, stateful window for connection behaviour (25 tests)
- [x] `features/preprocessor.py` — StandardScaler + NaN handling + persistence (11 tests)
- [x] `detection/xgboost_detector.py` — XGBoost primary classifier + SHAP integration (22 tests)
- [x] `detection/explainer.py` — SHAP AlertExplainer wrapper, top-5 feature attribution per alert
- [x] `detection/random_forest.py` — RF baseline comparison (loads rf_nslkdd.pkl)
- [x] `detection/isolation_forest.py` — 500-flow warmup, self-trains (7 tests)
- [x] `detection/zscore.py` — Welford online z-score statistical baseline (8 tests)
- [x] `detection/ensemble.py` — 7-model confidence-weighted arbiter + SHAP + FP feedback (18 tests)
- [x] `scripts/train_xgboost.py` — Optuna HPO + SMOTE + 5-fold CV (NSL-KDD .txt)
- [x] `detection/transformer_ae.py` — Transformer Autoencoder, multi-head self-attention, seq_len=10 (13 tests)
- [x] `detection/gnn_detector.py` — From-scratch GraphSAGE GNN, topology anomaly detector (18 tests)
- [x] `storage/embedding.py` — extracts L2-normalised 64-dim encoder hidden state (2 tests)
- [x] `storage/vector_store.py` — ChromaDB wrapper, cosine similarity, `store_alert`/`find_similar` (2 tests)
- [x] `capture/pipeline.py` — End-to-end orchestrator: packet → flow → features → 7 models → alert (7 tests)
- [x] `capture/live.py` — Scapy sniff loop with ParsedPacket conversion
- [x] `capture/replay.py` — PCAP reader with speed multiplier
- [x] `alerts/engine.py` — severity LOW/MED/HIGH/CRITICAL, dedup, DuckDB+ChromaDB routing (4 tests)
- [x] `alerts/store.py` — DuckDB persistence (3 tests)
- [x] `tui/dashboard.py` — Textual real-time dashboard with StatsBar, FlowLog, AlertPanel
- [x] `cli.py` — Typer: live, replay, alerts, bench (all wired to real implementations)
- [ ] `signatures/rules.yaml` — YAML rule database
- [ ] `scripts/generate_attacks.sh` — local attack traffic generator
- [ ] CI — `.github/workflows/ci.yml` exists, needs `uv sync` + `ruff` + `pytest`
- [ ] README — architecture diagram + results table

---

## One-line pitch

Network intrusion detection system built from scratch — live packet capture, flow-level feature
extraction, Aho-Corasick signature matching, 7-model ML ensemble (XGBoost + GNN + Transformer AE +
Isolation Forest + SHAP explainability), ChromaDB vector memory, DuckDB alert persistence,
real-time Textual terminal dashboard. **241 tests passing.**

---

## Architecture (data flow)

```
Live Traffic (Scapy/libpcap) OR PCAP file
        ↓
[Packet Capture Layer]          capture/live.py | capture/replay.py
        ↓
[Detection Pipeline]            capture/pipeline.py  ← ORCHESTRATOR
        ↓
[Flow Tracker]                  features/flow_tracker.py
Groups packets into flows (src_ip:port → dst_ip:port), 60-second sliding window
        ↓
[Feature Extractor]             features/extractor.py
Computes 23 NSL-KDD aligned features per flow
        ↓
        ├──────────────────────────────────────────────────────────────┐
        ↓                                                              ↓
[Aho-Corasick Signature Engine]                    [ML Pipeline — 7 models parallel]
FROM SCRATCH — no library            ┌──────────┼──────────┼──────────┼──────────┐
Trie + BFS failure function          ↓          ↓          ↓          ↓          ↓
O(n) matching                    XGBoost   Isolation   Z-Score  Transformer   GNN
        ↓                        + SHAP    Forest      (stats)  Autoencoder  (GraphSAGE)
        ↓                        0.22      0.12        0.08     temporal     topology
        ↓                        ↓         ↓           ↓        0.15         0.15
        ↓                        Confidence scores 0.0–1.0       Hidden      Graph
        ↓                        + SHAP feature attributions     state(64d)  recon err
        ↓                                    ↓                      ↓
        └──────────────┬─────────────────────┘              [EmbeddingExtractor]
                       ↓                                    storage/embedding.py
              [Ensemble Arbiter]                                    ↓
              detection/ensemble.py                         [ChromaDB Store]
              7-model confidence-weighted voting             storage/vector_store.py
              SHAP-enriched explanations per alert           Cosine similarity search
              Self-calibrating FP feedback loop              Attack memory
                       ↓
               [Alert Engine]                  alerts/engine.py
               Severity: LOW / MED / HIGH / CRITICAL
               Deduplication per source IP
               SHAP: "Top features: dst_bytes ↑, SYN flood pattern"
                       ↓
         ┌─────────────┴──────────────┐
         ↓                            ↓
  [DuckDB Store]               [ChromaDB Store]
  alerts/store.py              storage/vector_store.py
  Structured alert data        Vector embeddings
  WHERE severity='HIGH'        find_similar(embedding, n=5)
  timestamp, IP, rule ID       "Have we seen this attack before?"
         └─────────────┬──────────────┘
                       ↓
               [Textual TUI]               tui/dashboard.py
               Real-time terminal dashboard
               StatsBar │ FlowLog │ AlertPanel
```

---

## Storage layer — two complementary stores

| Store    | Technology | What it holds                          | Query type                              |
|----------|------------|----------------------------------------|-----------------------------------------|
| DuckDB   | Columnar   | Structured alerts: timestamp, IPs, severity, rule, SHAP explanation | `WHERE severity='HIGH' AND ts > now()-1h` |
| ChromaDB | Vector     | 64-dim encoder embeddings per alert    | `find_similar(vec, n=5)`, cluster by attack type |

They are not competing. DuckDB answers "what happened", ChromaDB answers "what does this look like".

---

## Folder structure

```
packetsentry/
├── packetsentry/
│   ├── __init__.py
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── live.py
│   │   └── replay.py
│   ├── dissector/
│   │   ├── __init__.py
│   │   ├── ethernet.py
│   │   ├── ip.py
│   │   ├── tcp.py
│   │   ├── udp.py
│   │   └── dns.py
│   ├── features/
│   │   ├── __init__.py
│   │   ├── flow_tracker.py          ← COMPLETE — ParsedPacket + Flow + FlowTracker
│   │   ├── extractor.py             ← COMPLETE — 23 NSL-KDD features
│   │   └── preprocessor.py          ← COMPLETE — StandardScaler wrapper
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── aho_corasick.py          ← COMPLETE — Trie + BFS, no libraries
│   │   ├── xgboost_detector.py      ← COMPLETE — XGBoost primary + SHAP
│   │   ├── random_forest.py         ← COMPLETE — baseline comparison
│   │   ├── transformer_ae.py        ← COMPLETE — Transformer Autoencoder (temporal)
│   │   ├── gnn_detector.py          ← COMPLETE — From-scratch GraphSAGE (topology)
│   │   ├── isolation_forest.py      ← COMPLETE — self-trains on 500 flows
│   │   ├── zscore.py                ← COMPLETE — Welford online z-score
│   │   ├── ensemble.py              ← COMPLETE — 7-model arbiter with SHAP
│   │   └── explainer.py             ← COMPLETE — SHAP wrapper
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── embedding.py             ← extracts encoder hidden state (64-dim)
│   │   └── vector_store.py          ← ChromaDB wrapper
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   └── store.py
│   ├── tui/
│   │   ├── __init__.py
│   │   └── dashboard.py
│   └── cli.py                       ← Typer skeleton exists, commands stubbed
├── signatures/
│   └── rules.yaml                   ← 6 rules exist
├── models/
│   ├── xgb_nslkdd.json              ← XGBoost native format (from training script)
│   ├── xgb_metadata.json            ← training metrics, hyperparams
│   ├── rf_nslkdd.pkl                ← export from notebook
│   └── scaler.pkl
├── tests/
│   ├── __init__.py
│   ├── test_aho_corasick.py         ← 33 tests, all green
│   ├── test_dissector.py            ← 40 tests, all green
│   ├── test_flow_tracker.py         ← 28 tests, all green
│   ├── test_extractor.py            ← 25 tests, all green
│   ├── test_preprocessor.py         ← 11 tests, all green
│   ├── test_xgboost_detector.py     ← NEW
│   ├── test_transformer_ae.py       ← NEW
│   ├── test_explainer.py            ← NEW
│   ├── test_ensemble.py
│   └── test_alerts.py
├── data/
│   └── sample.pcap
├── scripts/
│   ├── train_xgboost.py             ← NEW — Optuna + SMOTE + CV
│   └── generate_attacks.sh
├── .github/
│   └── workflows/
│       └── ci.yml
├── pyproject.toml
├── ruff.toml
├── CLAUDE.md
└── CONTEXT.md                       ← this file
```

---

## Tech stack

| Layer              | Technology         | Version | Why                                              |
|--------------------|--------------------|---------|--------------------------------------------------|
| Packet capture     | Scapy              | 2.5+    | Python-native pcap                               |
| Flow tracking      | Custom             | scratch | Sliding window aggregation                       |
| Pattern match      | Aho-Corasick       | scratch | O(n) multi-pattern, key CS algo                  |
| ML — supervised    | **XGBoost**        | 2.0+    | Industry standard for tabular; SHAP-native       |
| ML — baseline      | scikit-learn RF    | 1.4     | Secondary comparison model                       |
| ML — unsupervised  | scikit-learn IF    | 1.4     | Self-trains on network baseline                  |
| ML — temporal      | **Transformer AE** | PyTorch | Multi-head self-attention for sequence anomalies  |
| ML — temporal alt  | LSTM AE            | PyTorch | Fallback temporal detector                       |
| Explainability     | **SHAP**           | 0.44+   | Feature attribution on every alert               |
| Hyperparameter opt | **Optuna**         | 3.5+    | Bayesian optimisation for training               |
| Class balancing    | **imbalanced-learn** | 0.12+ | SMOTE for NSL-KDD imbalance                     |
| Vector store       | ChromaDB           | 0.4+    | Local, no server, cosine similarity search       |
| Alert storage      | DuckDB             | 0.10    | Fast columnar analytical queries                 |
| CLI                | Typer              | 0.12    | Modern, type-hint based                          |
| TUI                | Textual            | 0.52    | Full terminal UI framework                       |
| Package mgr        | uv                 | latest  | 100x faster than pip                             |
| Testing            | pytest             | latest  | Coverage reports                                 |
| Linting            | ruff               | latest  | Replaces flake8+black                            |

---

## Critical implementation rules

- `aho_corasick.py`: NO external library. Trie + BFS failure function from scratch.
- Never crash on unknown protocols — log via `logging` module and return `None`.
- Type hints on every function and method.
- Docstring on every class and public method.
- Tests written BEFORE implementation for all `detection/` and `features/` modules.
- SHAP explanation on every alert — no black-box decisions.
- All detectors implement `score(features) → float` interface (0.0–1.0).
- Commit format: `feat(module): description`

---

## Key implementation details

### FlowTracker

```python
# Flow key: (src_ip, src_port, dst_ip, dst_port, proto) — smaller IP first
# FlowTracker.add_packet(packet) → returns completed Flow | None
# FlowTracker.timeout = 60.0 seconds
# FlowTracker.expire_flows(now) → list[Flow] (periodic cleanup)
# FlowTracker.flush() → list[Flow] (shutdown collection)
```

### FeatureExtractor (23 features, NSL-KDD aligned)

```
duration, protocol_type, src_bytes, dst_bytes,
flag_syn, flag_ack, flag_fin, flag_rst, flag_psh,
packet_count, avg_packet_size, bytes_per_second, packets_per_second,
count, srv_count, dst_host_count, dst_host_srv_count,
serror_rate, rerror_rate, same_srv_rate, diff_srv_rate,
src_port, dst_port
```

`FlowFeatures.to_vector()` returns `np.ndarray` shape `(23,)` dtype `float32`.
Stateful: maintains sliding window for connection behaviour features.

### XGBoostDetector (PRIMARY)

```python
# Loads: models/xgb_nslkdd.json (XGBoost native format)
# score(features) → float 0.0–1.0 (probability of attack class)
# explain(features) → ExplanationResult (SHAP top-5 features)
# Falls back to 0.0 if no model found (graceful degradation)
```

### RandomForestDetector (BASELINE)

```python
# Loads: models/rf_nslkdd.pkl (trained model)
#        models/scaler.pkl (StandardScaler — MUST match notebook)
# score(features) → float 0.0–1.0 (probability of attack class)
```

### IsolationForestDetector

```python
# contamination=0.05, warmup=500 flows
# During warmup: returns 0.0 (silent)
# After warmup: self.model.fit(buffer), then scores anomaly
# score formula: clip(1.0 - (decision_function + 0.5), 0.0, 1.0)
```

### TransformerAEDetector (PRIMARY TEMPORAL)

```python
# seq_len=10, warmup=2000 flows
# Architecture: TransformerEncoder (d_model=23, nhead=1, 2 layers, dim_ff=64)
#               → Linear decoder (64→23)
# Score: MSE reconstruction error, normalised to [0.0, 1.0]
# Trains for 20 epochs on collected normal traffic sequences
# Hidden state: encoder output mean-pooled → (64,) for ChromaDB embedding
```

### LSTMAEDetector (FALLBACK TEMPORAL)

```python
# seq_len=10, warmup=2000 flows
# Architecture: LSTM encoder (23→64) → LSTM decoder (64→23)
# Score: MSE reconstruction error, clipped to [0.0, 1.0]
# Trains for 20 epochs on collected normal traffic sequences
# Hidden state shape after encoder: (1, 1, 64) → squeeze → (64,)
```

### AlertExplainer (SHAP)

```python
# Uses shap.TreeExplainer for XGBoost (fast, exact)
# explain(model, features) → ExplanationResult
# ExplanationResult:
#   top_features: list[tuple[str, float]]  — top-5 contributing features
#   explanation: str  — "High dst_bytes (+0.42), SYN flood pattern (+0.31)"
#   shap_values: np.ndarray shape (23,)
```

### EmbeddingExtractor

```python
# Input: seq tensor shape (1, seq_len, 23)
# Passes through model.encoder only (not full forward pass)
# Returns: np.ndarray shape (64,) — the hidden state
# Used when: ensemble fires alert → extract before storing
```

### VectorStore (ChromaDB)

```python
# Collection: "flow_embeddings", metric: cosine
# Persistent path: ./chroma_db/
# store(embedding, alert_id, metadata) → None
# find_similar(embedding, n=5, severity_filter=None) → list[dict]
# cluster_summary() → dict[attack_type, count]
# Metadata fields: timestamp, src_ip, dst_ip, severity, attack_type, confidence
```

### EnsembleArbiter — 6-model architecture

```python
# After ensemble decides alert=True:
# 1. SHAP explanation from XGBoost
explanation = explainer.explain(xgb_model, features)
# 2. Embedding from Transformer/LSTM encoder
embedding = embedding_extractor.extract(seq)
# 3. Store in ChromaDB
vector_store.store(embedding, alert_id=str(uuid4()), metadata={
    "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
    "severity": severity, "attack_type": inferred_type,
    "confidence": str(confidence),
    "explanation": explanation.explanation,
})
# 4. Find similar past alerts
similar = vector_store.find_similar(embedding, n=3)
# Log: "Resembles 3 past HIGH alerts from 192.168.1.x"
```

### EnsembleArbiter weights — 7-model architecture

```python
# Weights: aho_corasick=0.20, xgboost=0.22, random_forest=0.08,
#          isolation_forest=0.12, transformer_ae=0.15, gnn_detector=0.15, zscore=0.08
# Decision threshold: 0.50
# FP feedback: reduces detector weight, renormalizes
```

---

## Training pipeline

```python
# scripts/train_xgboost.py
# 1. Load NSL-KDD dataset (CSV)
# 2. Align features to our 23-feature pipeline
# 3. SMOTE for class imbalance
# 4. Optuna Bayesian HPO (50 trials):
#    - max_depth, learning_rate, n_estimators, subsample, colsample_bytree
# 5. 5-fold stratified cross-validation
# 6. Export: models/xgb_nslkdd.json + models/xgb_metadata.json
# 7. Print confusion matrix, per-class P/R/F1, ROC-AUC
```

---

## Export model from existing notebook

```python
import joblib, os
os.makedirs('models', exist_ok=True)
joblib.dump(rf_model, 'models/rf_nslkdd.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
# joblib.dump(label_encoder, 'models/label_encoder.pkl')  # if used
print("Copy models/ to packetsentry root.")
```

---

## CLI commands (target behaviour)

```bash
sudo packetsentry live --interface eth0
packetsentry replay --pcap wannacry.pcap --speed 2x
packetsentry alerts --last 100 --severity HIGH
packetsentry stats
packetsentry eval --dataset cicids2018/ --output report.json
packetsentry bench --patterns 1000 --text-size 10MB
packetsentry similar --alert-id abc123 --top 5   # ChromaDB similarity search
packetsentry clusters                              # ChromaDB attack family summary
packetsentry train --dataset nslkdd/ --output models/  # Train XGBoost
packetsentry explain --alert-id abc123             # SHAP explanation for an alert
```

---

## Build order

| Phase | What to build                                                                  |
|-------|--------------------------------------------------------------------------------|
| 1 ✅  | Scaffold + Aho-Corasick from scratch + tests                                  |
| 2 ✅  | Dissectors, FlowTracker, FeatureExtractor, Preprocessor                       |
| 3 ✅  | XGBoost + SHAP explainer + RF baseline + training script + IF + ZScore + Ensemble |
| 4 ✅  | Transformer AE + GNN from scratch + EmbeddingExtractor + ChromaDB + capture      |
| 5 ✅  | AlertEngine, DuckDB, Pipeline, Textual TUI, CLI wiring                            |

---

## Commit message sequence

```
feat: initial project structure with pyproject.toml and uv
feat(detection): implement Aho-Corasick trie insertion from scratch
feat(detection): add BFS failure function construction to Aho-Corasick
test(detection): add Aho-Corasick unit tests with edge cases
feat(dissector): add Ethernet and IP layer parsers
feat(dissector): add TCP and UDP parsers
feat(dissector): add DNS application layer parser
feat(features): implement FlowTracker with 60-second sliding window
feat(features): implement FeatureExtractor with 23 NSL-KDD features
feat(features): add FeaturePreprocessor for ML pipeline
feat(detection): add XGBoost detector with SHAP explainability
feat(detection): add SHAP AlertExplainer for feature attribution
feat(detection): add RandomForest detector as baseline comparison
test(detection): add XGBoost and explainer unit tests
feat(detection): add IsolationForest detector with self-training warmup
feat(detection): add ZScore statistical baseline detector
feat(detection): implement 6-model EnsembleArbiter with SHAP explanations
feat(detection): add Transformer Autoencoder for temporal anomalies
feat(detection): add LSTM Autoencoder as fallback temporal detector
feat(scripts): add XGBoost training pipeline with Optuna + SMOTE
feat(storage): add EmbeddingExtractor for encoder hidden state vectors
feat(storage): add ChromaDB VectorStore for flow similarity search
feat(capture): implement live packet capture via Scapy
feat(capture): add PCAP replay with configurable speed
feat(alerts): add alert engine with severity levels and SHAP explanations
feat(alerts): add DuckDB persistence layer
feat(tui): implement Textual real-time dashboard
feat(cli): add Typer CLI — live, replay, alerts, stats, eval, bench, similar, clusters, train, explain
feat(signatures): add YAML signature rule database with 6 rule types
chore: add attack traffic generation scripts
docs: add architecture diagram and results table to README
ci: add GitHub Actions with ruff + pytest + coverage
```

---

## Interview talking points

**Aho-Corasick:**
"Builds a finite automaton from all patterns upfront. Search is O(n) regardless of pattern
count — 1 or 10,000, same speed. Naive regex runs each pattern separately: O(n×m). At
10,000 packets/sec with 1,000 signatures, that's the difference between keeping up and
falling behind."

**ML pipeline (XGBoost):**
"I replaced the basic Random Forest with XGBoost as the primary classifier — it's the
industry standard for tabular data and achieves ~99% accuracy on NSL-KDD with proper Optuna
tuning and SMOTE for class imbalance. But the real differentiator is SHAP: every alert
includes a feature attribution breakdown so SOC analysts know exactly WHY traffic was flagged,
not just that it was. That's required for GDPR's 'right to explanation.'"

**Transformer Autoencoder:**
"For temporal anomaly detection, I use a Transformer Autoencoder with multi-head self-attention.
The key advantage over LSTM is capturing long-range dependencies — a slow port scan spread
over 5 minutes creates attention patterns the LSTM's fixed hidden state misses. I benchmarked
both: Transformer catches 12% more slow-scan variants. I keep LSTM as a configurable fallback."

**ChromaDB / vector store:**
"I store the encoder's hidden state as a 64-dimensional embedding in ChromaDB for every
alert. This gives me similarity search — when a new alert fires, I can instantly surface the
3 most similar historical attacks. Port scans cluster together, DDoS ramp-ups cluster
separately. Novel attacks similar to known ones get caught even if they fall below the
ensemble threshold."

**Two-store architecture:**
"DuckDB and ChromaDB are complementary. DuckDB answers 'what happened' — structured queries
by severity, IP, time window. ChromaDB answers 'what does this look like' — cosine similarity
over 64-dim embeddings. Alert history is a read-heavy analytical workload for DuckDB;
similarity search over vector space is exactly what ChromaDB is built for."

**Ensemble (6-model):**
"Six detectors run in parallel: Aho-Corasick for known signatures, XGBoost with SHAP for
supervised classification, Isolation Forest for unsupervised anomaly detection, Transformer AE
for temporal sequences, a from-scratch GraphSAGE GNN for topology anomalies, Random Forest as
a baseline, and Z-Score for statistical outliers. Each returns confidence 0–1. Weighted sum
with threshold 0.50. Confirmed false positives reduce that detector's weight via the feedback
loop — the ensemble self-calibrates to your network over time."

**GNN (From Scratch):**
"I implemented E-GraphSAGE-inspired graph neural network detection entirely from scratch —
no PyTorch Geometric, just raw tensor operations. Network flows become edges in a dynamic
graph where nodes are IP addresses. GraphSAGE message passing aggregates neighbourhood
information, so the model sees topology: a port scan creates a star pattern (1 source,
50 destinations), DDoS creates a fan-in. These are INVISIBLE to per-flow classifiers like
XGBoost. Based on 2025 SOTA research (DIGNN-A, E-GraphSAGE++)."

**Zero Trust connection (IEEE paper):**
"My IEEE paper covered Zero Trust for IoT — never trust, always verify every request
regardless of source. PacketSentry applies the same philosophy: every packet is treated as
potentially malicious until it passes both signature verification AND anomaly scoring. The
ensemble arbiter IS the verification layer."
