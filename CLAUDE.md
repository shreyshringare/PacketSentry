# PacketSentry

## Build order — completed ✅
1. ✅ Scaffold + pyproject.toml
2. ✅ Aho-Corasick FROM SCRATCH + tests (TDD first)
3. ✅ Protocol dissectors: ethernet → ip → tcp/udp → dns
4. ✅ FlowTracker + FeatureExtractor + FeaturePreprocessor
5. ✅ XGBoost detector (primary supervised) + SHAP explainer
6. ✅ RandomForest detector (baseline comparison)
7. ✅ IsolationForest + ZScore detectors
8. ✅ Transformer Autoencoder (temporal) + GNN from scratch (topology)
9. ✅ EnsembleArbiter (7-model, confidence-weighted, SHAP-enriched decisions)
10. ✅ EmbeddingExtractor + ChromaDB VectorStore
11. ✅ Training pipeline: scripts/train_xgboost.py (Optuna + SMOTE + CV)
12. ✅ AlertEngine + DuckDB store
13. ✅ DetectionPipeline orchestrator + Live capture + PCAP replay
14. ✅ Textual TUI dashboard
15. ✅ Typer CLI (live, replay, alerts, bench)

## Test suite: 241/241 passing ✅

## Critical rules
- aho_corasick.py: NO external library. Trie + BFS failure function from scratch.
- gnn_detector.py: NO PyTorch Geometric. GraphSAGE message passing from scratch.
- Never crash on unknown protocols — log and skip.
- Type hints on everything.
- Docstring on every class and public method.
- Tests before implementation for all detection/ and features/ modules.
- SHAP explanation on every alert — no black-box decisions.
- All detectors implement `score(features) → float` interface (0.0–1.0).

## ML stack (7 models)
- XGBoost 2.0 — primary supervised classifier, SHAP-native
- SHAP — TreeExplainer for XGBoost, every alert gets feature attribution
- Transformer Autoencoder — multi-head self-attention for temporal anomaly detection
- GNN (GraphSAGE) — from-scratch graph neural network for topology anomaly detection
- Isolation Forest — unsupervised, self-trains on network baseline
- Random Forest — baseline comparison model
- Z-Score — Welford online statistical anomaly detection
- Optuna — Bayesian hyperparameter optimisation for training
- SMOTE (imbalanced-learn) — class imbalance handling for NSL-KDD

## Commit format
feat(module): description

## Interview connection
Zero Trust from IEEE paper → ensemble arbiter as verification layer.
XGBoost + SHAP → "every alert is explainable, not a black box."
Transformer AE → "self-attention captures long-range dependencies LSTM misses."
GNN → "E-GraphSAGE-inspired: models traffic as a graph to catch topology attacks (DDoS fan-out, port scan star) invisible to per-flow classifiers."
