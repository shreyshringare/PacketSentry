"""Detection pipeline — end-to-end orchestrator.

Wires together every PacketSentry module into a single ``ingest()`` call:

    ParsedPacket → FlowTracker → FeatureExtractor → Preprocessor
                 → [AhoCorasick, XGBoost, RF, IF, TAE, GNN, ZScore]
                 → EnsembleArbiter → DecisionResult

Design decisions:
  - The pipeline owns all component instances so nothing leaks.
  - ``ingest()`` returns None for most packets (only fires on flow completion).
  - The preprocessor uses online fitting — it fits on the first batch of
    features it sees, then transforms subsequent ones.  This mirrors how
    Isolation Forest and Transformer AE self-train during warmup.
  - Aho-Corasick runs on raw packet payloads (before flow aggregation)
    because signatures match byte patterns, not statistical features.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from packetsentry.detection.aho_corasick import AhoCorasick
from packetsentry.detection.ensemble import DecisionResult, EnsembleArbiter
from packetsentry.detection.gnn_detector import GNNDetector
from packetsentry.detection.isolation_forest import IsolationForestDetector
from packetsentry.detection.random_forest import RandomForestDetector
from packetsentry.detection.transformer_ae import TransformerAEDetector
from packetsentry.detection.xgboost_detector import XGBoostDetector
from packetsentry.detection.zscore import ZScoreDetector
from packetsentry.features.extractor import FeatureExtractor, FlowFeatures
from packetsentry.features.flow_tracker import Flow, FlowTracker, ParsedPacket, flow_key as make_flow_key
from packetsentry.features.preprocessor import FeaturePreprocessor

logger = logging.getLogger(__name__)

# Default Aho-Corasick signatures (SQL injection, XSS, path traversal)
_DEFAULT_SIGNATURES = [
    b"' OR '1'='1",
    b"' OR 1=1--",
    b"<script>",
    b"../../../",
    b"/etc/passwd",
    b"UNION SELECT",
    b"cmd.exe",
    b"powershell -e",
    b"wget http",
    b"curl http",
]


class DetectionPipeline:
    """End-to-end packet → alert orchestrator.

    Args:
        flow_timeout: Seconds after which a flow is considered complete.
        signatures: List of byte patterns for Aho-Corasick.
        alert_callback: Optional function called on every alert.
    """

    def __init__(
        self,
        flow_timeout: float = 60.0,
        signatures: list[bytes] | None = None,
        alert_callback: Callable[[DecisionResult, FlowFeatures, str, str, int], None] | None = None,
    ) -> None:
        import yaml
        from pathlib import Path
        
        # --- Features layer ---
        self._tracker = FlowTracker(timeout=flow_timeout)
        self._extractor = FeatureExtractor()

        # Load saved preprocessor if available, otherwise start fresh.
        _preprocessor_path = Path(__file__).parent.parent.parent / "models" / "preprocessor.pkl"
        if _preprocessor_path.exists():
            try:
                self._preprocessor = FeaturePreprocessor.load(str(_preprocessor_path))
                self._pp_fitted = True
                logger.info("Loaded FeaturePreprocessor from %s", _preprocessor_path)
            except Exception as exc:
                logger.warning("Failed to load preprocessor (%s); starting fresh.", exc)
                self._preprocessor = FeaturePreprocessor()
                self._pp_fitted = False
        else:
            self._preprocessor = FeaturePreprocessor()
            self._pp_fitted = False

        self._pp_fit_buffer: list[FlowFeatures] = []
        self._pp_fit_threshold = 50

        # --- Detection layer (Gate 1 & 2) ---
        self._aho = AhoCorasick()
        
        # Load Gate 1 Rules
        rules_path = Path(__file__).parent.parent / "signatures" / "rules.yaml"
        loaded_sigs = []
        if rules_path.exists():
            try:
                with open(rules_path, "r") as f:
                    rules_doc = yaml.safe_load(f)
                    for policy in rules_doc.get("policies", []):
                        if policy.get("type") == "payload_signature":
                            for pat in policy.get("patterns", []):
                                loaded_sigs.append(pat.encode("utf-8", errors="replace"))
            except Exception as e:
                logger.error(f"Failed to load rules.yaml: {e}")
                
        sigs = signatures or loaded_sigs or _DEFAULT_SIGNATURES
        for sig in sigs:
            self._aho.add_pattern(sig.decode("utf-8", errors="replace"))
        self._aho.build()

        self._xgboost = XGBoostDetector()
        self._random_forest = RandomForestDetector()
        self._isolation_forest = IsolationForestDetector()
        self._transformer_ae = TransformerAEDetector()
        self._gnn = GNNDetector()
        self._zscore = ZScoreDetector()
        self._ensemble = EnsembleArbiter()

        # --- Callback ---
        self._alert_callback = alert_callback

        # --- Counters ---
        self._packet_count = 0
        self._flow_count = 0
        self._alert_count = 0
        self._total_bytes = 0
        self._payload_buffer: dict[str, bytes] = {}

    def ingest(self, packet: ParsedPacket) -> DecisionResult | None:
        self._packet_count += 1
        self._total_bytes += packet.length

        flow_key = make_flow_key(packet.src_ip, packet.dst_ip, str(packet.protocol))
        if packet.payload:
            accumulated = self._payload_buffer.get(flow_key, b"") + packet.payload
            self._payload_buffer[flow_key] = accumulated[:65536]

        completed_flow = self._tracker.add_packet(packet)
        if completed_flow is None:
            return None

        return self._process_flow(completed_flow)

    def flush(self) -> list[DecisionResult]:
        remaining = self._tracker.flush()
        results = []
        for flow in remaining:
            result = self._process_flow(flow)
            if result is not None:
                results.append(result)
        return results

    def stats(self) -> dict:
        return {
            "packets": self._packet_count,
            "bytes": self._total_bytes,
            "active_flows": self._tracker.active_count,
            "completed_flows": self._flow_count,
            "alerts": self._alert_count,
        }

    def _process_flow(self, flow: Flow) -> DecisionResult | None:
        self._flow_count += 1

        # =====================================================================
        # GATE 1: DETERMINISTIC FILTER
        # =====================================================================
        flow_key = make_flow_key(flow.src_ip, flow.dst_ip, str(flow.protocol))
        payload = self._payload_buffer.pop(flow_key, b"")
        
        if payload:
            matches = self._aho.search(payload)
            if matches:
                # INSTANT CERTAINTY MATCH! Skip Gate 2.
                result = DecisionResult(
                    is_alert=True,
                    confidence=1.0,
                    scores={"aho_corasick": 1.0},
                    explanation=None
                )
                self._alert_count += 1
                if self._alert_callback:
                    # We pass None for features since ML was skipped
                    self._alert_callback(
                        result, None, flow.src_ip, flow.dst_ip, flow.dst_port
                    )
                return result

        # =====================================================================
        # GATE 2: PROBABILISTIC ENSEMBLE
        # =====================================================================
        features = self._extractor.extract(flow)

        if not self._pp_fitted:
            self._pp_fit_buffer.append(features)
            if len(self._pp_fit_buffer) >= self._pp_fit_threshold:
                self._preprocessor.fit(self._pp_fit_buffer)
                self._pp_fitted = True
                self._pp_fit_buffer.clear()
                logger.info("FeaturePreprocessor online-fitted on %d flows", self._pp_fit_threshold)

        scores: dict[str, float] = {}
        scores["aho_corasick"] = 0.0 # Handled in Gate 1
        scores["xgboost"] = self._xgboost.score(features)
        scores["random_forest"] = self._random_forest.score(features)
        scores["isolation_forest"] = self._isolation_forest.score(features)
        scores["transformer_ae"] = self._transformer_ae.score(features)
        scores["gnn_detector"] = self._gnn.score(flow.src_ip, flow.dst_ip, features)
        scores["zscore"] = self._zscore.score(features)

        result = self._ensemble.decide(scores)

        if result.is_alert:
            self._alert_count += 1
            if self._alert_callback:
                self._alert_callback(
                    result, features, flow.src_ip, flow.dst_ip, flow.dst_port
                )

        return result
