"""Feature extraction pipeline: flow tracking → feature computation → preprocessing.

Public API:
    - ``ParsedPacket``: Lightweight packet representation for flow tracking.
    - ``Flow``: Bidirectional network flow grouping packets.
    - ``FlowTracker``: Groups packets into flows with timeout-based completion.
    - ``FlowFeatures``: 23 NSL-KDD aligned features per flow.
    - ``FeatureExtractor``: Computes FlowFeatures from completed flows.
    - ``FeaturePreprocessor``: Scales feature vectors for ML models.
"""

from packetsentry.features.extractor import FeatureExtractor, FlowFeatures
from packetsentry.features.flow_tracker import Flow, FlowTracker, ParsedPacket
from packetsentry.features.preprocessor import FeaturePreprocessor

__all__ = [
    "ParsedPacket",
    "Flow",
    "FlowTracker",
    "FlowFeatures",
    "FeatureExtractor",
    "FeaturePreprocessor",
]
