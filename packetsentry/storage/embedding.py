"""Embedding extractor.

Bridges the ML pipeline to the Vector Memory. Extracts the 64-dimensional
hidden state from the Transformer Autoencoder and normalizes it for
cosine similarity search in ChromaDB.
"""

from __future__ import annotations

import numpy as np

from packetsentry.features.extractor import FlowFeatures
from packetsentry.detection.transformer_ae import TransformerAEDetector


class EmbeddingExtractor:
    """Extracts and normalizes embeddings from the TransformerAE."""

    def __init__(self, transformer: TransformerAEDetector) -> None:
        self.transformer = transformer

    def extract(self, features: FlowFeatures) -> np.ndarray | None:
        """Extract a normalized 64-dim embedding vector.

        Returns None if the Transformer has not yet been trained or if
        the sliding window is not yet full.

        Args:
            features: The flow features.

        Returns:
            L2-normalized numpy array of shape (64,), or None.
        """
        emb = self.transformer.get_embedding(features)
        if emb is None:
            return None

        # L2 normalize the embedding for optimal cosine similarity search
        norm = np.linalg.norm(emb)
        if norm > 0:
            return emb / norm
        return emb
