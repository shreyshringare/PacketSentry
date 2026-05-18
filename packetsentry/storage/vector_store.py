"""ChromaDB Vector Store for attack memory.

Stores attack embeddings and metadata to allow for "fuzzy" similarity searches.
When a new attack is detected, we can query this store to see if we've seen
a similar attack before.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import chromadb
import numpy as np

logger = logging.getLogger(__name__)


class ChromaStore:
    """Wraps ChromaDB for storing and retrieving attack embeddings."""

    def __init__(self, persist_directory: str | None = "data/chroma", collection_name: str = "attack_memory") -> None:
        """Initialize the ChromaDB client.

        Args:
            persist_directory: Path to store data on disk. If None, uses an
                ephemeral in-memory client (for testing).
            collection_name: Name of the Chroma collection.
        """
        if persist_directory:
            self._client = chromadb.PersistentClient(path=persist_directory)
        else:
            self._client = chromadb.EphemeralClient()

        # We use cosine distance (1 - cosine_similarity)
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )

    def store_alert(
        self, alert_id: str, embedding: np.ndarray, metadata: dict[str, Any]
    ) -> None:
        """Store a new attack embedding.

        Args:
            alert_id: Unique string ID for the alert.
            embedding: 64-dim normalized numpy array.
            metadata: Dictionary of metadata (e.g. src_ip, severity).
        """
        try:
            self._collection.add(
                ids=[alert_id],
                embeddings=[embedding.tolist()],
                metadatas=[metadata]
            )
        except Exception as e:
            logger.error(f"Failed to store embedding for alert {alert_id}: {e}")

    def find_similar(
        self, embedding: np.ndarray, top_k: int = 5
    ) -> list[dict[str, Any]]:
        """Find the top-k most similar past attacks.

        Args:
            embedding: 64-dim normalized numpy array.
            top_k: Number of results to return.

        Returns:
            List of dictionaries containing 'alert_id', 'distance', and 'metadata'.
            Distance is cosine distance (0.0 means identical).
        """
        if self._collection.count() == 0:
            return []

        try:
            results = self._collection.query(
                query_embeddings=[embedding.tolist()],
                n_results=min(top_k, self._collection.count()),
                include=["metadatas", "distances"]
            )

            matches = []
            if results["ids"] and len(results["ids"]) > 0:
                for i in range(len(results["ids"][0])):
                    matches.append({
                        "alert_id": results["ids"][0][i],
                        "distance": results["distances"][0][i],
                        "metadata": results["metadatas"][0][i],
                    })
            return matches

        except Exception as e:
            logger.error(f"Failed to query similar attacks: {e}")
            return []
