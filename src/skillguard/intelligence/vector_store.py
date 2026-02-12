"""ChromaDB-backed vector store for attack pattern embeddings.

Provides a persistent store of attack pattern embeddings that can be
used by the VectorSearchEngine and other components for semantic
similarity searches.
"""

from __future__ import annotations

from typing import Any

try:
    import chromadb

    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer

    SBERT_AVAILABLE = True
except ImportError:
    SBERT_AVAILABLE = False

_COLLECTION_NAME = "skillguard_attack_patterns"
_DEFAULT_MODEL = "all-MiniLM-L6-v2"


class AttackPatternStore:
    """Persistent vector store for attack pattern embeddings.

    Wraps ChromaDB to provide semantic search over known attack
    patterns. Used by the VectorSearchEngine for similarity matching.
    """

    def __init__(self, persist_dir: str | None = None, model_name: str = _DEFAULT_MODEL) -> None:
        self._persist_dir = persist_dir
        self._model_name = model_name
        self._client: Any = None
        self._collection: Any = None
        self._model: Any = None
        self._initialized = False

    def _init(self) -> bool:
        """Initialize ChromaDB client and embedding model."""
        if self._initialized:
            return self._client is not None

        self._initialized = True

        if not CHROMA_AVAILABLE or not SBERT_AVAILABLE:
            return False

        try:
            self._model = SentenceTransformer(self._model_name)
            if self._persist_dir:
                self._client = chromadb.PersistentClient(path=self._persist_dir)
            else:
                self._client = chromadb.Client()

            self._collection = self._client.get_or_create_collection(
                name=_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            return True
        except Exception:
            return False

    async def add_pattern(
        self,
        pattern_id: str,
        text: str,
        category: str,
        severity: str = "high",
        metadata: dict[str, str] | None = None,
    ) -> bool:
        """Add a single attack pattern to the store."""
        if not self._init():
            return False

        try:
            embedding = self._model.encode([text]).tolist()
            meta = {"category": category, "severity": severity}
            if metadata:
                meta.update(metadata)

            self._collection.add(
                ids=[pattern_id],
                embeddings=embedding,
                documents=[text],
                metadatas=[meta],
            )
            return True
        except Exception:
            return False

    async def add_patterns_bulk(
        self,
        patterns: list[dict[str, str]],
    ) -> int:
        """Add multiple attack patterns in bulk.

        Args:
            patterns: List of dicts with keys: id, text, category, severity

        Returns:
            Number of patterns added successfully.
        """
        if not self._init():
            return 0

        try:
            ids = [p["id"] for p in patterns]
            texts = [p["text"] for p in patterns]
            metadatas = [
                {"category": p.get("category", "unknown"), "severity": p.get("severity", "high")}
                for p in patterns
            ]
            embeddings = self._model.encode(texts).tolist()

            self._collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=texts,
                metadatas=metadatas,
            )
            return len(patterns)
        except Exception:
            return 0

    async def search_similar(
        self,
        text: str,
        n_results: int = 5,
        threshold: float = 0.75,
    ) -> list[dict[str, Any]]:
        """Search for patterns similar to the given text.

        Returns:
            List of dicts with keys: id, text, category, severity, similarity
        """
        if not self._init():
            return []

        try:
            embedding = self._model.encode([text]).tolist()
            results = self._collection.query(
                query_embeddings=embedding,
                n_results=n_results,
                include=["documents", "metadatas", "distances"],
            )

            matches = []
            if results and results.get("distances"):
                for idx in range(len(results["distances"][0])):
                    dist = results["distances"][0][idx]
                    similarity = 1.0 - (dist / 2.0)
                    if similarity >= threshold:
                        matches.append({
                            "id": results["ids"][0][idx],
                            "text": results["documents"][0][idx],
                            "category": results["metadatas"][0][idx].get("category"),
                            "severity": results["metadatas"][0][idx].get("severity"),
                            "similarity": round(similarity, 4),
                        })
            return matches
        except Exception:
            return []

    async def count(self) -> int:
        """Return the number of patterns in the store."""
        if not self._init():
            return 0
        try:
            return self._collection.count()
        except Exception:
            return 0

    @property
    def available(self) -> bool:
        """Check if the vector store backend is available."""
        return CHROMA_AVAILABLE and SBERT_AVAILABLE
