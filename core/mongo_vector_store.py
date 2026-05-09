"""
MongoDB Atlas Vector Search store.

Dual-write companion to ChromaDB — keeps cloud and local in sync.
Requires a Vector Search index named 'vector_index' on the collection
with numDimensions=768 and similarity=cosine.

Atlas UI path:
  Cluster → Search → Create Search Index → JSON Editor → paste:
  {
    "fields": [{
      "type": "vector",
      "path": "embedding",
      "numDimensions": 768,
      "similarity": "cosine"
    }]
  }
"""
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def _embed(text: str) -> list[float]:
    """Generate a 768-dim embedding via Google text-embedding-004."""
    from langchain_google_genai import GoogleGenerativeAIEmbeddings
    embedder = GoogleGenerativeAIEmbeddings(
        model="models/text-embedding-004",
        google_api_key=os.environ["GOOGLE_API_KEY"],
    )
    return embedder.embed_query(text)


class MongoVectorStore:
    INDEX_NAME = "vector_index"

    def __init__(self, uri: str, db_name: str, collection_name: str) -> None:
        from pymongo import MongoClient
        self._client = MongoClient(uri)
        self._col = self._client[db_name][collection_name]

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def upsert(self, ids: list[str], documents: list[str], metadatas: list[dict]) -> None:
        from pymongo import ReplaceOne
        ops = []
        for doc_id, text, meta in zip(ids, documents, metadatas):
            try:
                embedding = _embed(text)
            except Exception as exc:
                logger.warning("Embedding failed for %s: %s — skipping Atlas upsert", doc_id, exc)
                continue
            ops.append(ReplaceOne(
                {"_id": doc_id},
                {"_id": doc_id, "text": text, "embedding": embedding, **meta},
                upsert=True,
            ))
        if ops:
            self._col.bulk_write(ops)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def query(self, text: str, n_results: int = 3) -> list[dict[str, Any]]:
        try:
            embedding = _embed(text)
        except Exception as exc:
            logger.warning("Embedding failed for query: %s", exc)
            return []

        pipeline = [
            {
                "$vectorSearch": {
                    "index":       self.INDEX_NAME,
                    "path":        "embedding",
                    "queryVector": embedding,
                    "numCandidates": n_results * 10,
                    "limit":       n_results,
                }
            },
            {
                "$project": {
                    "_id":   1,
                    "text":  1,
                    "score": {"$meta": "vectorSearchScore"},
                    "type": 1, "severity": 1, "location": 1,
                    "description": 1, "suggested_fix": 1,
                }
            },
        ]
        try:
            return list(self._col.aggregate(pipeline))
        except Exception as exc:
            logger.warning("Atlas vector search failed: %s", exc)
            return []

    def count(self) -> int:
        try:
            return self._col.estimated_document_count()
        except Exception:
            return 0
