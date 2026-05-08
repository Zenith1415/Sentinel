"""
Knowledge Base — ChromaDB-backed vector store of known vulnerability patterns.
"""
import os
from typing import List, Dict, Any
import chromadb


class KnowledgeBase:
    COLLECTION = "vuln_patterns"

    def __init__(self, path: str | None = None):
        chroma_path = path or os.getenv("CHROMA_PATH", "./chroma_db")
        self._client = chromadb.PersistentClient(path=chroma_path)
        self._col = self._client.get_or_create_collection(self.COLLECTION)

    def seed_defaults(self) -> None:
        patterns = [
            {
                "id": "KB-REENT-001",
                "severity": "critical",
                "type": "reentrancy",
                "location": "withdraw",
                "description": (
                    "External call before state update enables reentrancy. "
                    "Attacker's fallback re-enters withdraw() and drains funds."
                ),
                "suggested_fix": "Use CEI: update balances[msg.sender] = 0 BEFORE .call{value:}.",
                "code_pattern": ".call{value:} before balances update reentrancy external call",
            },
            {
                "id": "KB-ACC-001",
                "severity": "critical",
                "type": "access_control",
                "location": "setOwner",
                "description": "Privileged function missing onlyOwner or equivalent modifier.",
                "suggested_fix": "Add onlyOwner modifier.",
                "code_pattern": "function setOwner without onlyOwner access control missing",
            },
            {
                "id": "KB-INT-001",
                "severity": "high",
                "type": "integer_overflow",
                "location": "arithmetic",
                "description": "Unchecked arithmetic may overflow on older Solidity versions.",
                "suggested_fix": "Use Solidity >=0.8.0 built-in overflow checks or SafeMath.",
                "code_pattern": "unchecked arithmetic overflow uint256 addition subtraction",
            },
        ]
        ids = [p["id"] for p in patterns]
        docs = [p["code_pattern"] for p in patterns]
        metas = [{k: v for k, v in p.items() if k != "code_pattern"} for p in patterns]
        self._col.upsert(ids=ids, documents=docs, metadatas=metas)

    def query(self, text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        count = self._col.count()
        if count == 0:
            return []
        actual_n = min(n_results, count)
        results = self._col.query(query_texts=[text], n_results=actual_n)
        out = []
        for i, meta in enumerate(results.get("metadatas", [[]])[0]):
            score = results["distances"][0][i] if results.get("distances") else 1.0
            out.append({**meta, "score": score})
        return out

    def add_pattern(self, pattern: Dict[str, Any]) -> None:
        self._col.upsert(
            ids=[pattern["id"]],
            documents=[pattern.get("code_pattern", pattern["description"])],
            metadatas=[{k: v for k, v in pattern.items() if k != "code_pattern"}],
        )
