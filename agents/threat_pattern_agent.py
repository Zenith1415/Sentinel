"""
Threat pattern agent — queries ChromaDB KB for similar past vulnerability patterns.
Embeds contract source chunks, returns top-5 KB matches as findings.
"""
import os
from typing import Any

from graph.state import HealingState
from core.kb import KnowledgeBase

_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


class ThreatPatternAgent:
    methodology = "pattern"
    CHUNK_LINES = 25
    TOP_K = 5

    def __init__(self, chroma_path: str | None = None) -> None:
        path = chroma_path or os.getenv("CHROMA_PATH", "./chroma_db")
        self._kb = KnowledgeBase(path=path)
        self._kb.seed_defaults()

    def run(self, contract_source: str, state: HealingState) -> list[dict]:
        try:
            return self._query_findings(contract_source)
        except Exception:
            return []

    def _query_findings(self, source: str) -> list[dict]:
        chunks = self._chunk(source)
        findings: list[dict] = []
        seen_ids: set[str] = set()

        for chunk in chunks:
            for match in self._kb.query(chunk, n_results=self.TOP_K):
                vid = match.get("id", "KB-UNK")
                if vid in seen_ids:
                    continue
                seen_ids.add(vid)

                # ChromaDB distance: 0=identical, ~2=orthogonal (cosine space)
                raw_score = float(match.get("score", 1.0))
                confidence = round(max(0.0, min(1.0, 1.0 - raw_score / 2.0)), 3)

                sev_raw = match.get("severity", "medium")
                severity = _SEVERITY_MAP.get(sev_raw.lower(), "Medium")

                findings.append({
                    "vuln_type": self._fmt_type(match.get("type", "unknown")),
                    "severity": severity,
                    "affected_function": match.get("location", "unknown"),
                    "line_range": [0, 0],
                    "confidence": confidence,
                    "fix_recommendation": match.get("suggested_fix", "Review KB pattern."),
                    "evidence": (
                        f"[KB:{vid}] {match.get('description', '')}"[:400]
                    ),
                    "methodology": self.methodology,
                    "cross_contract_flag": False,
                })

        return findings

    def _chunk(self, source: str) -> list[str]:
        lines = source.splitlines()
        return [
            "\n".join(lines[i: i + self.CHUNK_LINES])
            for i in range(0, len(lines), self.CHUNK_LINES)
        ]

    def _fmt_type(self, t: str) -> str:
        return "".join(w.capitalize() for w in t.replace("_", " ").split())
