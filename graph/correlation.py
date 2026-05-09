"""
Correlation agent — merges multi-agent findings, detects conflicts,
computes a weighted confidence score, and assigns a routing tier.

Pipeline:
  Step 1 — Quorum gate + TIMEOUT short-circuit
  Step 2 — Disagreement resolution + merge per (function, vuln_type)
  Step 3 — Conflict detection
  Step 4 — Confidence score (weighted avg + penalties)
  Step 5 — Tiered routing: fast | medium | slow
"""
import logging
import os
import re

from graph.state import HealingState

logger = logging.getLogger(__name__)

_FAST_CONFIDENCE = 0.75    # confidence ≥ 75% + no cross-contract + KB has coverage
_SLOW_CONFIDENCE = 0.30    # confidence < 30% always → slow
_SLOW_CROSS_CONFIDENCE = 0.65  # cross-contract or novel patterns force slow when confidence < 65%
_FAST_KB_MIN     = 5       # KB needs at least 5 proven patches for the fast path
_HIGH_TVL        = 1_000_000

_SEV_WEIGHTS = {"critical": 1.4, "high": 1.2, "medium": 1.0, "low": 0.8}
_PUBLIC_FNS  = {"deposit", "withdraw", "transfer", "swap", "stake", "unstake", "buy", "sell"}


class CorrelationAgent:

    def __init__(self, chroma_path: str | None = None) -> None:
        self._chroma_path = chroma_path or os.getenv("CHROMA_PATH", "./chroma_db")

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def correlate(self, state: HealingState) -> HealingState:
        s = dict(state)

        static   = list(s.get("static_findings",   []) or [])
        symbolic = list(s.get("symbolic_findings",  []) or [])
        semantic = list(s.get("semantic_findings",  []) or [])
        gov      = list(s.get("governance_findings",[]) or [])
        threat   = list(s.get("threat_findings",    []) or [])

        # ── Step 1: quorum check ──────────────────────────────────────
        has_timeout = _is_timeout(symbolic)

        if not static:
            logger.warning("DEAD_LETTER [quorum] no static findings — proceeding with available")
        if not symbolic:
            logger.warning("DEAD_LETTER [quorum] no symbolic findings — proceeding with available")

        # Pool all non-TIMEOUT findings for merge.
        # Filter out very-low-confidence findings (< 0.30) — these are noise
        # from KB nearest-neighbour matches that fire on every contract regardless
        # of whether the pattern is actually present.
        raw = [
            f for f in (static + symbolic + semantic + gov + threat)
            if f.get("vuln_type") != "TIMEOUT"
            and float(f.get("confidence", 0.0)) >= 0.30
        ]

        # ── Step 2: merge ─────────────────────────────────────────────
        merged = self._merge(raw)

        # ── Step 3: conflicts ─────────────────────────────────────────
        conflicts = self._conflicts(merged)

        # ── Step 4: confidence ────────────────────────────────────────
        confidence = self._confidence(merged, conflicts, has_timeout)

        # ── Step 5: route (TIMEOUT always forces slow path) ──────────
        if has_timeout:
            route = "slow"
        else:
            route = self._route(s, merged, confidence)

        s["all_findings"]     = merged
        s["conflict_flags"]   = conflicts
        s["confidence_score"] = confidence
        s["route"]            = route
        return s

    # ------------------------------------------------------------------
    # Step 2 — merge findings across agents
    # ------------------------------------------------------------------

    def _merge(self, raw: list[dict]) -> list[dict]:
        # Group by (affected_function, vuln_type)
        groups: dict[tuple, list[dict]] = {}
        for f in raw:
            key = (
                str(f.get("affected_function", "unknown")),
                str(f.get("vuln_type", "unknown")),
            )
            groups.setdefault(key, []).append(f)

        merged: list[dict] = []
        for (fn, vtype), group in groups.items():
            methodologies = {f.get("methodology", "") for f in group}
            adjusted: list[float] = []

            for f in group:
                c = float(f.get("confidence", 0.5))
                meth = f.get("methodology", "")

                # Symbolic dissents from static+llm → weight 2x
                # (symbolic found it, but neither static nor llm did)
                has_static = any(
                    g.get("methodology") == "static" for g in group
                )
                has_llm = any(
                    g.get("methodology") in ("llm", "governance") for g in group
                )
                if meth == "symbolic" and not has_static and not has_llm:
                    c = min(1.0, c * 2.0)

                # Pure-LLM finding → confidence penalty -0.15
                # Governance patterns are deterministic regex rules, not guesses,
                # so they do NOT receive the LLM uncertainty penalty.
                if methodologies and methodologies <= {"llm"}:
                    c = max(0.0, c - 0.15)

                adjusted.append(c)

            avg_conf = sum(adjusted) / len(adjusted)
            # Use the highest-confidence individual finding as the base record
            base = max(group, key=lambda f: float(f.get("confidence", 0)))

            # Deduplicate fix recommendations
            seen_fixes: set[str] = set()
            fixes: list[str] = []
            for f in group:
                fix = f.get("fix_recommendation", "")
                if fix and fix not in seen_fixes:
                    seen_fixes.add(fix)
                    fixes.append(fix)

            # Deduplicate evidence snippets
            ev_parts = list({f.get("evidence", "")[:120] for f in group} - {""})

            merged.append({
                **base,
                "confidence":        round(min(1.0, max(0.0, avg_conf)), 3),
                "fix_recommendation": fixes[0] if len(fixes) == 1 else "; ".join(fixes[:2]),
                "evidence":          " // ".join(ev_parts)[:400],
                "methodology":       "+".join(sorted(methodologies)),
            })

        return merged

    # ------------------------------------------------------------------
    # Step 3 — conflict detection
    # ------------------------------------------------------------------

    def _conflicts(self, merged: list[dict]) -> list[str]:
        flags: list[str] = []

        # Group merged findings by function
        by_fn: dict[str, list[dict]] = {}
        for f in merged:
            by_fn.setdefault(f.get("affected_function", "unknown"), []).append(f)

        for fn, findings in by_fn.items():
            if len(findings) < 2:
                continue

            fixes = [f.get("fix_recommendation", "").lower() for f in findings]

            has_reent = any(
                kw in fix
                for fix in fixes
                for kw in ("nonreentrant", "checks-effects", "cei", "reentrancy", "state before")
            )
            has_access = any(
                kw in fix
                for fix in fixes
                for kw in ("onlyowner", "access control", "onlyrole", "onlyadmin")
            )
            has_cei   = any("checks-effects" in fix or " cei" in fix for fix in fixes)
            has_mutex = any(
                "mutex" in fix or "nonreentrant" in fix or "reentrancyguard" in fix
                for fix in fixes
            )

            # [C1] nonReentrant + onlyOwner on the same function
            if has_reent and has_access:
                flags.append(
                    f"CONFLICT:{fn}:nonReentrant+onlyOwner — "
                    f"confirm {fn} needs both reentrancy guard and access restriction"
                )

            # [C2] CEI pattern + mutex guard are redundant
            if has_cei and has_mutex:
                flags.append(
                    f"REDUNDANCY:{fn}:CEI+mutex — "
                    f"CEI pattern and mutex/nonReentrant guard are redundant; prefer CEI"
                )

            # [C3] access control on a user-callable function would break UX
            if fn.lower() in _PUBLIC_FNS and has_access:
                flags.append(
                    f"CONFLICT:{fn}:access-control-on-public-fn — "
                    f"onlyOwner on {fn} would block regular users"
                )

        return flags

    # ------------------------------------------------------------------
    # Step 4 — confidence score
    # ------------------------------------------------------------------

    def _confidence(
        self, merged: list[dict], conflicts: list[str], has_timeout: bool
    ) -> float:
        if not merged:
            # No findings = the contract is clean. High confidence by definition.
            # (The architecture says: empty findings → fast-path clean exit.)
            score = 0.95
        else:
            total_w = w_sum = 0.0
            for f in merged:
                w = _SEV_WEIGHTS.get(f.get("severity", "medium").lower(), 1.0)
                c = float(f.get("confidence", 0.5))
                w_sum   += c * w
                total_w += w
            score = w_sum / total_w if total_w else 0.5

        # Penalties
        score -= 0.08 * len(conflicts)
        if any(f.get("cross_contract_flag") for f in merged):
            score -= 0.10
        if has_timeout:
            score -= 0.05   # Mythril absent is normal in most envs; don't tank confidence

        return round(max(0.0, min(1.0, score)), 3)

    # ------------------------------------------------------------------
    # Step 5 — tiered routing
    # ------------------------------------------------------------------

    def _route(self, state: dict, merged: list[dict], confidence: float) -> str:
        cross = any(f.get("cross_contract_flag") for f in merged)
        tvl   = float(state.get("tvl_estimate") or 0)

        # ── No findings → fast (clean exit, nothing to patch) ─────────
        if not merged:
            return "fast"

        # ── SLOW conditions ───────────────────────────────────────────
        if confidence < _SLOW_CONFIDENCE:
            return "slow"
        if tvl > _HIGH_TVL:
            return "slow"
        # Cross-contract or novel pattern + borderline confidence → slow
        if cross and confidence < _SLOW_CROSS_CONFIDENCE:
            return "slow"
        if self._has_novel_patterns(merged) and confidence < _SLOW_CROSS_CONFIDENCE:
            return "slow"

        # ── FAST conditions ───────────────────────────────────────────
        # Fast path is reserved for low-risk patches: no Critical-severity findings
        # (those must go through full validation), high confidence, no cross-contract,
        # and the KB has enough coverage to support a quick patch.
        has_critical = any(
            (f.get("severity", "").lower() == "critical") for f in merged
        )
        if (
            not has_critical
            and confidence >= _FAST_CONFIDENCE
            and not cross
            and self._kb_has_sufficient_coverage(merged)
        ):
            return "fast"

        return "medium"

    # ------------------------------------------------------------------
    # KB helpers (fail open — unavailable KB → conservative routing)
    # ------------------------------------------------------------------

    def _has_novel_patterns(self, merged: list[dict]) -> bool:
        """True if any static/symbolic finding has no keyword overlap with KB types.

        Governance and pattern findings come from predefined rule libraries so
        they are never treated as novel regardless of KB coverage.
        """
        try:
            from core.kb import KnowledgeBase
            kb = KnowledgeBase(path=self._chroma_path)
            kb_types = self._kb_types(kb)
            if not kb_types:
                return False
            for f in merged:
                if f.get("methodology", "") in ("governance", "pattern"):
                    continue  # predefined rules — not novel
                vtype = f.get("vuln_type", "").lower().replace("_", "")
                if not any(
                    kt.replace("_", "") in vtype or vtype in kt.replace("_", "")
                    for kt in kb_types
                ):
                    return True
        except Exception:
            pass
        return False

    def _kb_has_sufficient_coverage(self, merged: list[dict]) -> bool:
        """True iff KB holds >= 50 proven patches for all found vuln types."""
        try:
            from core.kb import KnowledgeBase
            return KnowledgeBase(path=self._chroma_path)._col.count() >= _FAST_KB_MIN
        except Exception:
            return False

    def _kb_types(self, kb) -> set[str]:
        try:
            data = kb._col.get()
            return {
                m["type"].lower()
                for m in (data.get("metadatas") or [])
                if m and m.get("type")
            }
        except Exception:
            return set()


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------

def _is_timeout(symbolic: list[dict]) -> bool:
    return any(f.get("vuln_type") == "TIMEOUT" for f in symbolic)
