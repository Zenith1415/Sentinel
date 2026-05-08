---
name: Self-Healing Contracts Phase 5 Complete
description: Phase 5 (5-gate validator) is complete. Validator class in core/validator.py, 7 tests in tests/test_phase5.py, all 28 tests pass.
type: project
---

Phases 0–5 of the self-healing smart contracts project are complete.

**Why:** Building an AI pipeline that detects Solidity vulnerabilities and auto-patches them with zero-tolerance validation before governance/deployment.

**How to apply:** Next phase is governance approval (node_governance in healing_graph.py) and deployment via UUPS proxy.

Phase 5 delivered:
- `core/validator.py`: `Validator` class with `validate_all(state) -> state`
- 5 gates run in parallel (ThreadPoolExecutor) per candidate:
  - Gate 1: Re-run StaticAnalysisAgent/GovernanceMonitorAgent; no original Critical/High vulns remain (RL +0.3)
  - Gate 2: solcx compilation (import-resolution errors are tolerated as tooling issues)
  - Gate 3: Regex-based public/external function signature extraction and comparison
  - Gate 4: ChromaDB rejected_patches cosine similarity < 0.85 threshold
  - Gate 5: forge test → Echidna → static simulation fallback (RL +0.8)
- Ranking: gas (0.3) + semantic similarity (0.3) + RL score (0.2) + bytecode diff (0.2)
- Retry: retry_count increments on all-fail; route="slow" + human escalation at retry_count≥3
- All candidates (pass+fail) stored in KB with gate_results metadata
