# Self-Healing Smart Contracts — Project Handoff

Paste this whole document into Claude web to continue or extend the project.

---

## 1. What this project does

An autonomous pipeline that detects vulnerabilities in Solidity contracts, generates patch candidates, validates them through 5 gates, and deploys via UUPS proxy upgrade — with auto-rollback on post-deploy anomalies.

**Architecture (8 layers)**

| Layer | Purpose |
|---|---|
| 0 — Intelligence | Web Intel agent + Threat KB (ChromaDB) + RL agent (PPO, 3-phase rollout) |
| 1 — Event bus | Redis Streams: `contract.submitted` → `detection.complete` → `correlation.complete` → … → `monitor.anomaly` |
| 2 — Detection | 5 parallel agents: Static (Slither + regex), Symbolic (Mythril), LLM Semantic, Governance Monitor, Threat Pattern (KB similarity) |
| 3 — Correlation + Routing | Quorum gate, conflict detection, tiered routing: FAST / MEDIUM / SLOW |
| 4 — Repair | MasterPatchAgent generates 3 candidates in parallel: proven-KB, experimental-KB, pure LLM |
| 5 — Validation | 5 gates per candidate in parallel: vuln removed, compiles, signatures, KB bad-fix, fuzzing |
| 6 — Deploy + rollback | UUPS proxy upgrade, baseline snapshot, post-deploy monitor, auto-rollback on anomaly |
| 7 — Observability | Dashboard panels: live pipeline, threat feed, RL phase, diff viewer, rollback history, KB health, audit trail, **scope boundary alerts** |

---

## 2. Stack

- **Backend** — Python 3.14, FastAPI, LangGraph, ChromaDB, Motor (MongoDB Atlas), web3.py
- **LLMs** — Backboard.io (primary, unified gateway) → Gemma 4 via Ollama (local, gemma4:e2b) → Google Gemini (fallback chain, per-call)
- **Tracing** — LangSmith with live SSE streaming of prompts + responses to the dashboard
- **Frontend** — React + Vite, EventSource SSE, Recharts
- **Smart contracts** — Solidity 0.8.22, Hardhat, OpenZeppelin upgradeable contracts
- **Tests** — pytest, 46 passing

---

## 3. The three reference contracts

### `contracts/VulnerableVault.sol` — auto-patchable demo
| Vuln | Function | Severity |
|---|---|---|
| Reentrancy (`.call` before state update) | `withdraw()` | Critical |
| Missing access control | `setOwner()` | Critical |

→ Pipeline routes **MEDIUM** at ~91.7% confidence, generates 3 candidates, all 5 gates run, deploys.

### `contracts/UnpatchableVault.sol` — designed to defeat auto-patch
| # | Vuln class | Why auto-patch fails |
|---|---|---|
| 1 | Cross-contract reentrancy (VaultA→B→C→A triangle) | `nonReentrant` only locks current contract; re-entry from sibling still drains |
| 2 | Public initializer + governance reentrancy | Fix breaks proxy upgradability; LLM can't classify intent of `verify()` call |
| 3 | Oracle manipulation + unchecked arithmetic + timestamp | Any fix rewrites >40% of function → diff threshold flagged |
| 4 | Delegatecall storage collision (slot 0 across 3 contracts) | Coordinated fix across 3 separate-file contracts — out of single-file scope |
| 5 | Flash-loan callback reentrancy (ERC-3156) | nonReentrant breaks ERC-3156; removing callback breaks interface; balance fix exceeds diff cap |
| 6 | Selfdestruct + 1-token governance | Removing selfdestruct breaks recovery; fixing governance is multi-contract |

→ Pipeline routes **SLOW** at ~34.5% confidence, escalates to ScopeBoundaryAlert + HumanReview panels.

### `contracts/SafeVault.sol` — reference safe contract (0 vulns)
Every weakness from the above two has a fix:

| Defense | Mechanism |
|---|---|
| Reentrancy | CEI pattern + `nonReentrant` on every ETH-transferring fn |
| Public initializer | `onlyInitializing` modifier + `_initialized` set first |
| Ownership hijack | Two-step transfer (`transferOwnership` → `acceptOwnership`) |
| Oracle manipulation | Chainlink `latestRoundData()` + staleness check (3600s) + zero/negative-price guard, no `unchecked` |
| Delegatecall collision | No `delegatecall` anywhere |
| Flash-loan bypass | Pre-loan stack snapshot for repayment check + `nonReentrant` |
| Selfdestruct | No `selfdestruct` anywhere |
| Weak governance | 2-of-N multisig + 2-day timelock + queued action hash |
| Stray ETH | `receive()` reverts — must enter through `deposit()` |

→ Pipeline routes **FAST** at 95% confidence, no findings → skips patch/validate (clean exit), `healed=True`.

---

## 4. Routing logic (`graph/correlation.py`)

```
confidence < 0.30                     → SLOW
cross_contract OR novel + conf < 0.65 → SLOW
TVL > $1M                             → SLOW
no findings                           → FAST (skip patch — clean exit)
no Critical findings + conf >= 0.75 + KB has 5+ entries → FAST
otherwise                             → MEDIUM
```

Critical-severity findings can never go FAST — they always go through full validation gates.

---

## 5. Dashboard panels (`dashboard/src/components/`)

| Panel | Purpose |
|---|---|
| `PipelineVisualizer` | Node-by-node pipeline progress with rollback button |
| `FindingsTable` | Click-to-expand findings with agent attribution, evidence, fix recommendation, cross-contract flag explanation |
| `DiffViewer` | 3-candidate side-by-side diff against original |
| `GateResults` | 5 gates pass/fail per candidate |
| `DeployStatus` | tx_hash, rollback_target, rollback history |
| `KbHealth` | ChromaDB partition counts, stale entries |
| `TraceViewer` | LangSmith spans with **live polling** during run + click-to-expand prompt + response per LLM call |
| `StatsBar` | Aggregate pipeline counts (total / success rate / rollbacks / avg confidence) |
| `RLLearningCurve` | Recharts line of RL reward over phase transitions (sim/shadow/live) |
| `ScopeBoundaryAlert` | Red panel when route=slow — explains slow_path / retry_exhaustion / novel_pattern alerts |
| `HumanReview` | When slow path: list findings, edit manual patch, 2-of-2 approver fields, deploy button → `POST /pipeline/{id}/manual-deploy` |
| `CliConsole` | Live CLI-style event stream with timestamps, color codes per node, expanded sub-events (per-agent counts, per-gate names, deploy artifacts) |

---

## 6. Key files

```
api/main.py                        FastAPI + SSE + manual-deploy + scope-alerts endpoints
graph/healing_graph.py             LangGraph 9-node pipeline (detect/correlate/route/patch/validate/deploy/monitor/slow_path/clean)
graph/correlation.py               Tiered routing: FAST/MEDIUM/SLOW
agents/static_agent.py             Slither + regex (reentrancy, access control, delegatecall, selfdestruct, multi-contract)
agents/symbolic_agent.py           Mythril (graceful skip when not installed)
agents/semantic_agent.py           LLM analysis via core/llm.py
agents/governance_agent.py         Pattern matching + LLM
agents/threat_pattern_agent.py     KB similarity (filtered to ≥0.55 confidence)
agents/patch_agent.py              3 parallel candidates with 60s LLM timeout + fallback no-patch
core/llm.py                        Provider factory: Backboard → Ollama (gemma4:e2b, local) → Google with runtime fallback chain
core/backboard_llm.py              LangChain-compatible wrapper for Backboard.io API
core/validator.py                  5 gates, retry logic, escalation after 3 failures
core/monitor.py                    Post-deploy anomaly detection + auto-rollback
deploy/deployer.py                 UUPS proxy upgrade + simulated_deploy fallback when no chain
contracts/VulnerableVault.sol      2 vulns — auto-patchable
contracts/UnpatchableVault.sol     6 vuln classes + multi-contract architecture
contracts/SafeVault.sol            Reference safe contract
scripts/demo_all.py                CLI demo runner — shows every layer for every contract
scripts/check_routing.py           Quick routing sanity check
scripts/diagnose.py                Per-agent finding breakdown
scripts/deploy_vault.js            Hardhat deploy for VulnerableVault + UUPSProxy
scripts/deploy_unpatchable.js      Hardhat deploy for UnpatchableVault + 6 supporting contracts
tests/test_unpatchable.py          6 tests proving SLOW path always (route, healed=False, cross-contract, retry, scope-alert)
```

---

## 7. Environment

```env
# .env (do not commit)
BACKBOARD_API_KEY=espr_...
BACKBOARD_ASSISTANT_PATCH=          # optional: separate Backboard assistants per agent
BACKBOARD_ASSISTANT_SEMANTIC=        # to spread rate-limit budget
BACKBOARD_ASSISTANT_GOVERNANCE=
GOOGLE_API_KEY=AIza...               # fallback (currently quota-exhausted)

# Gemma 4 via Ollama — local, free, enabled by default if Ollama is running.
# Install: https://ollama.com  →  ollama pull gemma4:e2b
OLLAMA_MODEL=gemma4:e2b
OLLAMA_BASE_URL=http://localhost:11434
# OLLAMA_DISABLE=1                  # set to skip the Ollama tier entirely

LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=lsv2_pt_...
LANGCHAIN_PROJECT=self-healing-contracts

MONGODB_URI=mongodb+srv://...
MONGODB_DB=self_healing_contracts
MONGODB_DB_NAME=self_healing_contracts

RPC_URL=http://127.0.0.1:8545
PRIVATE_KEY=0x...
CHROMA_PATH=./chroma_db
REDIS_URL=redis://localhost:6379
```

---

## 8. Running it

```powershell
# Terminal 1 — local chain
npx hardhat node

# Terminal 2 — deploy a contract
npx hardhat run scripts/deploy_vault.js --network localhost
# (copy the proxy address)

# Terminal 3 — backend
uv run uvicorn api.main:app --reload --port 8000

# Terminal 4 — dashboard
cd dashboard && npm run dev   # → http://localhost:3000

# CLI demo (any time)
uv run python scripts/demo_all.py            # all 3 contracts
uv run python scripts/demo_all.py SafeVault  # one contract
uv run python scripts/check_routing.py       # quick routing summary
```

In the dashboard:
1. Pick a preset: ⚡ VulnerableVault / 💀 UnpatchableVault / ✅ SafeVault
2. Paste the deployed proxy address
3. Click **▶ Heal**
4. Watch the **📟 Live Pipeline Console** stream every event
5. SafeVault → completes "verified safe" with no patches
   VulnerableVault → 3 candidates → 5 gates → deploy → monitor
   UnpatchableVault → escalates → ScopeBoundaryAlert + HumanReview panels appear → write manual patch + 2 approvers → deploy

---

## 9. What still needs work

- **Backboard credit gate** — free tier returns "purchase credits" message. Fallback chain handles it but production should add Backboard credits and configure per-agent assistants.
- **Mythril not installed locally** — symbolic agent gracefully returns []; install Mythril for full detection.
- **Real Echidna/Foundry fuzzing in gate 5** — currently a regex placeholder; wire up real fuzzers.
- **RL agent (Layer 0)** — schema exists but the PPO training loop isn't wired. Need simulation/shadow/live phase rollout.
- **Web Intel agent (Layer 0)** — feed ingestion + adversarial-LLM filter is stub.
- **Redis Streams (Layer 1)** — pipeline currently runs synchronously through LangGraph; the architecture spec calls for true event-bus orchestration.
- **Per-topic consumer-lag monitoring** — listed in v4 architecture, not yet implemented.
- **30-day clean watch + KB promotion** — patches don't get promoted from experimental → proven yet.
- **Echidna/Foundry property-test auto-generation** — referenced in Layer 5, not built.
- **Audit trail (Layer 7 Panel 7)** — immutable on-chain audit log isn't wired.

---

## 10. Test status

```
46 passing — core pipeline, correlation, routing, validation, deploy, monitor,
            FastAPI endpoints, SSE streaming, scope alerts, manual deploy,
            UnpatchableVault slow path enforcement
1 known flaky — test_phase4 timing assertion (150ms parallel async, sometimes
                exceeds on a busy machine; not related to logic)
```

---

## 11. Honest scope boundaries (per architecture spec)

> Production-credible for: single-contract patching of known vuln classes on upgradeable contracts.
> 
> Open problems explicitly acknowledged:
> 1. Cross-contract interaction reasoning — detected, flagged, **not patched**
> 2. Unverified contracts without source — detected, flagged, **not patched**
> 3. Goodhart's Law — mitigated by Gate 5 (fuzzing) dominance, not eliminated

The slow-path / human-review workflow exists exactly because the system knows when it's out of its depth. UnpatchableVault is the demonstration of this self-knowledge.
