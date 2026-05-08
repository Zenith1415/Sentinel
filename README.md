# Self-Healing Smart Contracts

An AI pipeline that automatically detects vulnerabilities in Solidity smart contracts, generates patches, validates them through a 5-gate gauntlet, deploys via UUPS proxy upgrade, and monitors post-deployment for anomalies — rolling back automatically if something goes wrong.

---

## How it works

```
VulnerableVault.sol
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│  DETECT  (5 agents run in parallel)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Static       │  │ Symbolic     │  │ LLM Semantic  │      │
│  │ (regex +     │  │ (Mythril,    │  │ (Gemini —     │      │
│  │  Slither)    │  │  90 s cap)   │  │  logic flaws) │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │ Governance   │  │ Threat       │                         │
│  │ (timelocks,  │  │ Pattern      │                         │
│  │  flash vote) │  │ (ChromaDB)   │                         │
│  └──────────────┘  └──────────────┘                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
                    CORRELATE & ROUTE
               (merge findings, confidence score,
                assign fast / medium / slow path)
                            │
                            ▼
                    PATCH  (3 candidates)
               proven KB  │  experimental  │  pure LLM
                            │
                            ▼
               VALIDATE  (5-gate, zero tolerance)
          Gate 1 — Vuln removed (re-run agents)
          Gate 2 — Compiles (solcx)
          Gate 3 — Function signatures preserved
          Gate 4 — KB bad-fix similarity < 0.85
          Gate 5 — Fuzzing / invariant tests (Echidna)
                            │
                            ▼
                    DEPLOY  (UUPS proxy upgrade)
               baseline snapshot → access-control check
               → compile → deploy impl → upgradeToAndCall
               → emit HealingComplete event
                            │
                            ▼
                    MONITOR  (100-block watch)
               gas spike / balance drift / revert spike
                   ├── clean target → auto-rollback
                   └── both anomalous → circuit-breaker freeze
```

---

## Project layout

```
.
├── agents/
│   ├── static_agent.py          # Regex heuristics + Slither
│   ├── symbolic_agent.py        # Mythril (90 s hard timeout)
│   ├── semantic_agent.py        # Gemini 2.0 Flash — logic flaws
│   ├── governance_agent.py      # Timelocks, flash-loan voting
│   ├── threat_pattern_agent.py  # ChromaDB KB similarity
│   └── patch_agent.py           # 3 candidates via async LLM
│
├── graph/
│   ├── state.py                 # HealingState TypedDict
│   ├── correlation.py           # CorrelationAgent (5-step merge)
│   ├── healing_graph.py         # LangGraph StateGraph
│   └── runner.py                # run_healing_pipeline() entry point
│
├── core/
│   ├── validator.py             # 5-gate Validator
│   ├── monitor.py               # PostDeployMonitor (anomaly + rollback)
│   ├── kb.py                    # ChromaDB knowledge base
│   └── event_bus.py             # Redis Streams event bus
│
├── deploy/
│   └── deployer.py              # DeployAgent (UUPS upgrade)
│
├── api/
│   └── main.py                  # FastAPI + SSE backend
│
├── dashboard/
│   └── src/                     # React frontend
│       ├── App.jsx
│       └── components/
│           ├── PipelineVisualizer.jsx
│           ├── FindingsTable.jsx
│           ├── DiffViewer.jsx
│           ├── GateResults.jsx
│           ├── DeployStatus.jsx
│           └── KbHealth.jsx
│
├── contracts/
│   └── VulnerableVault.sol      # Demo contract (intentionally vulnerable)
│
├── tests/                       # 46 tests across 8 phases
├── .env.example
├── hardhat.config.js
└── pyproject.toml
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | ≥ 3.14 | Pipeline runtime |
| uv | latest | Python package manager |
| Node.js | ≥ 20 | Hardhat (local blockchain) |
| Redis | 7+ | Event bus (optional for demo) |

---

## Setup

**1. Clone and install Python dependencies**

```bash
git clone <repo-url>
cd self-healing-contracts
uv sync
```

**2. Configure environment**

```bash
cp .env.example .env
```

Edit `.env`:

```env
GOOGLE_API_KEY=your_gemini_api_key    # https://aistudio.google.com
RPC_URL=http://127.0.0.1:8545         # Hardhat local node
PRIVATE_KEY=0xYOUR_DEPLOYER_KEY
REDIS_URL=redis://localhost:6379      # optional
CHROMA_PATH=./chroma_db
```

**3. Install Hardhat**

```bash
npm install
```

**4. Install dashboard dependencies**

```bash
cd dashboard && npm install
```

---

## Running the demo

**Terminal 1 — Local blockchain**

```bash
npx hardhat node
```

**Terminal 2 — API server**

```bash
uv run uvicorn api.main:app --reload
# → http://localhost:8000
```

**Terminal 3 — Dashboard**

```bash
cd dashboard && npm run dev
# → http://localhost:3000
```

**Terminal 4 — Trigger a heal**

```bash
curl -X POST http://localhost:8000/heal \
  -H "Content-Type: application/json" \
  -d '{
    "contract_source": "<paste VulnerableVault.sol contents>",
    "contract_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "tvl_estimate": 1000000
  }'
# Returns: {"pipeline_id": "...", "status": "started"}
```

Watch the pipeline animate in real time on the dashboard, or stream events directly:

```bash
curl -N http://localhost:8000/pipeline/<pipeline_id>/stream
```

---

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/heal` | Start a healing pipeline |
| `GET`  | `/pipeline/{id}` | Full state snapshot |
| `GET`  | `/pipeline/{id}/stream` | SSE — one event per LangGraph node |
| `GET`  | `/pipelines` | List all pipelines |
| `POST` | `/pipeline/{id}/pause` | Pause (requires 2 approvers) |
| `POST` | `/pipeline/{id}/force-rollback` | Immediate rollback (requires 2 approvers) |
| `GET`  | `/kb/health` | ChromaDB partition stats |

**Force rollback** requires two distinct approvers to prevent a single operator from reverting production:

```bash
curl -X POST http://localhost:8000/pipeline/<id>/force-rollback \
  -H "Content-Type: application/json" \
  -d '{"approver_1": "alice@example.com", "approver_2": "bob@example.com"}'
```

---

## Running tests

```bash
uv run pytest tests/ -v
```

```
tests/test_phase1.py   — Static analysis agent
tests/test_phase2.py   — Symbolic execution agent
tests/test_phase3.py   — Semantic + governance + threat agents
tests/test_phase4.py   — Correlation agent + patch generation
tests/test_phase5.py   — 5-gate validator
tests/test_phase6.py   — Deploy agent + post-deploy monitor
tests/test_phase7.py   — Full LangGraph pipeline
tests/test_phase8.py   — FastAPI endpoints + SSE stream

46 tests, all passing
```

---

## Dashboard panels

| Panel | What it shows |
|-------|--------------|
| Pipeline Visualizer | Each LangGraph node as a step — grey/blue/green/red. Pause and Force Rollback buttons with dual-approver gate |
| Findings Table | All agent findings sorted by severity with confidence scores |
| Diff Viewer | Side-by-side Original vs each candidate patch with line-level diff and per-gate badges |
| Gate Results | 5 gates as live-updating checkboxes |
| Deploy Status | Tx hash, rollback target, RL reward, full rollback history |
| KB Health | ChromaDB partition sizes, stale entry count, conflict count |

---

## Key design decisions

**Why 5 agents?**
Static tools miss business-logic flaws; LLMs miss deterministic byte-level patterns. Running both in parallel and correlating via quorum gives higher recall than either alone.

**Why LangGraph?**
The pipeline has conditional routing (fast/medium/slow path), retry loops (patch → validate → patch), and a clean state machine that maps directly to a `StateGraph`. `graph.stream()` makes SSE trivial.

**Why UUPS proxy?**
Upgradeability with owner-only upgrade guard. The `rollback_target` is the previous implementation address captured before upgrade — rollback is just another `upgradeToAndCall`.

**Why dual approver for rollback?**
A single compromised operator key cannot unilaterally revert production. Two signatures from distinct identities are required, matching the standard multi-sig security model.

**Why ChromaDB for the KB?**
Cosine similarity over patch embeddings lets Gate 4 catch semantically-similar bad fixes even when variable names differ, without maintaining a hand-curated list.

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_API_KEY` | Yes | Gemini API key for semantic + governance agents |
| `RPC_URL` | Yes | EVM RPC endpoint (Hardhat: `http://127.0.0.1:8545`) |
| `PRIVATE_KEY` | Yes | Deployer private key (hex with `0x` prefix) |
| `CHROMA_PATH` | No | Path for ChromaDB storage (default: `./chroma_db`) |
| `REDIS_URL` | No | Redis for event bus (default: `redis://localhost:6379`) |