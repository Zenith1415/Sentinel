"""
FastAPI backend — REST + SSE interface to the self-healing pipeline.

Endpoints:
  POST /heal                          — start a pipeline
  GET  /pipeline/{id}                 — current state snapshot
  GET  /pipeline/{id}/stream          — SSE: one event per LangGraph node
  GET  /pipelines                     — list all pipeline summaries
  POST /pipeline/{id}/pause           — pause (requires 2 approvers)
  POST /pipeline/{id}/force-rollback  — immediate rollback (requires 2 approvers)
  GET  /kb/health                     — ChromaDB partition stats
"""
import asyncio
import json
import logging
import os
import threading
import time
import uuid
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App + CORS
# ---------------------------------------------------------------------------

app = FastAPI(title="Self-Healing Smart Contracts", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Per-pipeline registry
# ---------------------------------------------------------------------------

# pipeline_id → {
#   "state":    dict,          # latest merged HealingState
#   "status":   str,           # pending | running | complete | error | paused
#   "queue":    asyncio.Queue, # SSE events (put by background thread)
#   "approvals": set[str],     # collected approver identifiers
#   "paused":   bool,
#   "force_rollback": bool,
#   "rollback_history": list[dict],
#   "error":    str,
# }
_pipelines: dict[str, dict] = {}

# Default graph factory — overridden by tests via app.state.graph_factory
def _default_graph_factory():
    from graph.healing_graph import build_healing_graph
    return build_healing_graph()


def _graph_factory():
    factory = getattr(app.state, "graph_factory", _default_graph_factory)
    return factory()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class HealRequest(BaseModel):
    contract_source: str
    contract_address: str
    tvl_estimate: float = 0.0


class ApproverRequest(BaseModel):
    approver_1: str
    approver_2: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_initial_state(req: HealRequest, pipeline_id: str) -> dict:
    return {
        "pipeline_id":         pipeline_id,
        "contract_source":     req.contract_source,
        "contract_address":    req.contract_address,
        "solidity_version":    "0.8.22",
        "tvl_estimate":        req.tvl_estimate,
        "static_findings":     [],
        "symbolic_findings":   [],
        "semantic_findings":   [],
        "governance_findings": [],
        "threat_findings":     [],
        "all_findings":        [],
        "confidence_score":    0.0,
        "route":               "medium",
        "conflict_flags":      [],
        "candidate_patches":   [],
        "selected_patch":      "",
        "gate_results":        {},
        "validation_passed":   False,
        "retry_count":         0,
        "deployed":            False,
        "tx_hash":             "",
        "rollback_target":     "",
        "rl_reward":           0.0,
        "healed":              False,
        "error":               "",
    }


def _json_safe(state: dict) -> dict:
    """Strip non-JSON-serialisable values (e.g. bytes, custom objects)."""
    out: dict = {}
    for k, v in state.items():
        try:
            json.dumps(v)
            out[k] = v
        except (TypeError, ValueError):
            out[k] = str(v)
    return out


def _pipeline_summary(pid: str, entry: dict) -> dict:
    s = entry.get("state") or {}
    return {
        "pipeline_id":  pid,
        "status":       entry.get("status", "pending"),
        "healed":       s.get("healed", False),
        "deployed":     s.get("deployed", False),
        "route":        s.get("route", ""),
        "findings":     len(s.get("all_findings", [])),
        "error":        entry.get("error", "") or s.get("error", ""),
    }


# ---------------------------------------------------------------------------
# Background pipeline runner (runs in thread executor)
# ---------------------------------------------------------------------------

def _stream_pipeline(pipeline_id: str, initial_state: dict, graph, loop: asyncio.AbstractEventLoop):
    """Run graph.stream() in a background thread; push SSE events to the queue."""
    entry = _pipelines[pipeline_id]
    queue: asyncio.Queue = entry["queue"]

    def _put(event: dict):
        loop.call_soon_threadsafe(queue.put_nowait, event)

    current: dict = dict(initial_state)

    try:
        entry["status"] = "running"
        for chunk in graph.stream(initial_state, stream_mode="updates"):
            # chunk = {node_name: update_dict}
            for node_name, update in chunk.items():
                if isinstance(update, dict):
                    current.update(update)

            # Persist merged state
            entry["state"] = dict(current)

            node_name = next(iter(chunk))
            _put({"node": node_name, "state": _json_safe(current)})

            # Honour pause
            while entry.get("paused"):
                if entry.get("status") == "cancelled":
                    _put({"node": "__cancelled__", "state": _json_safe(current)})
                    return
                time.sleep(0.05)

            # Honour force-rollback
            if entry.get("force_rollback"):
                entry["force_rollback"] = False
                _do_rollback(pipeline_id, current, _put)
                entry["status"] = "rolled_back"
                _put({"node": "__rollback__", "state": _json_safe(current)})
                return

        entry["status"] = "complete"
        _put({"node": "__done__", "state": _json_safe(current)})

    except Exception as exc:
        logger.exception("Pipeline %s crashed: %s", pipeline_id, exc)
        entry["status"] = "error"
        entry["error"] = str(exc)
        _put({"node": "__error__", "error": str(exc), "state": _json_safe(current)})


def _do_rollback(pipeline_id: str, state: dict, put_fn):
    """Execute rollback via PostDeployMonitor and record history."""
    entry = _pipelines[pipeline_id]
    rollback_target = state.get("rollback_target", "")
    proxy_address   = state.get("contract_address", "")
    ts = time.time()

    try:
        from core.monitor import PostDeployMonitor
        mon = PostDeployMonitor()
        mon._perform_rollback(state, [{"type": "forced_rollback", "severity": "high"}])
    except Exception as exc:
        logger.warning("Rollback execution error: %s", exc)

    entry["rollback_history"].append({
        "timestamp":       ts,
        "rollback_target": rollback_target,
        "proxy_address":   proxy_address,
        "triggered_by":    "force_rollback_api",
    })
    state["deployed"] = False
    state["healed"]   = False
    state["error"]    = "Force-rollback executed by operator"
    put_fn({"node": "RollbackTriggered", "state": _json_safe(state)})


# ---------------------------------------------------------------------------
# POST /heal
# ---------------------------------------------------------------------------

@app.post("/heal", status_code=202)
async def start_healing(req: HealRequest):
    pipeline_id = str(uuid.uuid4())
    initial_state = _make_initial_state(req, pipeline_id)

    loop = asyncio.get_event_loop()
    entry: dict = {
        "state":           dict(initial_state),
        "status":          "pending",
        "queue":           asyncio.Queue(),
        "approvals":       set(),
        "paused":          False,
        "force_rollback":  False,
        "rollback_history": [],
        "error":           "",
    }
    _pipelines[pipeline_id] = entry

    graph = _graph_factory()

    # Run streaming in background thread
    loop.run_in_executor(
        None,
        _stream_pipeline,
        pipeline_id,
        initial_state,
        graph,
        loop,
    )

    return {"pipeline_id": pipeline_id, "status": "started"}


# ---------------------------------------------------------------------------
# GET /pipeline/{id}
# ---------------------------------------------------------------------------

@app.get("/pipeline/{pipeline_id}")
async def get_pipeline(pipeline_id: str):
    entry = _pipelines.get(pipeline_id)
    if entry is None:
        raise HTTPException(404, f"Pipeline {pipeline_id!r} not found")

    s = entry.get("state") or {}
    return {
        **_json_safe(s),
        "status":           entry["status"],
        "rollback_history": entry["rollback_history"],
        "paused":           entry["paused"],
    }


# ---------------------------------------------------------------------------
# GET /pipeline/{id}/stream  (SSE)
# ---------------------------------------------------------------------------

@app.get("/pipeline/{pipeline_id}/stream")
async def stream_pipeline(pipeline_id: str):
    entry = _pipelines.get(pipeline_id)
    if entry is None:
        raise HTTPException(404, f"Pipeline {pipeline_id!r} not found")

    queue: asyncio.Queue = entry["queue"]

    async def _event_gen() -> AsyncIterator[dict]:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                yield {"event": "ping", "data": "{}"}
                continue

            data = json.dumps(event)
            yield {"event": "node_complete", "data": data}

            node = event.get("node", "")
            if node in ("__done__", "__error__", "__cancelled__", "__rollback__"):
                break

    return EventSourceResponse(_event_gen())


# ---------------------------------------------------------------------------
# GET /pipelines
# ---------------------------------------------------------------------------

@app.get("/pipelines")
async def list_pipelines():
    return [_pipeline_summary(pid, entry) for pid, entry in _pipelines.items()]


# ---------------------------------------------------------------------------
# POST /pipeline/{id}/pause
# ---------------------------------------------------------------------------

@app.post("/pipeline/{pipeline_id}/pause")
async def pause_pipeline(pipeline_id: str, body: ApproverRequest):
    entry = _pipelines.get(pipeline_id)
    if entry is None:
        raise HTTPException(404, f"Pipeline {pipeline_id!r} not found")

    a1 = body.approver_1.strip()
    a2 = body.approver_2.strip()
    if not a1 or not a2:
        raise HTTPException(422, "Both approver_1 and approver_2 are required")
    if a1 == a2:
        raise HTTPException(422, "approver_1 and approver_2 must be different people")

    entry["paused"] = True
    entry["status"] = "paused"
    entry["approvals"].update({a1, a2})

    return {"pipeline_id": pipeline_id, "status": "paused", "approvers": [a1, a2]}


# ---------------------------------------------------------------------------
# POST /pipeline/{id}/force-rollback
# ---------------------------------------------------------------------------

@app.post("/pipeline/{pipeline_id}/force-rollback")
async def force_rollback(pipeline_id: str, body: ApproverRequest):
    entry = _pipelines.get(pipeline_id)
    if entry is None:
        raise HTTPException(404, f"Pipeline {pipeline_id!r} not found")

    a1 = body.approver_1.strip()
    a2 = body.approver_2.strip()

    if not a1 or not a2:
        raise HTTPException(403, "Two approvers required for force-rollback")
    if a1 == a2:
        raise HTTPException(403, "approver_1 and approver_2 must be different people")

    entry["force_rollback"] = True
    entry["approvals"].update({a1, a2})

    # If the pipeline has already completed, execute rollback directly
    if entry["status"] in ("complete", "error", "rolled_back"):
        current = entry.get("state") or {}

        loop = asyncio.get_event_loop()

        def _put(event: dict):
            loop.call_soon_threadsafe(entry["queue"].put_nowait, event)

        _do_rollback(pipeline_id, current, _put)
        entry["state"] = dict(current)
        entry["status"] = "rolled_back"

    return {
        "pipeline_id": pipeline_id,
        "status":      "rollback_initiated",
        "approvers":   [a1, a2],
    }


# ---------------------------------------------------------------------------
# GET /kb/health
# ---------------------------------------------------------------------------

@app.get("/kb/health")
async def kb_health():
    chroma_path = os.getenv("CHROMA_PATH", "./chroma_db")
    try:
        import chromadb
        client = chromadb.PersistentClient(path=chroma_path)

        collections = ["proven_patches", "rejected_patches", "vuln_patterns"]
        sizes: dict[str, int] = {}
        for name in collections:
            try:
                col = client.get_or_create_collection(name)
                sizes[name] = col.count()
            except Exception:
                sizes[name] = 0

        total = sum(sizes.values())

        # Rough stale-entry estimate: any entry with distance > 1.8 from centroid
        stale_count = 0
        conflict_count = 0
        try:
            proven_col = client.get_or_create_collection("proven_patches")
            if proven_col.count() > 0:
                results = proven_col.query(
                    query_texts=["reentrancy access control overflow"],
                    n_results=min(10, proven_col.count()),
                )
                dists = results.get("distances", [[]])[0]
                stale_count  = sum(1 for d in dists if d > 1.8)
                conflict_count = sum(1 for d in dists if 0.3 < d < 0.6)
        except Exception:
            pass

        return {
            "status":        "ok",
            "chroma_path":   chroma_path,
            "partitions":    sizes,
            "total_entries": total,
            "stale_count":   stale_count,
            "conflict_count": conflict_count,
            "ttl_days":      30,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# GET /health  (liveness probe)
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"ok": True, "version": "2.0.0"}
