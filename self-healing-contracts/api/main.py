"""
FastAPI backend — REST interface to the healing pipeline.
"""
import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional

from graph.healing_graph import healing_graph
from graph.state import HealingState

app = FastAPI(title="Self-Healing Smart Contracts", version="0.1.0")

_runs: dict[str, dict] = {}


class HealRequest(BaseModel):
    contract_source: str
    contract_address: Optional[str] = None
    max_iterations: int = 3


class HealResponse(BaseModel):
    run_id: str
    status: str


@app.post("/heal", response_model=HealResponse)
async def start_healing(req: HealRequest, background: BackgroundTasks):
    import uuid
    run_id = str(uuid.uuid4())
    initial_state = HealingState(
        contract_source=req.contract_source,
        contract_address=req.contract_address,
        static_findings=[],
        symbolic_findings=[],
        semantic_findings=[],
        threat_patterns=[],
        all_findings=[],
        patched_source=None,
        patch_diff=None,
        governance_approved=False,
        governance_notes="",
        gate_syntax_ok=False,
        gate_tests_ok=False,
        gate_slither_ok=False,
        gate_gas_ok=False,
        gate_governance_ok=False,
        new_implementation_address=None,
        upgrade_tx_hash=None,
        deploy_error=None,
        iteration=0,
        max_iterations=req.max_iterations,
        status="running",
    )
    _runs[run_id] = {"status": "running", "state": None}
    background.add_task(_run_pipeline, run_id, initial_state)
    return HealResponse(run_id=run_id, status="running")


async def _run_pipeline(run_id: str, state: HealingState):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, healing_graph.invoke, state)
    _runs[run_id] = {"status": result["status"], "state": result}


@app.get("/status/{run_id}")
async def get_status(run_id: str):
    if run_id not in _runs:
        raise HTTPException(404, "Run not found")
    run = _runs[run_id]
    return {
        "run_id": run_id,
        "status": run["status"],
        "findings_count": len((run.get("state") or {}).get("all_findings", [])),
        "upgrade_tx": (run.get("state") or {}).get("upgrade_tx_hash"),
        "new_impl": (run.get("state") or {}).get("new_implementation_address"),
    }


@app.get("/health")
async def health():
    return {"ok": True}
