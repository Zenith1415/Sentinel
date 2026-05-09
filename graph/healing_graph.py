"""
LangGraph healing pipeline:
  detect → correlate → route → patch → validate → deploy → monitor

Agents run in parallel inside detect_node via ThreadPoolExecutor.
build_healing_graph() accepts injectable components for testing.
"""
import asyncio as _asyncio
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from langgraph.graph import StateGraph, END

from graph.state import HealingState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Non-blocking DB helpers
# ---------------------------------------------------------------------------
# Motor binds its client to the event loop it is created in. We run a
# single persistent background loop so the motor client is always used
# in the same loop, and run_coroutine_threadsafe() submits writes without
# blocking the calling pipeline thread.
# ---------------------------------------------------------------------------

_db_loop: _asyncio.AbstractEventLoop | None = None
_db_loop_lock = threading.Lock()
_db_singleton = None
_db_singleton_lock = threading.Lock()


def _get_db_loop() -> _asyncio.AbstractEventLoop:
    """Return (or lazily start) the persistent background event loop for DB writes."""
    global _db_loop
    with _db_loop_lock:
        if _db_loop is None or _db_loop.is_closed():
            _db_loop = _asyncio.new_event_loop()
            threading.Thread(
                target=_db_loop.run_forever,
                daemon=True,
                name="db-event-loop",
            ).start()
    return _db_loop


def _get_db():
    """Return the Database singleton, always created inside the persistent DB loop."""
    global _db_singleton
    if _db_singleton is None:
        with _db_singleton_lock:
            if _db_singleton is None:
                try:
                    loop = _get_db_loop()

                    async def _init():
                        from core.database import Database
                        return Database()

                    future = _asyncio.run_coroutine_threadsafe(_init(), loop)
                    _db_singleton = future.result(timeout=10.0)
                except Exception as exc:
                    logger.debug("DB singleton init error: %s", exc)
    return _db_singleton


def _fire_db(coro) -> None:
    """Submit an async DB coroutine to the persistent DB event loop (non-blocking)."""
    try:
        _asyncio.run_coroutine_threadsafe(coro, _get_db_loop())
    except Exception as exc:
        logger.debug("_fire_db error: %s", exc)


# ---------------------------------------------------------------------------
# Agent field mapping (class name → HealingState field)
# ---------------------------------------------------------------------------

_AGENT_FIELD = {
    "StaticAnalysisAgent":   "static_findings",
    "SymbolicExecutionAgent": "symbolic_findings",
    "LLMSemanticAgent":      "semantic_findings",
    "SemanticAnalysisAgent": "semantic_findings",
    "GovernanceMonitorAgent": "governance_findings",
    "ThreatPatternAgent":    "threat_findings",
}


# ---------------------------------------------------------------------------
# Graph builder — accepts injectable components for testing
# ---------------------------------------------------------------------------

def build_healing_graph(
    agents=None,
    correlation_agent=None,
    patch_agent=None,
    validator=None,
    deploy_agent=None,
    monitor=None,
    chroma_path: str | None = None,
):
    """
    Compile and return the LangGraph StateGraph.

    All positional arguments are optional; defaults are lazy-instantiated
    so the module can be imported without requiring live credentials.
    """
    def _agents_():
        from agents.static_agent import StaticAnalysisAgent
        from agents.symbolic_agent import SymbolicExecutionAgent
        from agents.semantic_agent import LLMSemanticAgent
        from agents.governance_agent import GovernanceMonitorAgent
        from agents.threat_pattern_agent import ThreatPatternAgent
        return [
            StaticAnalysisAgent(),
            SymbolicExecutionAgent(),
            LLMSemanticAgent(),
            GovernanceMonitorAgent(),
            ThreatPatternAgent(),
        ]

    def _correlation_():
        from graph.correlation import CorrelationAgent
        return CorrelationAgent()

    def _patch_():
        from agents.patch_agent import MasterPatchAgent
        return MasterPatchAgent()

    def _validator_():
        from core.validator import Validator
        return Validator(chroma_path=chroma_path)

    def _deploy_():
        from deploy.deployer import DeployAgent
        return DeployAgent(chroma_path=chroma_path)

    def _monitor_():
        from core.monitor import PostDeployMonitor
        return PostDeployMonitor()

    _ag    = agents            if agents            is not None else _agents_()
    _corr  = correlation_agent if correlation_agent is not None else _correlation_()
    _patch = patch_agent       if patch_agent       is not None else _patch_()
    _val   = validator         if validator         is not None else _validator_()
    _dep   = deploy_agent      if deploy_agent      is not None else _deploy_()
    _mon   = monitor           if monitor           is not None else _monitor_()

    # -----------------------------------------------------------------------
    # Node functions (closures over injected components)
    # -----------------------------------------------------------------------

    def detect_node(state: HealingState) -> dict:
        """Run all detection agents in parallel; merge findings into state."""
        out: dict = {
            "static_findings":     [],
            "symbolic_findings":   [],
            "semantic_findings":   [],
            "governance_findings": [],
            "threat_findings":     [],
        }
        with ThreadPoolExecutor(max_workers=max(len(_ag), 1)) as exe:
            futures = {
                exe.submit(ag.run, state["contract_source"], state): ag
                for ag in _ag
            }
            for fut in as_completed(futures):
                ag = futures[fut]
                field = _AGENT_FIELD.get(type(ag).__name__, "static_findings")
                try:
                    out[field] = fut.result() or []
                except Exception as exc:
                    logger.warning("Agent %s raised: %s", type(ag).__name__, exc)

        db = _get_db()
        if db:
            pid = state.get("pipeline_id", "")
            pairs = (
                [(f, "static")     for f in out.get("static_findings", [])] +
                [(f, "symbolic")   for f in out.get("symbolic_findings", [])] +
                [(f, "semantic")   for f in out.get("semantic_findings", [])] +
                [(f, "governance") for f in out.get("governance_findings", [])] +
                [(f, "threat")     for f in out.get("threat_findings", [])]
            )

            async def _save_findings(pairs=pairs, pid=pid):
                for finding, meth in pairs:
                    f = dict(finding)
                    f.setdefault("methodology", meth)
                    await db.save_finding(f, pid)

            _fire_db(_save_findings())

        return out

    def correlate_node(state: HealingState) -> dict:
        result = dict(_corr.correlate(state))
        db = _get_db()
        if db:
            merged = {**state, **result}
            _fire_db(db.save_pipeline(merged))
        return result

    def route_node(state: HealingState) -> dict:
        return {}

    def patch_node(state: HealingState) -> dict:
        result = _patch.generate(state)
        patches = result.get("candidate_patches", [])
        db = _get_db()
        if db:
            pid = state.get("pipeline_id", "")

            async def _save_patches(patches=patches, pid=pid):
                for p in patches:
                    await db.save_patch(p, pid)

            _fire_db(_save_patches())
        return {"candidate_patches": patches}

    def validate_node(state: HealingState) -> dict:
        result = _val.validate_all(state)
        db = _get_db()
        if db:
            pid         = state.get("pipeline_id", "")
            gate_results = result.get("gate_results", {})
            _fire_db(db.update_pipeline(pid, {"gate_results": gate_results}))
        return {
            "selected_patch":    result.get("selected_patch", ""),
            "gate_results":      result.get("gate_results", {}),
            "validation_passed": result.get("validation_passed", False),
            "retry_count":       result.get("retry_count", state.get("retry_count", 0)),
            "route":             result.get("route", state.get("route", "medium")),
            "error":             result.get("error", ""),
        }

    def deploy_node(state: HealingState) -> dict:
        result = _dep.deploy(state)
        db = _get_db()
        if db:
            pid = state.get("pipeline_id", "")
            _fire_db(db.update_pipeline(pid, {
                "deployed": result.get("deployed", False),
                "tx_hash":  result.get("tx_hash", ""),
                "healed":   result.get("healed", False),
            }))
        return {
            "deployed":         result.get("deployed", False),
            "tx_hash":          result.get("tx_hash", ""),
            "rollback_target":  result.get("rollback_target", ""),
            "healed":           result.get("healed", False),
            "baseline_metrics": result.get("baseline_metrics", {}),
            "error":            result.get("error", ""),
        }

    def monitor_node(state: HealingState) -> dict:
        result = _mon.watch(state, duration_blocks=10)
        db = _get_db()
        if db:
            pid       = state.get("pipeline_id", "")
            rl_reward = result.get("rl_reward", state.get("rl_reward", 0.0))

            _fire_db(db.save_rl_reward({
                "pipeline_id": pid,
                "gate":        "monitor",
                "reward":      rl_reward,
                "cumulative":  rl_reward,
                "phase":       "live",
            }))

            # Detect rollback: deployed flipped False while it was True
            was_deployed = state.get("deployed", False)
            now_deployed = result.get("deployed", was_deployed)
            if was_deployed and not now_deployed:
                _fire_db(db.save_rollback_event({
                    "pipeline_id":      pid,
                    "contract_address": state.get("contract_address", ""),
                    "rollback_target":  state.get("rollback_target", ""),
                    "trigger_reason":   result.get("error", "anomaly detected"),
                    "anomaly_type":     "gas_spike_or_revert",
                    "tx_hash":          state.get("tx_hash", ""),
                }))

            _fire_db(db.update_pipeline(pid, {
                "rl_reward": rl_reward,
                "healed":    result.get("healed", state.get("healed", False)),
            }))

        return {
            "rl_reward": result.get("rl_reward", state.get("rl_reward", 0.0)),
            "deployed":  result.get("deployed", state.get("deployed", False)),
            "healed":    result.get("healed",   state.get("healed",   False)),
            "error":     result.get("error",    state.get("error",    "")),
        }

    def slow_path_node(state: HealingState) -> dict:
        logger.warning(
            "Pipeline %s escalated to slow path — human review required",
            state.get("pipeline_id", ""),
        )
        return {
            "healed": False,
            "error":  state.get("error") or "Escalated to slow path: human review required",
        }

    def failed_node(state: HealingState) -> dict:
        logger.error(
            "Pipeline %s failed: %s",
            state.get("pipeline_id", ""),
            state.get("error", "unknown error"),
        )
        return {"healed": False}

    # -----------------------------------------------------------------------
    # Routing functions
    # -----------------------------------------------------------------------

    def _route_after_route(state: HealingState) -> str:
        # Slow → human review path (skip patching)
        if state.get("route") == "slow":
            return "slow_path"
        # No findings → contract is clean, no patches needed → straight to "clean"
        if not state.get("all_findings"):
            return "clean"
        return "patch"

    def clean_node(state: HealingState) -> dict:
        """Contract has no findings — nothing to patch. Skip to a clean exit
        with healed=True so the dashboard reflects 'verified safe'."""
        logger.info(
            "Pipeline %s: no findings detected — contract verified safe, no patches needed",
            state.get("pipeline_id", ""),
        )
        return {
            "healed":            True,
            "deployed":          False,   # nothing to deploy — contract unchanged
            "validation_passed": True,
            "selected_patch":    state.get("contract_source", ""),
            "gate_results":      {"no_patch_needed": True},
            "tx_hash":           "",
            "rollback_target":   "",
            "rl_reward":         1.0,     # max reward for clean verification
            "error":             "",
        }

    def _route_after_validate(state: HealingState) -> str:
        if state.get("validation_passed"):
            return "deploy"
        if state.get("retry_count", 0) >= 3:
            return "slow_path"
        return "patch"

    def _route_after_deploy(state: HealingState) -> str:
        return "monitor" if state.get("deployed") else "failed"

    # -----------------------------------------------------------------------
    # Assemble graph
    # -----------------------------------------------------------------------

    g = StateGraph(HealingState)

    g.add_node("detect",    detect_node)
    g.add_node("correlate", correlate_node)
    g.add_node("route",     route_node)
    g.add_node("patch",     patch_node)
    g.add_node("validate",  validate_node)
    g.add_node("deploy",    deploy_node)
    g.add_node("monitor",   monitor_node)
    g.add_node("slow_path", slow_path_node)
    g.add_node("failed",    failed_node)
    g.add_node("clean",     clean_node)

    g.set_entry_point("detect")
    g.add_edge("detect",    "correlate")
    g.add_edge("correlate", "route")

    g.add_conditional_edges(
        "route",
        _route_after_route,
        {"patch": "patch", "slow_path": "slow_path", "clean": "clean"},
    )

    g.add_edge("clean", END)

    g.add_edge("patch", "validate")

    g.add_conditional_edges(
        "validate",
        _route_after_validate,
        {"deploy": "deploy", "patch": "patch", "slow_path": "slow_path"},
    )

    g.add_conditional_edges(
        "deploy",
        _route_after_deploy,
        {"monitor": "monitor", "failed": "failed"},
    )

    g.add_edge("monitor",   END)
    g.add_edge("slow_path", END)
    g.add_edge("failed",    END)

    return g.compile()


# Module-level default graph — wrapped so the module remains importable
# even when external credentials (LLM keys, RPC) are unavailable.
try:
    healing_graph = build_healing_graph()
except Exception as _build_err:
    logger.debug("Default healing_graph not built at import time: %s", _build_err)
    healing_graph = None
