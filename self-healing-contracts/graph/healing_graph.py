"""
LangGraph healing pipeline:
  detect → correlate → route → patch → validate → deploy → monitor

Agents run in parallel inside detect_node via ThreadPoolExecutor.
build_healing_graph() accepts injectable components for testing.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from langgraph.graph import StateGraph, END

from graph.state import HealingState

logger = logging.getLogger(__name__)

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
        return out

    def correlate_node(state: HealingState) -> dict:
        return dict(_corr.correlate(state))

    def route_node(state: HealingState) -> dict:
        return {}

    def patch_node(state: HealingState) -> dict:
        result = _patch.generate(state)
        return {"candidate_patches": result.get("candidate_patches", [])}

    def validate_node(state: HealingState) -> dict:
        result = _val.validate_all(state)
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
        return "slow_path" if state.get("route") == "slow" else "patch"

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

    g.set_entry_point("detect")
    g.add_edge("detect",    "correlate")
    g.add_edge("correlate", "route")

    g.add_conditional_edges(
        "route",
        _route_after_route,
        {"patch": "patch", "slow_path": "slow_path"},
    )

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
