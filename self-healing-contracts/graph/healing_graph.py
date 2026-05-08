"""
LangGraph pipeline: detect → aggregate → patch → validate → govern → deploy
"""
from langgraph.graph import StateGraph, END

from graph.state import HealingState
from agents.static_agent import run_static_analysis
from agents.symbolic_agent import run_symbolic_analysis
from agents.semantic_agent import run_semantic_analysis
from agents.threat_pattern_agent import run_threat_pattern_analysis
from agents.governance_agent import run_governance_review
from core.validator import run_validation_gates
from deploy.deployer import deploy_upgrade


# ---------------------------------------------------------------------------
# Node functions
# ---------------------------------------------------------------------------

def node_static(state: HealingState) -> HealingState:
    return {**state, "static_findings": run_static_analysis(state["contract_source"])}


def node_symbolic(state: HealingState) -> HealingState:
    return {**state, "symbolic_findings": run_symbolic_analysis(state["contract_source"])}


def node_semantic(state: HealingState) -> HealingState:
    return {**state, "semantic_findings": run_semantic_analysis(state["contract_source"])}


def node_threat_patterns(state: HealingState) -> HealingState:
    return {**state, "threat_patterns": run_threat_pattern_analysis(state["contract_source"])}


def node_aggregate(state: HealingState) -> HealingState:
    all_findings = (
        state.get("static_findings", [])
        + state.get("symbolic_findings", [])
        + state.get("semantic_findings", [])
        + state.get("threat_patterns", [])
    )
    # Deduplicate by (type, location)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["type"], f["location"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return {**state, "all_findings": unique}


def node_patch(state: HealingState) -> HealingState:
    from agents.semantic_agent import generate_patch
    patched, diff = generate_patch(state["contract_source"], state["all_findings"])
    return {**state, "patched_source": patched, "patch_diff": diff}


def node_validate(state: HealingState) -> HealingState:
    gates = run_validation_gates(state.get("patched_source", ""))
    return {
        **state,
        "gate_syntax_ok": gates["syntax"],
        "gate_tests_ok": gates["tests"],
        "gate_slither_ok": gates["slither"],
        "gate_gas_ok": gates["gas"],
    }


def node_governance(state: HealingState) -> HealingState:
    approved, notes = run_governance_review(state)
    return {
        **state,
        "governance_approved": approved,
        "governance_notes": notes,
        "gate_governance_ok": approved,
        "status": "awaiting_governance" if not approved else state["status"],
    }


def node_deploy(state: HealingState) -> HealingState:
    try:
        addr, tx = deploy_upgrade(
            state["contract_address"],
            state["patched_source"],
        )
        return {
            **state,
            "new_implementation_address": addr,
            "upgrade_tx_hash": tx,
            "status": "healed",
        }
    except Exception as e:
        return {**state, "deploy_error": str(e), "status": "failed"}


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def route_after_validate(state: HealingState) -> str:
    gates_ok = all([
        state.get("gate_syntax_ok"),
        state.get("gate_tests_ok"),
        state.get("gate_slither_ok"),
        state.get("gate_gas_ok"),
    ])
    if not gates_ok:
        if state.get("iteration", 0) >= state.get("max_iterations", 3):
            return "fail"
        return "retry_patch"
    return "governance"


def route_after_governance(state: HealingState) -> str:
    return "deploy" if state.get("governance_approved") else "fail"


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

def build_healing_graph() -> StateGraph:
    g = StateGraph(HealingState)

    # Detection nodes (run in parallel conceptually; LangGraph executes sequentially)
    g.add_node("static", node_static)
    g.add_node("symbolic", node_symbolic)
    g.add_node("semantic", node_semantic)
    g.add_node("threat_patterns", node_threat_patterns)
    g.add_node("aggregate", node_aggregate)
    g.add_node("patch", node_patch)
    g.add_node("validate", node_validate)
    g.add_node("governance", node_governance)
    g.add_node("deploy", node_deploy)

    g.set_entry_point("static")
    g.add_edge("static", "symbolic")
    g.add_edge("symbolic", "semantic")
    g.add_edge("semantic", "threat_patterns")
    g.add_edge("threat_patterns", "aggregate")
    g.add_edge("aggregate", "patch")
    g.add_edge("patch", "validate")

    g.add_conditional_edges(
        "validate",
        route_after_validate,
        {"governance": "governance", "retry_patch": "patch", "fail": END},
    )
    g.add_conditional_edges(
        "governance",
        route_after_governance,
        {"deploy": "deploy", "fail": END},
    )
    g.add_edge("deploy", END)

    return g.compile()


healing_graph = build_healing_graph()
