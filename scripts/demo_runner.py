"""
demo_runner.py — Orchestrated 7-step demo with colored terminal output.

Usage:
    python scripts/demo_runner.py
    python scripts/demo_runner.py --api http://localhost:8000 --tvl 5000000

Prerequisites (run before this script):
    1. npx hardhat node
    2. uv run uvicorn api.main:app --reload
    3. npx hardhat run scripts/deploy_vault.js --network localhost
"""
import argparse
import json
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

# ── ANSI colours ─────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"

SEP    = f"{DIM}{'─' * 62}{RESET}"

NODE_COLOR = {
    "detect":            BLUE,
    "correlate":         BLUE,
    "route":             BLUE,
    "patch":             CYAN,
    "validate":          CYAN,
    "deploy":            GREEN,
    "monitor":           GREEN,
    "__done__":          GREEN,
    "RollbackTriggered": RED,
    "__rollback__":      RED,
    "__error__":         RED,
}


# ── Prerequisites ─────────────────────────────────────────────────────────────

def check_hardhat() -> bool:
    try:
        r = requests.post(
            "http://127.0.0.1:8545",
            json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
            timeout=3,
        )
        block = int(r.json()["result"], 16)
        print(f"  {GREEN}✓{RESET} Hardhat node running — block #{block}")
        return True
    except Exception as e:
        print(f"  {RED}✗{RESET} Hardhat node not reachable: {e}")
        print(f"    Run: {CYAN}npx hardhat node{RESET}")
        return False


def check_api(api_base: str) -> bool:
    try:
        r = requests.get(f"{api_base}/health", timeout=3)
        assert r.json().get("ok")
        print(f"  {GREEN}✓{RESET} API server running at {api_base}")
        return True
    except Exception as e:
        print(f"  {RED}✗{RESET} API server not reachable: {e}")
        print(f"    Run: {CYAN}uv run uvicorn api.main:app --reload{RESET}")
        return False


def read_deployment(root: Path) -> dict | None:
    p = root / "artifacts" / "demo_deployment.json"
    if not p.exists():
        print(f"  {RED}✗{RESET} {p} not found")
        print(f"    Run: {CYAN}npx hardhat run scripts/deploy_vault.js --network localhost{RESET}")
        return None
    data = json.loads(p.read_text())
    print(f"  {GREEN}✓{RESET} Deployment: proxy {data['proxyAddress']}")
    return data


# ── SSE streaming (raw parser — no external sseclient dep) ────────────────────

def iter_sse(url: str, timeout: int = 120):
    """Yield parsed JSON event dicts from an SSE endpoint."""
    with requests.get(
        url,
        stream=True,
        headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
        timeout=timeout,
    ) as resp:
        buf = None
        for line in resp.iter_lines(decode_unicode=True):
            if line.startswith("data:"):
                buf = line[5:].strip()
            elif line == "" and buf:
                try:
                    yield json.loads(buf)
                except json.JSONDecodeError:
                    pass
                buf = None


# ── Pipeline streaming with pretty output ────────────────────────────────────

def stream_pipeline(api_base: str, pipeline_id: str, stop_nodes: tuple) -> dict:
    url = f"{api_base}/pipeline/{pipeline_id}/stream"
    final_state: dict = {}

    for event in iter_sse(url):
        node  = event.get("node", "")
        state = event.get("state", {})
        color = NODE_COLOR.get(node, RESET)

        if node == "detect":
            # all_findings is populated AFTER correlate/dedup. At the detect
            # event boundary it can still be empty while per-agent arrays
            # already hold raw findings. Sum the per-agent counts to avoid
            # the "0 total / 8 per-agent" contradiction.
            n = sum(len(state.get(f"{a}_findings", []))
                    for a in ("static", "symbolic", "semantic", "governance", "threat"))
            print(f"  {color}[detect    ]{RESET} {n} findings detected across 5 agents")

        elif node == "correlate":
            route = state.get("route", "?")
            score = state.get("confidence_score", 0.0)
            route_col = RED if route == "slow" else GREEN
            print(f"  {color}[correlate ]{RESET} route={route_col}{route}{RESET}  "
                  f"confidence={score:.0%}")

        elif node == "route":
            pass  # passthrough, nothing useful to print

        elif node == "patch":
            n = len(state.get("candidate_patches", []))
            strats = [c.get("strategy", "?") for c in state.get("candidate_patches", [])]
            print(f"  {color}[patch     ]{RESET} {n} candidates: {', '.join(strats)}")

        elif node == "validate":
            # On success the validator copies the winning candidate's gates
            # to top-level `gate_results`. On failure it doesn't, so fall
            # back to the first candidate's per-candidate gate_results so
            # the gate breakdown is visible in the failure case too.
            gates = state.get("gate_results") or {}
            if not gates:
                cands = state.get("candidate_patches", [])
                if cands:
                    gates = cands[0].get("gate_results", {}) or {}
            passed = sum(1 for v in gates.values() if v)
            total  = len(gates)
            ok_str = (f"{GREEN}PASS{RESET}" if state.get("validation_passed")
                      else f"{RED}FAIL{RESET}")
            print(f"  {color}[validate  ]{RESET} {passed}/{total} gates {ok_str}")
            labels = {
                "gate1": "Vuln removed",
                "gate2": "Compiles",
                "gate3": "Signatures",
                "gate4": "KB check",
                "gate5": "Fuzzing",
            }
            for g, v in gates.items():
                icon = f"{GREEN}✓{RESET}" if v else f"{RED}✗{RESET}"
                print(f"               {icon} {labels.get(g, g)}")

        elif node == "deploy":
            tx   = state.get("tx_hash", "")
            rb   = state.get("rollback_target", "")
            print(f"  {color}[deploy    ]{RESET} tx_hash:        {tx[:20]}…")
            print(f"               rollback_target: {rb[:20]}…")

        elif node == "monitor":
            print(f"  {color}[monitor   ]{RESET} post-deploy watch complete — no anomalies")

        elif node == "__done__":
            rl = state.get("rl_reward", 0.0)
            print(f"\n  {GREEN}{BOLD}✓ Pipeline complete{RESET}  "
                  f"rl_reward={GREEN}+{rl:.2f}{RESET}")
            final_state = state

        elif node == "RollbackTriggered":
            anomalies = event.get("anomalies", [])
            print(f"\n  {RED}{BOLD}⚠ ROLLBACK TRIGGERED{RESET}")
            for a in anomalies:
                fn   = a.get("function", "?")
                typ  = a.get("type", "?")
                cur  = a.get("current_gas", "?")
                p95  = a.get("p95_gas", "?")
                print(f"    {RED}→{RESET} {typ} on {CYAN}{fn}{RESET}: "
                      f"current_gas={cur}  p95_gas={p95}")
            final_state = state

        elif node == "__rollback__":
            print(f"  {RED}[__rollback__]{RESET} rollback complete")
            final_state = state

        elif node == "__error__":
            print(f"  {RED}[error]{RESET} {event.get('error', 'unknown error')}")
            final_state = state

        else:
            print(f"  {color}[{node:<10}]{RESET}")

        final_state = state or final_state

        if node in stop_nodes:
            break

    return final_state


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Self-Healing Contracts Demo Runner")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--tvl", type=float, default=1_000_000.0)
    args = parser.parse_args()

    api_base   = args.api.rstrip("/")
    root       = Path(__file__).parent.parent

    load_dotenv(root / ".env")

    # ── Banner ────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}  SELF-HEALING SMART CONTRACTS  ·  LIVE DEMO{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}\n")

    # ── Step 0: Prerequisites ─────────────────────────────────────────────────
    print(f"{BOLD}Checking prerequisites…{RESET}")
    ok  = check_hardhat()
    ok &= check_api(api_base)
    deployment = read_deployment(root)
    if deployment is None:
        ok = False
    if not ok:
        print(f"\n{RED}Fix the issues above and re-run.{RESET}\n")
        sys.exit(1)

    proxy_address = deployment["proxyAddress"]
    source = (root / "contracts" / "VulnerableVault.sol").read_text()

    # ── Step 1: Show the vulnerable contract ─────────────────────────────────
    print(f"\n{SEP}")
    print(f"{BOLD}Step 1 — Vulnerable contract{RESET}")
    print(f"  Proxy address : {CYAN}{proxy_address}{RESET}")
    print(f"  {YELLOW}VULN-1{RESET} Reentrancy in withdraw()  "
          f"— state update AFTER external call")
    print(f"  {YELLOW}VULN-2{RESET} Missing onlyOwner on setOwner() "
          f"— anyone can hijack ownership")

    # ── Step 2: Start pipeline ────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"{BOLD}Step 2 — Starting healing pipeline…{RESET}")

    resp = requests.post(
        f"{api_base}/heal",
        json={
            "contract_source":  source,
            "contract_address": proxy_address,
            "tvl_estimate":     args.tvl,
        },
    )
    resp.raise_for_status()
    pipeline_id = resp.json()["pipeline_id"]
    print(f"  Pipeline ID: {CYAN}{pipeline_id}{RESET}\n")

    # ── Steps 3–6: Stream node events ────────────────────────────────────────
    print(f"{BOLD}Steps 3–6 — Detection → Patch → Validate → Deploy{RESET}")
    print(f"{DIM}  (streaming SSE events…){RESET}\n")

    final_state = stream_pipeline(
        api_base, pipeline_id,
        stop_nodes=("__done__", "__error__"),
    )

    if not final_state.get("deployed"):
        print(f"\n{RED}Pipeline did not complete deployment. Check API logs.{RESET}\n")
        sys.exit(1)

    tx_hash         = final_state.get("tx_hash", "N/A")
    rollback_target = final_state.get("rollback_target", "N/A")
    findings_count  = len(final_state.get("all_findings", []))
    gates           = final_state.get("gate_results", {})
    gates_passed    = sum(1 for v in gates.values() if v)

    print(f"\n  {GREEN}✓ Deployed{RESET}  tx: {tx_hash[:24]}…")
    print(f"  Rollback target: {rollback_target[:24]}…")

    # ── Step 7: Inject anomaly ────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"{BOLD}Step 7 — The Money Shot™{RESET}")
    print(f"  {YELLOW}Injecting a gas-spike anomaly to trigger auto-rollback…{RESET}")
    input(f"\n  {DIM}Press Enter when ready…{RESET} ")

    r = requests.post(f"{api_base}/demo/inject-anomaly/{pipeline_id}")
    r.raise_for_status()
    print(f"\n  Anomaly injected. Streaming rollback events…\n")

    time.sleep(0.15)  # allow executor thread to start

    final_state = stream_pipeline(
        api_base, pipeline_id,
        stop_nodes=("__rollback__", "RollbackTriggered", "__error__"),
    )

    # Fetch final rollback history
    rollback_history: list = []
    try:
        rh = requests.get(f"{api_base}/pipeline/{pipeline_id}").json()
        rollback_history = rh.get("rollback_history", [])
    except Exception:
        pass

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}  DEMO COMPLETE{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")
    print(f"  Pipeline ID   : {pipeline_id}")
    print(f"  Findings      : {findings_count}")
    print(f"  Gates passed  : {gates_passed}/5")
    print(f"  Deploy tx     : {tx_hash[:32]}…")
    print(f"  RL reward     : {final_state.get('rl_reward', 0.0):.2f}")
    print(f"  Rollbacks     : {len(rollback_history)}")
    if rollback_history:
        rb  = rollback_history[-1]
        ts  = time.strftime("%H:%M:%S", time.localtime(rb.get("timestamp", 0)))
        tby = rb.get("triggered_by", "?")
        print(f"  Last rollback : {tby} @ {ts}")
    print(f"\n{GREEN}{BOLD}  All 7 steps complete.{RESET}\n")


if __name__ == "__main__":
    main()
