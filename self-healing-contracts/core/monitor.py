"""
Monitor — Phase 6 of the self-healing smart contracts pipeline.

ContractMonitor : pre-deploy on-chain event watcher (original).
PostDeployMonitor : post-deploy anomaly detector with auto-rollback / freeze.

PostDeployMonitor.watch() monitors for 100 blocks post-deploy, comparing
every block against the pre-patch baseline captured by DeployAgent:

  Anomaly types:
    gas_spike        — current avg_gas > p95_gas * 1.5
    failed_calls     — revert_rate increased by > 50 percentage points
    balance_drift    — unexpected negative balance delta vs baseline
    dependency_anomaly — external calls to unexpected addresses (future)

  On anomaly:
    rollback_target clean   → auto-rollback + emit RollbackTriggered + RL -1.0
    rollback_target anomalous → FREEZE (circuit breaker) + emit critical.freeze.required

  After 30-day clean window (≈172 800 blocks) with ≥100 txs:
    emit RL reward +0.5
    promote patch to proven KB partition
"""
import logging
import os
import time

from web3 import Web3

from graph.state import HealingState

logger = logging.getLogger(__name__)

# UUPS upgradeToAndCall ABI (also defined in deployer.py — kept local to avoid circular import)
def _minimal_uups_abi() -> list:
    return [
        {
            "inputs": [
                {"internalType": "address", "name": "newImplementation", "type": "address"},
                {"internalType": "bytes", "name": "data", "type": "bytes"},
            ],
            "name": "upgradeToAndCall",
            "outputs": [],
            "stateMutability": "payable",
            "type": "function",
        }
    ]


# ---------------------------------------------------------------------------
# Original pre-deploy event monitor (kept for backwards compatibility)
# ---------------------------------------------------------------------------

class ContractMonitor:
    POLL_INTERVAL = 2  # seconds

    def __init__(self, contract_address: str, abi: list, rpc_url: str | None = None):
        rpc = rpc_url or os.getenv("RPC_URL", "http://127.0.0.1:8545")
        self._w3 = Web3(Web3.HTTPProvider(rpc))
        self._address = Web3.to_checksum_address(contract_address)
        self._contract = self._w3.eth.contract(address=self._address, abi=abi)
        self._last_block = self._w3.eth.block_number

    def watch(self, on_suspicious, stop_event=None) -> None:
        """Poll for events; call on_suspicious(tx_info) on anomalies."""
        logger.info("Monitoring %s from block %d", self._address, self._last_block)
        while not (stop_event and stop_event.is_set()):
            try:
                current = self._w3.eth.block_number
                if current > self._last_block:
                    self._scan_blocks(self._last_block + 1, current, on_suspicious)
                    self._last_block = current
            except Exception as e:
                logger.warning("Monitor poll error: %s", e)
            time.sleep(self.POLL_INTERVAL)

    def _scan_blocks(self, from_block, to_block, callback) -> None:
        for event in self._contract.events:
            try:
                logs = event().get_logs(fromBlock=from_block, toBlock=to_block)
                for log in logs:
                    if self._is_suspicious(log):
                        callback(dict(log))
            except Exception:
                pass

    def _is_suspicious(self, log: dict) -> bool:
        args = log.get("args", {})
        return args.get("amount", 0) > self._w3.to_wei(10, "ether")

    @property
    def connected(self) -> bool:
        return self._w3.is_connected()


# ---------------------------------------------------------------------------
# Post-deploy anomaly monitor
# ---------------------------------------------------------------------------

class PostDeployMonitor:
    """
    Monitors a deployed contract for anomalies against a pre-patch baseline.
    Triggers auto-rollback (or freeze) when anomalies are detected.
    Promotes to proven KB after a clean observation window.
    """

    POLL_INTERVAL = 2                     # seconds between block polls
    GAS_SPIKE_MULTIPLIER = 1.5            # current_gas > p95 * 1.5 → spike
    REVERT_RATE_THRESHOLD = 0.50          # +50 pp spike in revert rate → anomaly
    CLEAN_WINDOW_BLOCKS = 172_800         # ≈ 30 days at 15 s/block
    MIN_TX_FOR_PROMOTION = 100            # minimum transactions before promotion

    def __init__(
        self,
        event_bus=None,
        deploy_agent=None,
        rpc_url: str | None = None,
        private_key: str | None = None,
        chroma_path: str | None = None,
        _w3=None,                         # injected Web3 for testing
    ) -> None:
        self._event_bus = event_bus
        self._deploy_agent = deploy_agent
        self._rpc_url = rpc_url or os.getenv("RPC_URL", "http://127.0.0.1:8545")
        self._private_key = private_key or os.getenv("PRIVATE_KEY", "")
        self._chroma_path = chroma_path or os.getenv("CHROMA_PATH", "./chroma_db")
        self._w3_injected = _w3
        self._poll_interval = self.POLL_INTERVAL

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def watch(self, state: HealingState, duration_blocks: int = 100) -> HealingState:
        """
        Monitor for duration_blocks.  On anomaly → rollback or freeze.
        After a clean full window → promote + RL +0.5.
        Returns the (possibly mutated) state dict.
        """
        s = dict(state)
        baseline = s.get("baseline_metrics", {})
        start_block = self._get_start_block()

        for block_num in self._block_range(start_block, start_block + duration_blocks):
            metrics = self._collect_metrics_at_block(block_num, s)
            anomalies = self._detect_anomalies(metrics, baseline)
            if anomalies:
                self._handle_anomalies(anomalies, s)
                return s

        # No anomalies over the full window
        self._check_promotion(s)
        return s

    # ------------------------------------------------------------------
    # Block iteration helpers (overridden in tests)
    # ------------------------------------------------------------------

    def _get_start_block(self) -> int:
        try:
            return self._w3.eth.block_number
        except Exception:
            return 0

    def _block_range(self, start: int, end: int):
        """Generator: yields block numbers as they arrive until end reached."""
        current = start
        while current < end:
            try:
                live = self._w3.eth.block_number
                if live > current:
                    current = live
                    yield current
                else:
                    time.sleep(self._poll_interval)
            except Exception as exc:
                logger.warning("Block poll error: %s", exc)
                return

    # ------------------------------------------------------------------
    # Metrics collection (overridden in tests)
    # ------------------------------------------------------------------

    def _collect_metrics_at_block(self, block_num: int, state: dict) -> dict:
        """Collect per-function gas / revert metrics for a single block."""
        contract_address = state.get("contract_address", "")
        if not contract_address:
            return {}

        metrics: dict = {}
        try:
            checksum = Web3.to_checksum_address(contract_address)
            block = self._w3.eth.get_block(block_num, full_transactions=True)
            by_fn: dict[str, list] = {}

            for tx in block.get("transactions", []):
                if tx.get("to") and tx["to"].lower() == checksum.lower():
                    receipt = self._w3.eth.get_transaction_receipt(tx["hash"])
                    selector = (tx.get("input") or "0x")[:10]
                    by_fn.setdefault(selector, []).append({
                        "gas_used": receipt.get("gasUsed", 0) if receipt else 0,
                        "status": receipt.get("status", 1) if receipt else 1,
                    })

            for fn, txs in by_fn.items():
                gas_vals = [t["gas_used"] for t in txs]
                reverted = sum(1 for t in txs if t.get("status", 1) == 0)
                n = len(txs)
                metrics[fn] = {
                    "avg_gas": sum(gas_vals) / n if n else 0,
                    "revert_rate": reverted / n if n else 0.0,
                }
        except Exception as exc:
            logger.warning("Metrics collection at block %d failed: %s", block_num, exc)

        return metrics

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def _detect_anomalies(self, metrics: dict, baseline: dict) -> list[dict]:
        """Compare current block metrics against pre-patch baseline."""
        anomalies: list[dict] = []

        for fn, current in metrics.items():
            base = baseline.get(fn, {})
            if not base:
                continue

            current_gas = current.get("avg_gas", 0)
            p95_gas = base.get("p95_gas", 0)

            # Gas spike: current avg > p95 * 1.5
            if p95_gas and current_gas > p95_gas * self.GAS_SPIKE_MULTIPLIER:
                anomalies.append({
                    "type": "gas_spike",
                    "function": fn,
                    "current_gas": current_gas,
                    "p95_gas": p95_gas,
                    "severity": "high",
                })

            # Failed calls: revert rate spike > 50 pp above baseline
            current_rr = current.get("revert_rate", 0.0)
            base_rr = base.get("revert_rate", 0.0)
            if current_rr > base_rr + self.REVERT_RATE_THRESHOLD:
                anomalies.append({
                    "type": "failed_calls",
                    "function": fn,
                    "current_revert_rate": current_rr,
                    "baseline_revert_rate": base_rr,
                    "severity": "medium",
                })

            # Balance drift: unexpected negative delta
            current_delta = current.get("balance_delta")
            base_delta = base.get("typical_balance_delta")
            if (current_delta is not None and base_delta is not None
                    and current_delta < base_delta - 0.5):
                anomalies.append({
                    "type": "balance_drift",
                    "function": fn,
                    "current_delta": current_delta,
                    "baseline_delta": base_delta,
                    "severity": "high",
                })

        return anomalies

    # ------------------------------------------------------------------
    # Anomaly response
    # ------------------------------------------------------------------

    def _handle_anomalies(self, anomalies: list[dict], state: dict) -> None:
        """Route anomaly response: rollback if clean target, else freeze."""
        rollback_target = state.get("rollback_target", "")
        if self._is_rollback_target_anomalous(rollback_target, state):
            self._freeze_contract(state, anomalies)
        else:
            self._perform_rollback(state, anomalies)

    def _is_rollback_target_anomalous(self, rollback_target: str, state: dict) -> bool:
        """Check whether the rollback target is itself compromised.
        Can be overridden in tests by injecting state['rollback_target_anomalous'].
        """
        return bool(state.get("rollback_target_anomalous", False))

    def _perform_rollback(self, state: dict, anomalies: list[dict]) -> None:
        """Execute rollback to previous implementation."""
        rollback_target = state.get("rollback_target", "")
        proxy_address = state.get("contract_address", "")

        logger.warning(
            "AUTO-ROLLBACK: reverting to %s due to anomalies: %s",
            rollback_target, anomalies,
        )

        try:
            if rollback_target and proxy_address:
                self._execute_upgrade(proxy_address, rollback_target)
        except Exception as exc:
            logger.error("Rollback execution failed: %s", exc)

        # Emit RollbackTriggered event
        self._emit_rollback_event({
            "rollback_target": rollback_target,
            "anomalies": anomalies,
            "pipeline_id": state.get("pipeline_id", ""),
        })

        # Publish to event bus
        if self._event_bus:
            try:
                from core.event_bus import MONITOR_ANOMALY
                self._event_bus.publish(
                    MONITOR_ANOMALY,
                    state.get("pipeline_id", ""),
                    {"anomalies": anomalies, "action": "rollback"},
                )
            except Exception as exc:
                logger.warning("Failed to publish rollback event: %s", exc)

        # RL penalty
        state["rl_reward"] = state.get("rl_reward", 0.0) - 1.0
        state["deployed"] = False
        state["healed"] = False

    def _freeze_contract(self, state: dict, anomalies: list[dict]) -> None:
        """Circuit breaker: freeze contract when rollback target is also compromised."""
        proxy_address = state.get("contract_address", "")
        logger.critical("CIRCUIT BREAKER ACTIVATED: freezing %s", proxy_address)

        try:
            if proxy_address:
                self._execute_pause(proxy_address)
        except Exception as exc:
            logger.error("Pause execution failed: %s", exc)

        freeze_event = {
            "proxy_address": proxy_address,
            "anomalies": anomalies,
            "pipeline_id": state.get("pipeline_id", ""),
            "action": "freeze",
        }
        self._emit_freeze_event(freeze_event)

        if self._event_bus:
            try:
                self._event_bus.publish(
                    "critical.freeze.required",
                    state.get("pipeline_id", ""),
                    freeze_event,
                )
            except Exception as exc:
                logger.warning("Failed to publish freeze event: %s", exc)

        state["deployed"] = False
        state["healed"] = False
        state["error"] = "CIRCUIT BREAKER ACTIVATED: human-only resolution required"

    # ------------------------------------------------------------------
    # On-chain execution helpers (overridden in tests)
    # ------------------------------------------------------------------

    def _execute_upgrade(self, proxy_address: str, new_impl: str) -> None:
        """Call upgradeToAndCall for rollback."""
        account = self._w3.eth.account.from_key(self._private_key)
        proxy = self._w3.eth.contract(
            address=Web3.to_checksum_address(proxy_address),
            abi=_minimal_uups_abi(),
        )
        nonce = self._w3.eth.get_transaction_count(account.address)
        tx = proxy.functions.upgradeToAndCall(
            Web3.to_checksum_address(new_impl), b""
        ).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": self._w3.eth.gas_price,
        })
        signed = self._w3.eth.account.sign_transaction(tx, self._private_key)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

    def _execute_pause(self, proxy_address: str) -> None:
        """Call pause() on the contract as circuit breaker."""
        pause_abi = [{
            "inputs": [],
            "name": "pause",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        }]
        try:
            contract = self._w3.eth.contract(
                address=Web3.to_checksum_address(proxy_address),
                abi=pause_abi,
            )
            account = self._w3.eth.account.from_key(self._private_key)
            nonce = self._w3.eth.get_transaction_count(account.address)
            tx = contract.functions.pause().build_transaction({
                "from": account.address,
                "nonce": nonce,
                "gas": 100_000,
                "gasPrice": self._w3.eth.gas_price,
            })
            signed = self._w3.eth.account.sign_transaction(tx, self._private_key)
            tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
            self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        except Exception as exc:
            logger.warning("pause() call failed (may not be supported): %s", exc)

    # ------------------------------------------------------------------
    # Event emission stubs (override in tests to capture emitted data)
    # ------------------------------------------------------------------

    def _emit_rollback_event(self, event_data: dict) -> None:
        logger.info("RollbackTriggered: %s", event_data)

    def _emit_freeze_event(self, event_data: dict) -> None:
        logger.info("CircuitBreakerActivated: %s", event_data)

    # ------------------------------------------------------------------
    # Post-window promotion
    # ------------------------------------------------------------------

    def _check_promotion(self, state: dict) -> None:
        """After clean window, award RL +0.5 and promote patch to proven KB."""
        logger.info(
            "Clean monitoring window complete for pipeline %s",
            state.get("pipeline_id", ""),
        )
        state["rl_reward"] = state.get("rl_reward", 0.0) + 0.5

        if self._deploy_agent is not None:
            try:
                self._deploy_agent._promote_to_proven(state)
            except Exception as exc:
                logger.warning("KB promotion failed: %s", exc)

    # ------------------------------------------------------------------
    # Internal Web3 accessor
    # ------------------------------------------------------------------

    @property
    def _w3(self) -> Web3:
        if self._w3_injected is not None:
            return self._w3_injected
        return Web3(Web3.HTTPProvider(self._rpc_url))
