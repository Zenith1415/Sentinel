"""
Symbolic execution agent — Mythril with a hard 90-second timeout.
Returns a TIMEOUT sentinel finding if Mythril is absent or exceeds budget;
this sentinel signals the graph router to take the Slow Path.
"""
import json
import os
import subprocess
import tempfile

from graph.state import HealingState

_SEVERITY = {"High": "Critical", "Medium": "High", "Low": "Medium"}
_CONFIDENCE = {"High": 0.85, "Medium": 0.65, "Low": 0.40}
_SWC_FIX = {
    "107": "Apply Checks-Effects-Interactions pattern to prevent reentrancy.",
    "115": "Replace tx.origin with msg.sender for authorisation.",
    "105": "Add onlyOwner guard to Ether withdrawal functions.",
    "116": "Never rely on block.timestamp as a sole security control.",
    "101": "Use SafeMath or Solidity >=0.8 to prevent integer overflow.",
}


class SymbolicExecutionAgent:
    methodology = "symbolic"
    HARD_TIMEOUT = 90        # seconds — absolute wall-clock cap
    MYTH_TIMEOUT = 60        # seconds — passed to myth's --execution-timeout

    def run(self, contract_source: str, state: HealingState) -> list[dict]:
        tmp: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".sol", mode="w", delete=False, encoding="utf-8"
            ) as f:
                f.write(contract_source)
                tmp = f.name

            result = subprocess.run(
                [
                    "myth", "analyze", tmp,
                    "-o", "json",
                    "--execution-timeout", str(self.MYTH_TIMEOUT),
                ],
                capture_output=True,
                text=True,
                timeout=self.HARD_TIMEOUT,
            )
            self._cleanup(tmp)

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            return [self._map(issue) for issue in data.get("issues", [])]

        except subprocess.TimeoutExpired:
            self._cleanup(tmp)
            return [self._timeout_finding("Mythril exceeded 90-second time budget.")]

        except FileNotFoundError:
            self._cleanup(tmp)
            return [self._timeout_finding("Mythril (myth) not installed — skipping symbolic path.")]

        except Exception:
            self._cleanup(tmp)
            return []

    # ------------------------------------------------------------------

    def _map(self, issue: dict) -> dict:
        swc = issue.get("swc-id", "???")
        sev_raw = issue.get("severity", "Low")
        return {
            "vuln_type": (issue.get("title") or f"SWC-{swc}").replace(" ", ""),
            "severity": _SEVERITY.get(sev_raw, "Low"),
            "affected_function": issue.get("function", "unknown"),
            "line_range": [
                issue.get("lineno", 0),
                (issue.get("lineno") or 0) + 5,
            ],
            "confidence": _CONFIDENCE.get(sev_raw, 0.50),
            "fix_recommendation": _SWC_FIX.get(swc, issue.get("description", "Review SWC docs.")[:300]),
            "evidence": (issue.get("description") or "")[:400],
            "methodology": self.methodology,
            "cross_contract_flag": False,
        }

    def _timeout_finding(self, reason: str) -> dict:
        return {
            "vuln_type": "TIMEOUT",
            "severity": "Low",
            "affected_function": "unknown",
            "line_range": [0, 0],
            "confidence": 0.0,
            "fix_recommendation": "Run symbolic analysis with a higher timeout or on a dedicated machine.",
            "evidence": reason,
            "methodology": self.methodology,
            "cross_contract_flag": False,
        }

    def _cleanup(self, path: str | None) -> None:
        if path:
            try:
                os.unlink(path)
            except Exception:
                pass
