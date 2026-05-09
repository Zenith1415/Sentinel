"""
Static analysis agent — regex heuristics (primary) + Slither (supplementary).
Guarantees findings without any external tools via robust regex fallback.
"""
import json
import os
import re
import subprocess
import tempfile

from graph.state import HealingState

_SLITHER_SEVERITY = {
    "High": "Critical",
    "Medium": "High",
    "Low": "Medium",
    "Informational": "Low",
    "Optimization": "Low",
}
_SLITHER_CONFIDENCE = {"High": 0.90, "Medium": 0.70, "Low": 0.50}
_FIX_HINTS = {
    "reentrancy": "Apply Checks-Effects-Interactions: update all state before any external call.",
    "access-control": "Add onlyOwner or appropriate access control modifier.",
    "suicidal": "Remove selfdestruct or guard it with onlyOwner.",
    "tx-origin": "Replace tx.origin with msg.sender for authorisation.",
    "locked-ether": "Add a withdrawal function so trapped ETH can be recovered.",
}


class StaticAnalysisAgent:
    methodology = "static"

    def run(self, contract_source: str, state: HealingState) -> list[dict]:
        findings: list[dict] = []
        findings += self._regex_findings(contract_source)
        findings += self._slither_findings(contract_source)
        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # Regex heuristics — always run, zero external dependencies
    # ------------------------------------------------------------------

    def _regex_findings(self, source: str) -> list[dict]:
        findings: list[dict] = []
        lines = source.splitlines()

        # [VULN-1] Reentrancy: .call{value:} before state update — detect CEI violation
        # Scan ONLY within the enclosing function (not the whole file) and skip
        # functions that already use nonReentrant or follow CEI (state cleared first).
        for i, line in enumerate(lines):
            if not (re.search(r'\.call\{value:', line) or re.search(r'\.call\.value\(', line)):
                continue

            # Find the enclosing function's body bounds (between matching braces)
            fn_start = i
            for j in range(i, -1, -1):
                if re.search(r'function\s+\w+', lines[j]):
                    fn_start = j
                    break
            fn_end = self._find_fn_end(lines, fn_start)

            fn_body_before = "\n".join(lines[fn_start:i])
            fn_body_after  = "\n".join(lines[i + 1:fn_end + 1])

            # ✅ CEI applied: state cleared BEFORE the call → not vulnerable
            cleared_before = bool(
                re.search(r'\bbalances\b\s*\[[^\]]+\]\s*[-]=', fn_body_before)
                or re.search(r'\bbalances\b\s*\[[^\]]+\]\s*=\s*0\b', fn_body_before)
            )
            if cleared_before:
                continue

            # ✅ nonReentrant guard on this function → not vulnerable
            fn_signature = "\n".join(lines[fn_start: min(fn_start + 3, len(lines))])
            if re.search(r'\bnonReentrant\b', fn_signature):
                continue

            # 🔴 State update AFTER the call → reentrancy
            if not re.search(r'\bbalances\b\s*\[[^\]]+\]\s*[-]=|\bbalances\b\s*\[[^\]]+\]\s*=\s*0\b', fn_body_after):
                continue

            fn_name = self._enclosing_fn(lines, i)
            # cross_contract_flag only when calling a stored external address,
            # not msg.sender or address(this) which are always intra-contract
            is_cross = bool(re.search(r'\.call\{value:', line)) and not bool(
                re.search(r'msg\.sender\.call|address\(this\)\.call', line)
            )
            findings.append(self._make(
                vuln_type="Reentrancy",
                severity="Critical",
                affected_function=fn_name,
                line_range=[i + 1, min(i + 6, len(lines))],
                confidence=0.95,
                fix_recommendation=_FIX_HINTS["reentrancy"],
                evidence=(
                    f"Line {i + 1}: `{line.strip()}` — state update follows "
                    f"external call, enabling reentrancy."
                ),
                cross_contract_flag=is_cross,
            ))

        # [VULN-2] Missing access control on setter functions
        for i, line in enumerate(lines):
            if not re.search(r'function\s+set\w*(?:[Oo]wner|[Aa]dmin|[Cc]ontroller)\s*\(', line):
                continue
            # Only inspect the function signature (≤2 lines); strip // comments so
            # a comment saying "missing onlyOwner" doesn't falsely suppress the finding
            sig = "\n".join(lines[max(0, i - 1): i + 2])
            sig_clean = re.sub(r"//[^\n]*", "", sig)
            if re.search(r'\bonlyOwner\b|\bonlyAdmin\b|\bonlyRole\b', sig_clean):
                continue
            fn = re.search(r'function\s+(\w+)', line)
            findings.append(self._make(
                vuln_type="MissingAccessControl",
                severity="Critical",
                affected_function=fn.group(1) if fn else "unknown",
                line_range=[i + 1, min(i + 5, len(lines))],
                confidence=0.90,
                fix_recommendation=_FIX_HINTS["access-control"],
                evidence=f"Line {i + 1}: `{line.strip()}` — no access control modifier detected.",
                cross_contract_flag=False,
            ))

        # [VULN-3] delegatecall — cross-contract storage collision risk
        for i, line in enumerate(lines):
            if not re.search(r'\.delegatecall\s*\(', line):
                continue
            fn = self._enclosing_fn(lines, i)
            findings.append(self._make(
                vuln_type="DangerousDelegatecall",
                severity="Critical",
                affected_function=fn,
                line_range=[i + 1, min(i + 6, len(lines))],
                confidence=0.30,   # auto-fixing requires storage-layout coordination
                fix_recommendation=(
                    "delegatecall shares the caller's storage layout — verify storage "
                    "slots match across contracts and consider EIP-1967 namespacing."
                ),
                evidence=f"Line {i + 1}: `{line.strip()}` — delegatecall to user-controlled address.",
                cross_contract_flag=True,
            ))

        # [VULN-4] selfdestruct — irreversible, governance/operational concern
        for i, line in enumerate(lines):
            if not re.search(r'\bselfdestruct\s*\(', line):
                continue
            fn = self._enclosing_fn(lines, i)
            findings.append(self._make(
                vuln_type="SelfdestructPresent",
                severity="High",
                affected_function=fn,
                line_range=[i + 1, min(i + 4, len(lines))],
                confidence=0.35,
                fix_recommendation=_FIX_HINTS["suicidal"],
                evidence=f"Line {i + 1}: `{line.strip()}` — selfdestruct kills the implementation contract.",
                cross_contract_flag=False,
            ))

        # [VULN-5] Multiple contracts in one file → architecture complexity signal
        contract_decls = re.findall(r'^\s*contract\s+(\w+)', source, re.MULTILINE)
        if len(contract_decls) >= 3:
            # Multi-contract architecture — every reentrancy/external-call finding
            # should be flagged as cross-contract regardless of the specific call site,
            # because routing decisions depend on contract-graph complexity.
            for f in findings:
                if f.get("vuln_type") in ("Reentrancy", "DangerousDelegatecall"):
                    f["cross_contract_flag"] = True
            # Also emit an explicit complexity finding
            findings.append(self._make(
                vuln_type="MultiContractArchitecture",
                severity="Medium",
                affected_function="<file-level>",
                line_range=[1, len(lines)],
                confidence=0.40,
                fix_recommendation=(
                    "File defines "
                    f"{len(contract_decls)} contracts: {', '.join(contract_decls[:6])}. "
                    "Cross-contract behaviour cannot be patched in isolation."
                ),
                evidence=f"{len(contract_decls)} contract declarations in single source file.",
                cross_contract_flag=True,
            ))

        return findings

    # ------------------------------------------------------------------
    # Slither — supplementary, fails silently
    # ------------------------------------------------------------------

    def _slither_findings(self, source: str) -> list[dict]:
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".sol", mode="w", delete=False, encoding="utf-8"
            ) as f:
                f.write(source)
                tmp = f.name

            result = subprocess.run(
                ["slither", tmp, "--json", "-", "--disable-color"],
                capture_output=True, text=True, timeout=120,
            )
            os.unlink(tmp)

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            if not data.get("success"):
                return []

            findings = []
            for det in data.get("results", {}).get("detectors", []):
                check = det.get("check", "unknown")
                fix_key = next((k for k in _FIX_HINTS if k in check), None)
                findings.append(self._make(
                    vuln_type=self._fmt(check),
                    severity=_SLITHER_SEVERITY.get(det.get("impact", "Low"), "Low"),
                    affected_function=self._slither_fn(det),
                    line_range=self._slither_lines(det),
                    confidence=_SLITHER_CONFIDENCE.get(det.get("confidence", "Low"), 0.5),
                    fix_recommendation=(
                        _FIX_HINTS[fix_key]
                        if fix_key
                        else det.get("wiki_recommendation", "See Slither docs.")
                    ),
                    evidence=det.get("description", "")[:400],
                    cross_contract_flag="cross" in check or "delegatecall" in check,
                ))
            return findings

        except Exception:
            return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make(
        self,
        vuln_type: str,
        severity: str,
        affected_function: str,
        line_range: list,
        confidence: float,
        fix_recommendation: str,
        evidence: str,
        cross_contract_flag: bool,
    ) -> dict:
        return {
            "vuln_type": vuln_type,
            "severity": severity,
            "affected_function": affected_function,
            "line_range": line_range,
            "confidence": confidence,
            "fix_recommendation": fix_recommendation,
            "evidence": evidence,
            "methodology": self.methodology,
            "cross_contract_flag": cross_contract_flag,
        }

    def _enclosing_fn(self, lines: list[str], target: int) -> str:
        for i in range(target, -1, -1):
            m = re.search(r'function\s+(\w+)', lines[i])
            if m:
                return m.group(1)
        return "unknown"

    def _find_fn_end(self, lines: list[str], start: int) -> int:
        """Return the line index of the closing brace of the function starting at `start`."""
        depth = 0
        seen_open = False
        for i in range(start, len(lines)):
            for ch in lines[i]:
                if ch == "{":
                    depth += 1
                    seen_open = True
                elif ch == "}":
                    depth -= 1
                    if seen_open and depth == 0:
                        return i
        return len(lines) - 1

    def _fmt(self, check: str) -> str:
        return "".join(w.capitalize() for w in re.split(r'[-_]', check))

    def _slither_fn(self, det: dict) -> str:
        for el in det.get("elements", []):
            name = el.get("name", "")
            if name:
                return name
        return "unknown"

    def _slither_lines(self, det: dict) -> list[int]:
        nums: list[int] = []
        for el in det.get("elements", []):
            nums.extend(el.get("source_mapping", {}).get("lines", []))
        return [min(nums), max(nums)] if nums else [0, 0]

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        seen: set[tuple] = set()
        out = []
        for f in findings:
            key = (f["vuln_type"], f["affected_function"])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
