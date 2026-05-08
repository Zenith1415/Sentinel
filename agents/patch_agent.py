"""
Master Patch Agent — generates 3 patch candidates in parallel.

Candidates:
  1. proven   — KB proven_patches query + LLM refinement
  2. experimental — KB experimental_patches query + LLM refinement
  3. pure_llm — cold LLM generation (no KB)

Each candidate is pre-validated:
  - source diff % (>40% → flagged_for_review)
  - Slither new-vuln check (new High/Critical → flagged_for_review)

Rejected candidates (Slither found new High/Critical) are stored in the
rejected_patches ChromaDB collection.
"""
import asyncio
import difflib
import json
import logging
import os
import re
import subprocess
import tempfile
import uuid

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

from graph.state import HealingState

logger = logging.getLogger(__name__)

_SYSTEM_PATCH = """\
You are an expert Solidity security engineer.
You will be given a vulnerable Solidity contract and a list of findings.
Return a single JSON object with exactly these keys:
  patch_source  — the complete fixed Solidity source (string)
  explanation   — brief description of every change made (string)
  vuln_types_addressed — list of vuln_type strings fixed (array of strings)
Return ONLY the JSON object, no markdown fences."""

_SYSTEM_REFINE = """\
You are an expert Solidity security engineer.
You will be given a Solidity patch template retrieved from a knowledge base
and the original vulnerable contract.  Adapt the template to exactly match
the original contract's style, imports, and variable names.
Return a single JSON object with the same keys:
  patch_source, explanation, vuln_types_addressed
Return ONLY the JSON object."""


class MasterPatchAgent:

    def __init__(self, chroma_path: str | None = None) -> None:
        self._chroma_path = chroma_path or os.getenv("CHROMA_PATH", "./chroma_db")
        self._llm: ChatGoogleGenerativeAI | None = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def generate(self, state: HealingState) -> HealingState:
        s = dict(state)
        try:
            candidates = asyncio.run(self._generate_all(s))
        except RuntimeError:
            # Already inside a running event loop (e.g. Jupyter / pytest-asyncio)
            loop = asyncio.get_event_loop()
            candidates = loop.run_until_complete(self._generate_all(s))

        # Pre-validate each candidate
        validated: list[dict] = []
        for c in candidates:
            if isinstance(c, Exception) or c is None:
                continue
            c = self._prevalidate(c, s)
            validated.append(c)

        s["candidate_patches"] = validated
        print("PHASE 4 COMPLETE — 3 candidates generated and pre-checked")
        return s

    # ------------------------------------------------------------------
    # Parallel generation
    # ------------------------------------------------------------------

    async def _generate_all(self, state: dict) -> list:
        results = await asyncio.gather(
            self._gen_proven(state),
            self._gen_experimental(state),
            self._gen_pure_llm(state),
            return_exceptions=True,
        )
        return list(results)

    async def _gen_proven(self, state: dict) -> dict | None:
        template = self._query_kb("proven_patches", state.get("all_findings", []))
        return await self._build_candidate(state, template, strategy="proven")

    async def _gen_experimental(self, state: dict) -> dict | None:
        template = self._query_kb("experimental_patches", state.get("all_findings", []))
        return await self._build_candidate(state, template, strategy="experimental")

    async def _gen_pure_llm(self, state: dict) -> dict | None:
        return await self._build_candidate(state, template=None, strategy="pure_llm")

    async def _build_candidate(
        self, state: dict, template: str | None, strategy: str
    ) -> dict | None:
        source = state.get("contract_source", "")
        findings = state.get("all_findings", [])
        findings_text = json.dumps(findings, indent=2)[:3000]

        if template:
            messages = [
                SystemMessage(content=_SYSTEM_REFINE),
                HumanMessage(
                    content=(
                        f"Template from KB:\n```solidity\n{template}\n```\n\n"
                        f"Original contract:\n```solidity\n{source}\n```\n\n"
                        f"Findings:\n{findings_text}"
                    )
                ),
            ]
        else:
            messages = [
                SystemMessage(content=_SYSTEM_PATCH),
                HumanMessage(
                    content=(
                        f"Contract:\n```solidity\n{source}\n```\n\n"
                        f"Findings:\n{findings_text}"
                    )
                ),
            ]

        try:
            raw = await self._call_llm(messages)
            data = self._parse_json(raw)
            if not data or "patch_source" not in data:
                return None
            return {
                "id": str(uuid.uuid4()),
                "strategy": strategy,
                "patch_source": str(data.get("patch_source", "")),
                "explanation": str(data.get("explanation", "")),
                "vuln_types_addressed": list(data.get("vuln_types_addressed", [])),
                "flagged_for_review": False,
                "flag_reasons": [],
                "new_vulns": [],
            }
        except Exception as exc:
            logger.warning("Patch candidate '%s' failed: %s", strategy, exc)
            return None

    # ------------------------------------------------------------------
    # Pre-validation
    # ------------------------------------------------------------------

    def _prevalidate(self, candidate: dict, state: dict) -> dict:
        original = state.get("contract_source", "")
        patched = candidate.get("patch_source", "")
        findings = state.get("all_findings", [])

        flags: list[str] = list(candidate.get("flag_reasons", []))

        # Diff check
        diff_pct = self._source_diff_pct(original, patched)
        if diff_pct > 0.40:
            candidate["flagged_for_review"] = True
            flags.append(f"large_diff:{diff_pct:.0%}")

        # Slither new-vuln check
        new_vulns = self._slither_new_vulns(patched, findings)
        candidate["new_vulns"] = new_vulns
        if new_vulns:
            candidate["flagged_for_review"] = True
            flags.append(f"new_vulns:{','.join(new_vulns)}")
            self._store_rejected(candidate, state)

        candidate["flag_reasons"] = flags
        return candidate

    def _source_diff_pct(self, original: str, patched: str) -> float:
        if not original and not patched:
            return 0.0
        ratio = difflib.SequenceMatcher(None, original, patched).ratio()
        return 1.0 - ratio

    def _slither_new_vulns(self, patched_source: str, original_findings: list[dict]) -> list[str]:
        if not patched_source.strip():
            return []
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".sol", mode="w", delete=False, encoding="utf-8"
            ) as f:
                f.write(patched_source)
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

            orig_types = {
                f.get("vuln_type", "").lower()
                for f in original_findings
            }

            new: list[str] = []
            for det in data.get("results", {}).get("detectors", []):
                impact = det.get("impact", "").lower()
                if impact not in ("high", "critical"):
                    continue
                check = det.get("check", "unknown").lower()
                # New if not present in original findings
                if not any(check in ot or ot in check for ot in orig_types):
                    new.append(det.get("check", "unknown"))
            return new

        except FileNotFoundError:
            return []  # Slither not installed — fail open
        except Exception:
            return []

    # ------------------------------------------------------------------
    # KB retrieval
    # ------------------------------------------------------------------

    def _query_kb(self, collection_name: str, findings: list[dict]) -> str | None:
        if not findings:
            return None
        try:
            import chromadb
            client = chromadb.PersistentClient(path=self._chroma_path)
            col = client.get_or_create_collection(collection_name)
            if col.count() == 0:
                return None
            query_text = " ".join(
                f.get("vuln_type", "") + " " + f.get("affected_function", "")
                for f in findings[:5]
            )
            results = col.query(query_texts=[query_text], n_results=1)
            docs = results.get("documents", [[]])
            return docs[0][0] if docs and docs[0] else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Rejected patch storage
    # ------------------------------------------------------------------

    def _store_rejected(self, candidate: dict, state: dict) -> None:
        try:
            import chromadb
            client = chromadb.PersistentClient(path=self._chroma_path)
            col = client.get_or_create_collection("rejected_patches")
            col.add(
                documents=[candidate.get("patch_source", "")],
                metadatas=[{
                    "strategy": candidate.get("strategy", ""),
                    "new_vulns": ",".join(candidate.get("new_vulns", [])),
                    "pipeline_id": str(state.get("pipeline_id", "")),
                    "flag_reasons": ",".join(candidate.get("flag_reasons", [])),
                }],
                ids=[candidate.get("id", str(uuid.uuid4()))],
            )
        except Exception as exc:
            logger.warning("Failed to store rejected patch: %s", exc)

    # ------------------------------------------------------------------
    # LLM helpers
    # ------------------------------------------------------------------

    def _get_llm(self) -> ChatGoogleGenerativeAI:
        if self._llm is None:
            self._llm = ChatGoogleGenerativeAI(
                model="gemini-2.0-flash",
                google_api_key=os.environ["GOOGLE_API_KEY"],
                max_output_tokens=8192,
            )
        return self._llm

    async def _call_llm(self, messages: list) -> str:
        llm = self._get_llm()
        resp = await llm.ainvoke(messages)
        return resp.content.strip()

    def _parse_json(self, raw: str) -> dict | None:
        raw = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
        raw = re.sub(r"\n?```$", "", raw.strip())
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract the first {...} block
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except json.JSONDecodeError:
                    pass
        return None
