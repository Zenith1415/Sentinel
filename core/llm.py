"""
LLM provider factory — tries providers in priority order based on env vars.

Priority:
  1. Backboard.io  — unified gateway, per-agent assistant_id spreads rate limits
  2. Gemma 4 (Ollama, local) — free local inference, requires `ollama pull gemma4:e2b`
  3. Google Gemini — original provider

Per-agent rate-limit spreading
  Pass `agent_role` ("patch" | "semantic" | "governance" | "default") and the
  factory picks a role-specific Backboard assistant_id from env if configured:

      BACKBOARD_ASSISTANT_PATCH=...
      BACKBOARD_ASSISTANT_SEMANTIC=...
      BACKBOARD_ASSISTANT_GOVERNANCE=...
      BACKBOARD_ASSISTANT_ID=...   (fallback for any role)

  Unset → uses default assistant. Each agent still gets its own thread per
  call (memory=Off), so concurrent invocations don't queue against each
  other on the same thread.

Usage:
    from core.llm import get_llm
    llm = get_llm(max_tokens=4096, agent_role="patch")
"""
import os
import logging
import asyncio

logger = logging.getLogger(__name__)


class _FallbackChain:
    """Try each LLM in order; on RuntimeError (incl. Backboard credit gate),
    move to the next. Presents the same .ainvoke/.invoke shape the agents use."""

    def __init__(self, llms: list, labels: list[str]):
        if not llms:
            raise RuntimeError("FallbackChain requires at least one LLM")
        self._llms   = llms
        self._labels = labels

    async def ainvoke(self, messages, config=None, **kwargs):
        last_err: Exception | None = None
        for llm, label in zip(self._llms, self._labels):
            try:
                return await llm.ainvoke(messages, config=config, **kwargs)
            except Exception as exc:
                logger.warning("LLM provider %s failed (%s); trying next.", label, exc)
                last_err = exc
        raise RuntimeError(f"All LLM providers failed. Last error: {last_err}")

    def invoke(self, messages, config=None, **kwargs):
        last_err: Exception | None = None
        for llm, label in zip(self._llms, self._labels):
            try:
                return llm.invoke(messages, config=config, **kwargs)
            except Exception as exc:
                logger.warning("LLM provider %s failed (%s); trying next.", label, exc)
                last_err = exc
        raise RuntimeError(f"All LLM providers failed. Last error: {last_err}")


def _backboard_assistant_for(role: str) -> str | None:
    """Look up the Backboard assistant_id for a given agent role."""
    role = (role or "default").upper()
    return (
        os.getenv(f"BACKBOARD_ASSISTANT_{role}", "").strip()
        or os.getenv("BACKBOARD_ASSISTANT_ID", "").strip()
        or None
    )


def get_llm(max_tokens: int = 4096, agent_role: str = "default", json_mode: bool = False):
    """Return a fallback chain of available chat LLMs for the given agent role.

    The chain is tried per-call: if Backboard hits a credit gate or rate limit,
    the request automatically falls through to Gemma (local Ollama), then Google.

    json_mode=True constrains providers that support it (Ollama via format="json",
    Gemini via response_mime_type) to emit valid JSON. Use for agents whose
    prompts require parseable JSON output — small local models in particular
    benefit, since they often ignore "return only JSON" instructions.
    """
    llms:   list = []
    labels: list[str] = []

    # ── 1. Backboard.io — unified gateway, per-agent assistants ───────────────
    # Skipped when json_mode=True: Backboard's wrapper has no JSON-grammar
    # toggle, and the FallbackChain only falls through on *exception* — a
    # successful Backboard response that isn't parseable JSON would short-
    # circuit the chain before Ollama (which DOES support format="json")
    # ever sees the request. For JSON-strict callers (patch agent) we route
    # straight to Ollama / Gemini, both of which honor JSON mode.
    backboard_key = os.getenv("BACKBOARD_API_KEY", "").strip()
    if backboard_key and not json_mode:
        try:
            from core.backboard_llm import BackboardChat
            assistant_id = _backboard_assistant_for(agent_role)
            llms.append(BackboardChat(
                api_key=backboard_key,
                assistant_id=assistant_id,
                max_tokens=max_tokens,
            ))
            labels.append(f"Backboard[role={agent_role}, assistant={assistant_id or 'default'}]")
        except Exception as exc:
            logger.warning("Backboard init failed: %s", exc)

    # ── 2. Gemma 4 via Ollama — local, free inference ────────────────────────
    # Enabled by default; set OLLAMA_DISABLE=1 to skip. Override model/host via
    # OLLAMA_MODEL (default: gemma4:e2b) and OLLAMA_BASE_URL (default: localhost:11434).
    if not os.getenv("OLLAMA_DISABLE", "").strip():
        try:
            from langchain_community.chat_models import ChatOllama
            ollama_model = os.getenv("OLLAMA_MODEL", "gemma4:e2b").strip() or "gemma4:e2b"
            ollama_url   = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").strip()
            ollama_kwargs = dict(
                model=ollama_model,
                base_url=ollama_url,
                temperature=0,
                num_predict=max_tokens,
            )
            if json_mode:
                ollama_kwargs["format"] = "json"
            llms.append(ChatOllama(**ollama_kwargs))
            labels.append(f"Ollama[{ollama_model}{', json' if json_mode else ''}]")
        except Exception as exc:
            logger.warning("Ollama init failed: %s", exc)

    # ── 4. Google Gemini — last resort ───────────────────────────────────────
    google_key = os.getenv("GOOGLE_API_KEY", "").strip()
    if google_key:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            gemini_kwargs = dict(
                model="gemini-2.0-flash",
                google_api_key=google_key,
                max_output_tokens=max_tokens,
            )
            if json_mode:
                # Gemini 2.0 honors response_mime_type for structured output
                gemini_kwargs["model_kwargs"] = {"response_mime_type": "application/json"}
            llms.append(ChatGoogleGenerativeAI(**gemini_kwargs))
            labels.append(f"Google[gemini-2.0-flash{', json' if json_mode else ''}]")
        except Exception as exc:
            logger.warning("Google Gemini init failed: %s", exc)

    if not llms:
        raise RuntimeError(
            "No LLM available. Set one of: "
            "BACKBOARD_API_KEY, GOOGLE_API_KEY (or run Ollama locally with `ollama pull gemma4:e2b`)"
        )

    logger.info("LLM chain for role=%s: %s", agent_role, " → ".join(labels))
    return _FallbackChain(llms, labels)
