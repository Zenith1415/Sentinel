"""
Backboard.io chat model wrapper (LangChain-compatible).

Backboard exposes a stateful messages API (not OpenAI-compatible):
  POST https://app.backboard.io/api/threads/messages
  Headers: X-API-Key
  Body:    { content, thread_id?, assistant_id?, stream, memory }

This wrapper presents a minimal LangChain-style interface (`ainvoke` / `invoke`)
so the existing detection / patch agents can talk to Backboard without
changing any of their call sites.

Each agent in the pipeline can use a *different* Backboard assistant_id so
the per-assistant rate limit is shared across multiple buckets instead of one.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

from langchain_core.messages import (
    BaseMessage, SystemMessage, HumanMessage, AIMessage,
)

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = os.getenv("BACKBOARD_BASE_URL", "https://app.backboard.io/api")


class _BackboardResponse:
    """Mimics ChatModel response — only `.content` is consumed by callers."""
    def __init__(self, content: str):
        self.content = content


class BackboardChat:
    """LangChain-style chat client for Backboard.io.

    Args:
        api_key: Backboard API key (X-API-Key header).
        assistant_id: optional Backboard assistant UUID. Different assistants
            can be configured to use different underlying models — pass a
            distinct id per agent role to spread rate-limit budget.
        max_tokens: kept for API compatibility (Backboard doesn't expose it).
        base_url: override for the Backboard endpoint (testing).
        memory: "Auto" or "Off". "Off" makes calls effectively stateless,
            which matches the existing agents' expectations.
        timeout: per-request timeout in seconds.
    """
    def __init__(
        self,
        api_key: str,
        assistant_id: str | None = None,
        max_tokens: int = 4096,
        base_url: str | None = None,
        memory: str = "Off",
        timeout: float = 90.0,
    ):
        if not api_key:
            raise ValueError("Backboard requires an API key (BACKBOARD_API_KEY).")
        self._api_key      = api_key
        self._assistant_id = assistant_id or None
        self._max_tokens   = max_tokens
        self._base_url     = (base_url or _DEFAULT_BASE_URL).rstrip("/")
        self._memory       = memory
        self._timeout      = timeout

    # ------------------------------------------------------------------ #

    @staticmethod
    def _format_messages(messages: list[BaseMessage] | str) -> str:
        """Flatten a LangChain message list into a single Backboard `content` string."""
        if isinstance(messages, str):
            return messages
        parts: list[str] = []
        for m in messages:
            if isinstance(m, SystemMessage):
                parts.append(f"[SYSTEM]\n{m.content}")
            elif isinstance(m, HumanMessage):
                parts.append(f"[USER]\n{m.content}")
            elif isinstance(m, AIMessage):
                parts.append(f"[ASSISTANT]\n{m.content}")
            else:
                parts.append(str(getattr(m, "content", m)))
        return "\n\n".join(parts)

    def _request_body(self, content: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "content": content,
            "stream":  False,
            "memory":  self._memory,
        }
        if self._assistant_id:
            body["assistant_id"] = self._assistant_id
        return body

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "X-API-Key":    self._api_key,
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------ #
    # Async — used by every agent in this codebase
    # ------------------------------------------------------------------ #

    # Sentinel substrings that indicate Backboard rejected the chat request
    # despite returning HTTP 200 (e.g. free-tier credit gate).
    _CREDIT_GATE_MARKERS = (
        "purchase credits",
        "free credits can only be used",
        "out of credits",
        "no credits available",
    )

    async def ainvoke(self, messages, config=None, **kwargs) -> _BackboardResponse:
        content = self._format_messages(messages)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(
                f"{self._base_url}/threads/messages",
                json=self._request_body(content),
                headers=self._headers,
            )
            if r.status_code >= 400:
                raise RuntimeError(
                    f"Backboard {r.status_code}: {r.text[:300]}"
                )
            data = r.json()

        text = str(data.get("content", "")).strip()
        # Surface credit-gate / quota responses as exceptions so the LLM
        # factory can fall back to the next provider instead of returning
        # a useless string to downstream agents.
        low = text.lower()
        if any(m in low for m in self._CREDIT_GATE_MARKERS):
            raise RuntimeError(f"Backboard credit gate: {text}")
        return _BackboardResponse(text)

    def invoke(self, messages, config=None, **kwargs) -> _BackboardResponse:
        """Synchronous variant — uses sync httpx so it works from any thread
        without needing an event loop."""
        content = self._format_messages(messages)
        with httpx.Client(timeout=self._timeout) as client:
            r = client.post(
                f"{self._base_url}/threads/messages",
                json=self._request_body(content),
                headers=self._headers,
            )
            if r.status_code >= 400:
                raise RuntimeError(f"Backboard {r.status_code}: {r.text[:300]}")
            data = r.json()
        text = str(data.get("content", "")).strip()
        low = text.lower()
        if any(m in low for m in self._CREDIT_GATE_MARKERS):
            raise RuntimeError(f"Backboard credit gate: {text}")
        return _BackboardResponse(text)
