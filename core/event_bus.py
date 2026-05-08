"""
Redis Streams event bus for the healing pipeline.
"""
import hashlib
import json
import os
import time
from typing import Any, Callable, Generator, Tuple

import redis

# ---------------------------------------------------------------------------
# Topic constants
# ---------------------------------------------------------------------------
CONTRACT_SUBMITTED   = "contract.submitted"
DETECTION_COMPLETE   = "detection.complete"
CORRELATION_COMPLETE = "correlation.complete"
PATCH_GENERATED      = "patch.generated"
VALIDATION_RESULT    = "validation.result"
DEPLOY_COMPLETE      = "deploy.complete"
MONITOR_ANOMALY      = "monitor.anomaly"
RL_REWARD            = "rl.reward"

_DLQ_STREAM        = "dlq:failed"
_IDEMPOTENCY_SET   = "idempotency:seen"
_IDEMPOTENCY_TTL   = 86400  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _d(v: bytes | str) -> str:
    return v.decode() if isinstance(v, bytes) else v


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------

class EventBus:
    def __init__(self, url: str | None = None, _client=None):
        """
        Pass _client for testing (e.g. fakeredis.FakeRedis()).
        Otherwise a real Redis connection is created from url / REDIS_URL env var.
        """
        self._r = _client if _client is not None else redis.from_url(
            url or os.getenv("REDIS_URL", "redis://localhost:6379")
        )

    # ------------------------------------------------------------------
    # Idempotency key
    # ------------------------------------------------------------------

    def _ikey(self, topic: str, pipeline_id: str, data: dict) -> str:
        h = hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()[:16]
        return f"{topic}:{pipeline_id}:{h}"

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(self, topic: str, pipeline_id: str, data: dict) -> str:
        """
        Publish data to topic stream.
        Every message carries an idempotency_key derived from
        (topic, pipeline_id, sha256(data)).
        Returns the Redis stream entry ID.
        """
        ikey = self._ikey(topic, pipeline_id, data)
        entry = {
            "pipeline_id":     pipeline_id,
            "idempotency_key": ikey,
            "payload":         json.dumps(data),
            "published_at":    str(time.time()),
        }
        return _d(self._r.xadd(topic, entry))

    # ------------------------------------------------------------------
    # Subscribe (generator)
    # ------------------------------------------------------------------

    def subscribe(
        self,
        topic: str,
        group: str = "default",
        consumer: str = "worker-1",
        block_ms: int = 0,
    ) -> Generator[Tuple[str, dict], None, None]:
        """
        Yield (pipeline_id, data) for each unprocessed message on topic.
        Duplicate messages (same idempotency_key) are silently skipped.
        block_ms=0  → non-blocking (drain existing messages and return)
        block_ms>0  → block for that many milliseconds waiting for new messages
        """
        try:
            self._r.xgroup_create(topic, group, id="0", mkstream=True)
        except redis.exceptions.ResponseError:
            pass  # group already exists

        while True:
            if block_ms and block_ms > 0:
                messages = self._r.xreadgroup(
                    group, consumer, {topic: ">"}, count=10, block=block_ms
                )
            else:
                messages = self._r.xreadgroup(
                    group, consumer, {topic: ">"}, count=10
                )

            if not messages:
                return

            for _, entries in messages:
                for entry_id, fields in entries:
                    ikey = _d(fields.get(b"idempotency_key", b""))

                    # Idempotency gate
                    if self._r.sismember(_IDEMPOTENCY_SET, ikey):
                        self._r.xack(topic, group, entry_id)
                        continue

                    self._r.sadd(_IDEMPOTENCY_SET, ikey)
                    self._r.expire(_IDEMPOTENCY_SET, _IDEMPOTENCY_TTL)
                    self._r.xack(topic, group, entry_id)

                    pipeline_id = _d(fields.get(b"pipeline_id", b""))
                    payload = json.loads(_d(fields.get(b"payload", b"{}")))
                    yield pipeline_id, payload

    # ------------------------------------------------------------------
    # Process (handler-based — sends failures to DLQ)
    # ------------------------------------------------------------------

    def process(
        self,
        topic: str,
        handler: Callable[[str, dict], Any],
        group: str = "default",
        consumer: str = "worker-1",
        block_ms: int = 0,
    ) -> None:
        """
        Consume topic with handler(pipeline_id, data).
        On any exception the message is sent to the dead letter queue.
        """
        for pipeline_id, data in self.subscribe(topic, group, consumer, block_ms):
            try:
                handler(pipeline_id, data)
            except Exception as exc:
                self.send_to_dlq(topic, pipeline_id, data, repr(exc))

    # ------------------------------------------------------------------
    # Dead letter queue
    # ------------------------------------------------------------------

    def send_to_dlq(
        self,
        source_topic: str,
        pipeline_id: str,
        data: dict,
        error: str,
    ) -> str:
        """Explicitly move a message to the dead letter queue stream."""
        entry = {
            "source_topic": source_topic,
            "pipeline_id":  pipeline_id,
            "payload":      json.dumps(data),
            "error":        error,
            "failed_at":    str(time.time()),
        }
        return _d(self._r.xadd(_DLQ_STREAM, entry))

    def read_dlq(self, count: int = 100) -> list[dict]:
        """Return all messages currently in the dead letter queue."""
        messages = self._r.xread({_DLQ_STREAM: "0"}, count=count)
        if not messages:
            return []
        results = []
        for _, entries in messages:
            for _, fields in entries:
                results.append({_d(k): _d(v) for k, v in fields.items()})
        return results

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        try:
            return bool(self._r.ping())
        except Exception:
            return False
