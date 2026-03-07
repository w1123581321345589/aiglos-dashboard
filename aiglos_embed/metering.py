"""
aiglos.metering
Usage metering client.

Records every tool call to the Aiglos cloud for:
  - Cloud telemetry (Pro tier and above; free tier runs local-only)
  - Threat telemetry (blocked events, findings)
  - Session attestation feed

Design constraints:
  - NEVER blocks the agent call path
  - NEVER raises exceptions to the caller
  - Batches events for network efficiency
  - Falls back to local-only in-memory counter when API key absent (free tier)
  - Graceful degradation: if network unavailable, buffers up to 1,000 events
    then drops oldest

Events emitted:
  tool_call    -- every call intercepted (CLEAN, WARN, or BLOCK)
  block_event  -- every BLOCK verdict (tracked for telemetry)
  session_end  -- emitted when session context is closed
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any

from .config import AiglosConfig
from .scanner import ScanResult, ScanVerdict

log = logging.getLogger("aiglos.metering")

_MAX_BUFFER = 1_000
_BATCH_SIZE = 50
_FLUSH_INTERVAL_SECONDS = 30.0


@dataclass
class UsageEvent:
    event_type: str
    tool_name: str
    verdict: str
    risk_type: str
    api_key: str | None
    timestamp: float
    latency_ms: float
    session_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class MeterClient:
    """
    Thread-safe usage metering client with async support.

    Free-tier (no API key): counts locally, no network calls.
    Paid-tier (API key set): batches events and sends to aiglos.io/v1/events.
    """

    def __init__(self, config: AiglosConfig | None = None):
        self.config = config or AiglosConfig.from_env()
        self._buffer: deque[UsageEvent] = deque(maxlen=_MAX_BUFFER)
        self._lock = threading.Lock()
        self._call_count = 0
        self._block_count = 0
        self._free_tier_warned = False
        self._flush_thread: threading.Thread | None = None
        if self.config.api_key:
            self._start_flush_thread()

    def record(self, tool_name: str, args: dict, result: ScanResult,
               config: AiglosConfig | None = None) -> None:
        cfg = config or self.config
        with self._lock:
            self._call_count += 1
            if result.verdict == ScanVerdict.BLOCK:
                self._block_count += 1

            if cfg.is_free_tier and self._call_count > cfg.free_limit:
                if not self._free_tier_warned:
                    log.warning(
                        "[Aiglos] Free tier limit (%d tool calls/month) reached. "
                        "Set AIGLOS_KEY to continue. Visit aiglos.io to sign up.",
                        cfg.free_limit
                    )
                    self._free_tier_warned = True
                return

            if not cfg.api_key:
                return

            event = UsageEvent(
                event_type="block_event" if result.verdict == ScanVerdict.BLOCK else "tool_call",
                tool_name=tool_name,
                verdict=result.verdict.value,
                risk_type=result.risk_type,
                api_key=cfg.api_key,
                timestamp=time.time(),
                latency_ms=result.latency_ms,
            )
            self._buffer.append(event)

    async def record_async(self, tool_name: str, args: dict, result: ScanResult,
                           config: AiglosConfig | None = None) -> None:
        self.record(tool_name, args, result, config)
        if len(self._buffer) >= _BATCH_SIZE:
            await self._flush_async()

    def _start_flush_thread(self):
        def _run():
            while True:
                time.sleep(_FLUSH_INTERVAL_SECONDS)
                self._flush_sync()
        t = threading.Thread(target=_run, daemon=True, name="aiglos-meter-flush")
        t.start()
        self._flush_thread = t

    def _flush_sync(self):
        batch = self._drain_batch()
        if not batch:
            return
        try:
            self._post_batch(batch)
        except Exception as exc:
            log.debug("[Aiglos] Meter flush failed: %s", exc)
            with self._lock:
                for ev in reversed(batch):
                    self._buffer.appendleft(ev)

    async def _flush_async(self):
        batch = self._drain_batch()
        if not batch:
            return
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, self._post_batch, batch
            )
        except Exception as exc:
            log.debug("[Aiglos] Async meter flush failed: %s", exc)

    def _drain_batch(self) -> list[UsageEvent]:
        with self._lock:
            batch = []
            for _ in range(min(_BATCH_SIZE, len(self._buffer))):
                if self._buffer:
                    batch.append(self._buffer.popleft())
            return batch

    def _post_batch(self, batch: list[UsageEvent]):
        if not self.config.api_key:
            return
        payload = json.dumps({
            "api_key": self.config.api_key,
            "events": [e.to_dict() for e in batch],
        }).encode()
        url = f"{self.config.endpoint}/events"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Aiglos-Key": self.config.api_key,
                "X-Aiglos-Version": "1.0.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                log.debug("[Aiglos] Meter flushed %d events, status %d",
                          len(batch), resp.status)
        except Exception as exc:
            log.debug("[Aiglos] Meter POST failed (will retry): %s", exc)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "call_count": self._call_count,
                "block_count": self._block_count,
                "buffer_depth": len(self._buffer),
                "free_tier": self.config.is_free_tier,
                "free_tier_remaining": max(
                    0, self.config.free_limit - self._call_count
                ) if self.config.is_free_tier else None,
            }
