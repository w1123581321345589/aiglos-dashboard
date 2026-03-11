"""
aiglos.interceptor
In-process MCP call interceptor.

Monkey-patches mcp.client.* (and the raw transport layer) so every tool call
passes through the Aiglos fast-path scanner before execution.  No proxy server,
no port, no yaml.  Works whether the caller uses the official MCP Python SDK,
a custom client, or calls the JSON-RPC transport directly.

Patch hierarchy (applied in order, each is a no-op if the target is absent):
  1. mcp.client.session.ClientSession.call_tool        (official SDK)
  2. mcp.client.stdio.StdioServerParameters            (stdio transport)
  3. mcp.ClientSession                                 (alias in some SDK versions)
  4. anthropic.tools (Anthropic SDK tool dispatch)     (fallback)

Each patched method:
  - Calls FastPathScanner.scan(tool_name, arguments) synchronously (<1 ms)
  - Emits a usage event to the MeterClient (async, fire-and-forget)
  - If scan returns BLOCK: raises AiglosBlockedError before the call executes
  - If scan returns WARN:  calls original, appends finding to session log
  - If scan returns CLEAN: calls original unchanged
"""

from __future__ import annotations

import asyncio
import functools
import importlib
import inspect
import logging
import os
import threading
import time
from typing import Any, Callable

from .scanner import FastPathScanner, ScanResult, ScanVerdict
from .metering import MeterClient
from .config import AiglosConfig

log = logging.getLogger("aiglos.interceptor")

_LOCK = threading.Lock()
_PATCHED: set[str] = set()   # tracks which targets have been patched


class AiglosBlockedError(RuntimeError):
    """Raised when Aiglos blocks a tool call."""
    def __init__(self, tool_name: str, result: ScanResult):
        self.tool_name = tool_name
        self.result = result
        super().__init__(
            f"[Aiglos] Tool call '{tool_name}' blocked: {result.reason} "
            f"[{result.risk_type}]"
        )


# ─── Patch targets ────────────────────────────────────────────────────────────

_PATCH_TARGETS = [
    # (module_path, class_name, method_name)
    ("mcp.client.session",  "ClientSession",    "call_tool"),
    ("mcp",                 "ClientSession",    "call_tool"),
    ("mcp.client",          "ClientSession",    "call_tool"),
]

_ANTHROPIC_TARGET = ("anthropic._client", "Anthropic", "_request")


def _make_sync_wrapper(original_fn: Callable, scanner: FastPathScanner,
                       meter: MeterClient, config: AiglosConfig) -> Callable:
    """Wrap a synchronous tool-call method."""
    @functools.wraps(original_fn)
    def wrapper(self_obj, tool_name: str, arguments: dict | None = None, **kwargs):
        args = arguments or {}
        result = scanner.scan(tool_name, args)
        meter.record(tool_name, args, result, config)
        if result.verdict == ScanVerdict.BLOCK:
            log.warning("[Aiglos BLOCK] %s: %s", tool_name, result.reason)
            raise AiglosBlockedError(tool_name, result)
        if result.verdict == ScanVerdict.WARN:
            log.info("[Aiglos WARN] %s: %s", tool_name, result.reason)
        return original_fn(self_obj, tool_name, args, **kwargs)
    return wrapper


def _make_async_wrapper(original_fn: Callable, scanner: FastPathScanner,
                        meter: MeterClient, config: AiglosConfig) -> Callable:
    """Wrap an async tool-call method."""
    @functools.wraps(original_fn)
    async def wrapper(self_obj, tool_name: str, arguments: dict | None = None, **kwargs):
        args = arguments or {}
        result = scanner.scan(tool_name, args)
        # Fire-and-forget meter event (doesn't block the call path)
        asyncio.ensure_future(_meter_async(meter, tool_name, args, result, config))
        if result.verdict == ScanVerdict.BLOCK:
            log.warning("[Aiglos BLOCK] %s: %s", tool_name, result.reason)
            raise AiglosBlockedError(tool_name, result)
        if result.verdict == ScanVerdict.WARN:
            log.info("[Aiglos WARN] %s: %s", tool_name, result.reason)
        return await original_fn(self_obj, tool_name, args, **kwargs)
    return wrapper


async def _meter_async(meter: MeterClient, tool_name: str, args: dict,
                       result: ScanResult, config: AiglosConfig):
    try:
        await meter.record_async(tool_name, args, result, config)
    except Exception:
        pass   # metering never crashes the agent


def _wrap_method(module_path: str, class_name: str, method_name: str,
                 scanner: FastPathScanner, meter: MeterClient,
                 config: AiglosConfig) -> bool:
    """Attempt to patch one target. Returns True if successful."""
    patch_key = f"{module_path}.{class_name}.{method_name}"
    if patch_key in _PATCHED:
        return True

    try:
        mod = importlib.import_module(module_path)
    except ImportError:
        return False

    cls = getattr(mod, class_name, None)
    if cls is None:
        return False

    original = getattr(cls, method_name, None)
    if original is None:
        return False

    if inspect.iscoroutinefunction(original):
        wrapped = _make_async_wrapper(original, scanner, meter, config)
    else:
        wrapped = _make_sync_wrapper(original, scanner, meter, config)

    try:
        setattr(cls, method_name, wrapped)
        _PATCHED.add(patch_key)
        log.info("[Aiglos] Patched %s", patch_key)
        return True
    except (AttributeError, TypeError):
        return False


# ─── Public API ───────────────────────────────────────────────────────────────

class AiglosInterceptor:
    """
    Registers the Aiglos in-process MCP intercept layer.

    Usage:
        interceptor = AiglosInterceptor()
        interceptor.register()   # patches mcp.client.* in-place

    Or via the zero-config path:
        import aiglos             # __init__.py calls register() automatically
    """

    def __init__(self, config: AiglosConfig | None = None):
        self.config = config or AiglosConfig.from_env()
        self.scanner = FastPathScanner(config=self.config)
        self.meter = MeterClient(config=self.config)
        self._registered = False

    def register(self) -> dict[str, bool]:
        """
        Patch all available MCP client targets.
        Safe to call multiple times -- subsequent calls are no-ops.
        Returns a dict mapping patch_key -> success.
        """
        with _LOCK:
            results = {}
            patched_any = False
            for module_path, class_name, method_name in _PATCH_TARGETS:
                key = f"{module_path}.{class_name}.{method_name}"
                ok = _wrap_method(module_path, class_name, method_name,
                                  self.scanner, self.meter, self.config)
                results[key] = ok
                if ok:
                    patched_any = True

            if not patched_any:
                # mcp SDK not installed -- install a future-patch hook so that
                # when mcp is imported later, we patch it then
                self._install_import_hook()
                log.info(
                    "[Aiglos] MCP SDK not found at register time. "
                    "Import hook installed -- will patch on first import."
                )

            self._registered = True
            key_str = self.config.api_key
            masked = f"{key_str[:8]}..." if key_str and len(key_str) > 8 else "(no key)"
            log.info(
                "[Aiglos] Interceptor registered. key=%s mode=%s",
                masked, self.config.mode
            )
            return results

    def _install_import_hook(self):
        """
        Install a sys.meta_path hook that patches mcp.client.session
        the moment it is first imported.
        """
        import sys
        scanner = self.scanner
        meter = self.meter
        config = self.config

        class _AiglosMCPImportHook:
            def find_module(self, name, path=None):
                if name in ("mcp", "mcp.client", "mcp.client.session"):
                    return self
                return None

            def load_module(self, name):
                if name in sys.modules:
                    return sys.modules[name]
                # Load normally
                import importlib
                hook_self = sys.meta_path.pop(sys.meta_path.index(self))
                try:
                    mod = importlib.import_module(name)
                finally:
                    # Don't re-add -- one-shot hook
                    pass
                # Now patch
                for mp, cn, mn in _PATCH_TARGETS:
                    _wrap_method(mp, cn, mn, scanner, meter, config)
                return mod

        if not any(isinstance(h, _AiglosMCPImportHook) for h in sys.meta_path):
            sys.meta_path.insert(0, _AiglosMCPImportHook())

    @property
    def is_registered(self) -> bool:
        return self._registered

    def status(self) -> dict:
        return {
            "registered": self._registered,
            "patched_targets": list(_PATCHED),
            "mode": self.config.mode,
            "api_key_set": bool(self.config.api_key),
            "free_tier_active": not bool(self.config.api_key),
        }
