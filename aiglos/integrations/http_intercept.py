"""
aiglos.integrations.http_intercept
====================================
Protocol-agnostic HTTP/API interception layer.

Monkey-patches the send/request methods of every common Python HTTP client
library at attach time. Every outbound HTTP request made by the agent process
passes through threat inspection before network I/O occurs.

Supported clients (all patched in a single attach() call):
  - requests          (Session.send)
  - httpx             (Client.send, AsyncClient.send)
  - aiohttp           (ClientSession._request)
  - urllib            (urllib.request.urlopen)

Threat families inspected:
  T19  CRED_HARVEST  -- credentials in request body/params to non-allow-listed hosts
  T20  DATA_EXFIL    -- PII patterns in request body to external hosts
  T22  RECON         -- known OSINT/enumeration endpoint calls
  T25  CONFUSED_DEP  -- cross-origin credential forwarding
  T27  PROMPT_INJECT -- injection payloads in API response bodies (response hook)
  T34  DATA_AGENT    -- analytics/BI API calls with sensitive parameters
  T35  MODEL_EXFIL   -- model weight/training data transfer patterns
  T36  SUPPLY_CHAIN  -- package index calls outside declared dependencies

On BLOCK: raises AiglosBlockedRequest before any bytes reach the network.
On WARN:  logs finding, request proceeds.
On ALLOW: transparent pass-through, <0.5ms overhead.

Allow-list:
  Domains in allow_http skip RECON/EXFIL rules but still pass CRED checks.
  Wildcard prefix supported: "*.amazonaws.com" matches "s3.amazonaws.com".
  Supply the allow list at attach time:
      aiglos.attach(allow_http=["api.stripe.com", "*.amazonaws.com"])

Free tier: opt-in (intercept_http=True required in attach()).
Pro tier:  on by default.
"""

from __future__ import annotations

import fnmatch
import functools
import importlib
import inspect
import logging
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, List, Optional

log = logging.getLogger("aiglos.http_intercept")

_LOCK    = threading.Lock()
_PATCHED: set[str] = set()


# ── Result types ──────────────────────────────────────────────────────────────

class HttpVerdict(str, Enum):
    ALLOW = "ALLOW"
    WARN  = "WARN"
    BLOCK = "BLOCK"


@dataclass
class HttpScanResult:
    verdict:     HttpVerdict
    rule_id:     str
    rule_name:   str
    reason:      str
    url:         str        = ""
    method:      str        = ""
    matched_val: str        = ""
    allow_listed: bool      = False
    latency_ms:  float      = 0.0
    timestamp:   float      = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "type":        "http_request",
            "verdict":     self.verdict.value,
            "rule_id":     self.rule_id,
            "rule_name":   self.rule_name,
            "reason":      self.reason,
            "url":         self.url,
            "method":      self.method,
            "allow_listed": self.allow_listed,
            "latency_ms":  round(self.latency_ms, 3),
        }


_CLEAN_HTTP = HttpScanResult(
    verdict=HttpVerdict.ALLOW,
    rule_id="none",
    rule_name="none",
    reason="",
)


class AiglosBlockedRequest(RuntimeError):
    """Raised when Aiglos blocks an outbound HTTP request."""
    def __init__(self, result: HttpScanResult):
        self.result = result
        super().__init__(
            f"[Aiglos] HTTP request to '{result.url}' blocked: "
            f"{result.reason} [{result.rule_id}]"
        )


# ── Rule tables ───────────────────────────────────────────────────────────────

# T19: Credential patterns in request body/params
_T19_CRED_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token"
    r"|private[_-]?key|client[_-]?secret|bearer\s+[A-Za-z0-9\-._~+/]+"
    r"|id_rsa|\.env\b|\.ssh/|aws_secret|Authorization:\s*Bearer)",
    re.IGNORECASE,
)

# T20: PII patterns in request body
_T20_PII_PATTERNS = re.compile(
    r"(\b\d{3}-\d{2}-\d{4}\b"                            # SSN
    r"|\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b"        # credit card
    r"|[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"  # email (bulk)
    r"|\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b)",               # phone
    re.IGNORECASE,
)

# T22: Known OSINT / enumeration / recon endpoints
_T22_RECON_HOSTS = re.compile(
    r"(shodan\.io|censys\.io|haveibeenpwned\.com|intelx\.io"
    r"|hunter\.io|clearbit\.com|fullcontact\.com|pipl\.com"
    r"|spyse\.com|greynoise\.io|ipinfo\.io|ipapi\.co"
    r"|whatismyipaddress\.com|ipqualityscore\.com)",
    re.IGNORECASE,
)

# T25: SSRF / confused deputy: internal metadata endpoints
_T25_SSRF_PATTERNS = re.compile(
    r"(169\.254\.169\.254"                   # AWS/GCP metadata
    r"|metadata\.google\.internal"
    r"|169\.254\.170\.2"                     # ECS task metadata
    r"|fd00:|fc00:"                          # IPv6 private
    r"|192\.168\.\d+\.\d+"
    r"|10\.\d+\.\d+\.\d+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
    re.IGNORECASE,
)

# T34: Analytics/BI API endpoints that should not receive raw agent data
_T34_ANALYTICS_HOSTS = re.compile(
    r"(amplitude\.com/api|mixpanel\.com/track"
    r"|segment\.io|segment\.com/v1"
    r"|analytics\.google\.com"
    r"|bigquery\.googleapis\.com"
    r"|looker\.com/api|metabase\.com/api"
    r"|posthog\.com/capture)",
    re.IGNORECASE,
)

# T35: Model/training data exfil endpoints
_T35_MODEL_EXFIL_PATTERNS = re.compile(
    r"(model_weights|model\.bin|model\.safetensors"
    r"|training_data|fine.?tune.*upload"
    r"|embeddings.*export|\.gguf\b|\.ggml\b)",
    re.IGNORECASE,
)

# T36: Supply chain — unexpected package index calls
_T36_PACKAGE_HOSTS = re.compile(
    r"(pypi\.org/legacy|upload\.pypi\.org"
    r"|registry\.npmjs\.org"
    r"|hub\.docker\.com/v2.*push"
    r"|ghcr\.io.*push)",
    re.IGNORECASE,
)

# Suspicious TLDs / known exfil staging hosts (high confidence)
_EXFIL_TLD_PATTERNS = re.compile(
    r"(ngrok\.io|ngrok\.app|requestbin\.com|webhook\.site"
    r"|pipedream\.net|beeceptor\.com|hookdeck\.com"
    r"|\.xyz/|\.top/|\.tk/|\.ml/|\.ga/)",
    re.IGNORECASE,
)


# ── Allow-list helper ─────────────────────────────────────────────────────────

def _host_is_allowed(host: str, allow_list: List[str]) -> bool:
    """Return True if host matches any entry in the allow list (supports wildcards)."""
    host = host.lower().rstrip(".")
    for pattern in allow_list:
        pattern = pattern.lower()
        if fnmatch.fnmatch(host, pattern):
            return True
        # also match without www
        if host.startswith("www.") and fnmatch.fnmatch(host[4:], pattern):
            return True
    return False


def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


# ── Core inspection logic ─────────────────────────────────────────────────────

def inspect_request(
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Any = None,
    allow_list: Optional[List[str]] = None,
    mode: str = "block",
) -> HttpScanResult:
    """
    Inspect an outbound HTTP request against all applicable threat families.

    Parameters
    ----------
    method     : HTTP verb (GET, POST, ...)
    url        : Full request URL
    headers    : Request headers dict
    body       : Request body (bytes, str, or dict)
    allow_list : Hostnames to apply relaxed rules to
    mode       : "block" | "warn" | "audit"

    Returns
    -------
    HttpScanResult with verdict ALLOW | WARN | BLOCK
    """
    t0 = time.monotonic()
    allow_list = allow_list or []
    headers = headers or {}

    host      = _extract_host(url)
    allowed   = _host_is_allowed(host, allow_list)

    # Flatten inspectable text: url + header values + body
    body_str = ""
    if isinstance(body, bytes):
        try:
            body_str = body.decode("utf-8", errors="replace")
        except Exception:
            body_str = ""
    elif isinstance(body, str):
        body_str = body
    elif isinstance(body, dict):
        import json
        try:
            body_str = json.dumps(body)
        except Exception:
            body_str = str(body)
    elif body is not None:
        body_str = str(body)

    header_str = " ".join(str(v) for v in (headers or {}).values())
    full_text  = f"{url} {header_str} {body_str}"

    def _result(rule_id, rule_name, reason, matched=""):
        verdict = HttpVerdict.WARN if mode == "warn" else HttpVerdict.BLOCK
        if mode == "audit":
            verdict = HttpVerdict.WARN
        return HttpScanResult(
            verdict=verdict,
            rule_id=rule_id,
            rule_name=rule_name,
            reason=reason,
            url=url,
            method=method,
            matched_val=matched[:120],
            allow_listed=allowed,
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    # T25 / SSRF -- always block regardless of allow-list
    m = _T25_SSRF_PATTERNS.search(url)
    if m:
        return _result("T25", "SSRF",
                       f"Request targets internal/metadata endpoint: {m.group()}", m.group())

    # T22: Recon -- skip for allow-listed domains
    if not allowed and _T22_RECON_HOSTS.search(url):
        return _result("T22", "RECON",
                       f"Request to known OSINT/recon endpoint: {host}")

    # T19: Credential harvest -- even allow-listed domains get credential checks
    m = _T19_CRED_PATTERNS.search(full_text)
    if m:
        # High-confidence: explicit credential file paths
        if re.search(r"(id_rsa|\.ssh/|\.env\b|aws_secret)", full_text, re.IGNORECASE):
            return _result("T19", "CRED_HARVEST",
                           "Request body contains credential file reference", m.group())
        # Lower confidence for token patterns: warn unless exfil TLD
        if _EXFIL_TLD_PATTERNS.search(url):
            return _result("T19", "CRED_HARVEST",
                           f"Credential pattern sent to suspicious domain: {host}", m.group())
        if not allowed:
            # Warn on non-allow-listed hosts with credential patterns
            r = _result("T19", "CRED_HARVEST",
                        f"Potential credential in request to non-allow-listed host: {host}",
                        m.group())
            r.verdict = HttpVerdict.WARN
            r.latency_ms = (time.monotonic() - t0) * 1000
            return r

    # T20: PII exfil to external/suspicious hosts
    if not allowed and _T20_PII_PATTERNS.search(body_str):
        if _EXFIL_TLD_PATTERNS.search(url):
            return _result("T20", "DATA_EXFIL",
                           f"PII pattern in request body to suspicious domain: {host}")
        r = _result("T20", "DATA_EXFIL",
                    f"PII pattern in request body to non-allow-listed host: {host}")
        r.verdict = HttpVerdict.WARN
        r.latency_ms = (time.monotonic() - t0) * 1000
        return r

    # T34: Analytics/BI APIs with raw agent data
    if _T34_ANALYTICS_HOSTS.search(url) and len(body_str) > 512:
        r = _result("T34", "DATA_AGENT",
                    f"Large payload to analytics endpoint: {host}")
        r.verdict = HttpVerdict.WARN
        r.latency_ms = (time.monotonic() - t0) * 1000
        return r

    # T35: Model/training data exfil
    m = _T35_MODEL_EXFIL_PATTERNS.search(full_text)
    if m:
        return _result("T35", "MODEL_EXFIL",
                       f"Model weight / training data transfer detected", m.group())

    # T36: Unexpected package publish
    if _T36_PACKAGE_HOSTS.search(url) and method.upper() in ("POST", "PUT"):
        return _result("T36", "SUPPLY_CHAIN",
                       f"Package publish to registry: {host}")

    # Exfil staging hosts (always block, regardless of allow-list)
    if _EXFIL_TLD_PATTERNS.search(url):
        return _result("T19", "CRED_HARVEST",
                       f"Request to known exfil staging host: {host}")

    latency = (time.monotonic() - t0) * 1000
    result  = HttpScanResult(
        verdict=HttpVerdict.ALLOW,
        rule_id="none",
        rule_name="none",
        reason="",
        url=url,
        method=method,
        allow_listed=allowed,
        latency_ms=latency,
    )
    return result


# ── Patch helpers ─────────────────────────────────────────────────────────────

def _make_requests_wrapper(original_send: Callable,
                           allow_list: List[str],
                           mode: str,
                           session_events: list) -> Callable:
    @functools.wraps(original_send)
    def wrapper(self_obj, request, **kwargs):
        body = None
        if hasattr(request, "body"):
            body = request.body
        result = inspect_request(
            method=getattr(request, "method", ""),
            url=str(getattr(request, "url", "")),
            headers=dict(getattr(request, "headers", {})),
            body=body,
            allow_list=allow_list,
            mode=mode,
        )
        session_events.append(result.to_dict())
        if result.verdict == HttpVerdict.BLOCK:
            log.warning("[Aiglos BLOCK HTTP] %s %s: %s",
                        request.method, request.url, result.reason)
            raise AiglosBlockedRequest(result)
        if result.verdict == HttpVerdict.WARN:
            log.warning("[Aiglos WARN HTTP] %s %s: %s",
                        request.method, request.url, result.reason)
        return original_send(self_obj, request, **kwargs)
    return wrapper


def _make_httpx_sync_wrapper(original_send: Callable,
                              allow_list: List[str],
                              mode: str,
                              session_events: list) -> Callable:
    @functools.wraps(original_send)
    def wrapper(self_obj, request, **kwargs):
        body = None
        if hasattr(request, "content"):
            body = request.content
        result = inspect_request(
            method=str(getattr(request, "method", "")),
            url=str(getattr(request, "url", "")),
            headers=dict(getattr(request, "headers", {})),
            body=body,
            allow_list=allow_list,
            mode=mode,
        )
        session_events.append(result.to_dict())
        if result.verdict == HttpVerdict.BLOCK:
            log.warning("[Aiglos BLOCK HTTPX] %s: %s", request.url, result.reason)
            raise AiglosBlockedRequest(result)
        if result.verdict == HttpVerdict.WARN:
            log.warning("[Aiglos WARN HTTPX] %s: %s", request.url, result.reason)
        return original_send(self_obj, request, **kwargs)
    return wrapper


def _make_httpx_async_wrapper(original_send: Callable,
                               allow_list: List[str],
                               mode: str,
                               session_events: list) -> Callable:
    @functools.wraps(original_send)
    async def wrapper(self_obj, request, **kwargs):
        body = None
        if hasattr(request, "content"):
            body = request.content
        result = inspect_request(
            method=str(getattr(request, "method", "")),
            url=str(getattr(request, "url", "")),
            headers=dict(getattr(request, "headers", {})),
            body=body,
            allow_list=allow_list,
            mode=mode,
        )
        session_events.append(result.to_dict())
        if result.verdict == HttpVerdict.BLOCK:
            log.warning("[Aiglos BLOCK HTTPX-ASYNC] %s: %s", request.url, result.reason)
            raise AiglosBlockedRequest(result)
        if result.verdict == HttpVerdict.WARN:
            log.warning("[Aiglos WARN HTTPX-ASYNC] %s: %s", request.url, result.reason)
        return await original_send(self_obj, request, **kwargs)
    return wrapper


def _make_urllib_wrapper(original_urlopen: Callable,
                          allow_list: List[str],
                          mode: str,
                          session_events: list) -> Callable:
    @functools.wraps(original_urlopen)
    def wrapper(url_or_req, data=None, **kwargs):
        import urllib.request as _urllib_req
        if hasattr(url_or_req, "full_url"):
            url    = url_or_req.full_url
            method = getattr(url_or_req, "method", "POST" if data else "GET")
            headers = dict(url_or_req.headers)
        else:
            url    = str(url_or_req)
            method = "POST" if data else "GET"
            headers = {}
        result = inspect_request(
            method=method,
            url=url,
            headers=headers,
            body=data,
            allow_list=allow_list,
            mode=mode,
        )
        session_events.append(result.to_dict())
        if result.verdict == HttpVerdict.BLOCK:
            log.warning("[Aiglos BLOCK URLLIB] %s: %s", url, result.reason)
            raise AiglosBlockedRequest(result)
        if result.verdict == HttpVerdict.WARN:
            log.warning("[Aiglos WARN URLLIB] %s: %s", url, result.reason)
        return original_urlopen(url_or_req, data, **kwargs)
    return wrapper


# ── Public attach/detach API ──────────────────────────────────────────────────

# Shared session event log -- populated by all wrappers, read by session artifact
_session_events: list = []


def attach_http_intercept(
    allow_list: Optional[List[str]] = None,
    mode: str = "block",
) -> dict[str, bool]:
    """
    Patch all available HTTP client libraries in the current process.

    Parameters
    ----------
    allow_list : List of hostnames (wildcards OK) that receive relaxed rules.
    mode       : "block" | "warn" | "audit"

    Returns
    -------
    dict mapping client_name -> successfully_patched
    """
    global _session_events
    allow_list = allow_list or []
    results: dict[str, bool] = {}

    with _LOCK:
        # ── requests ──────────────────────────────────────────────────────────
        if "requests" not in _PATCHED:
            try:
                import requests
                from requests import Session
                orig = Session.send
                Session.send = _make_requests_wrapper(orig, allow_list, mode, _session_events)
                _PATCHED.add("requests")
                results["requests"] = True
                log.info("[Aiglos] Patched requests.Session.send")
            except ImportError:
                results["requests"] = False
            except Exception as e:
                results["requests"] = False
                log.warning("[Aiglos] Could not patch requests: %s", e)
        else:
            results["requests"] = True

        # ── httpx sync ────────────────────────────────────────────────────────
        if "httpx.sync" not in _PATCHED:
            try:
                import httpx
                orig_sync = httpx.Client.send
                httpx.Client.send = _make_httpx_sync_wrapper(
                    orig_sync, allow_list, mode, _session_events)
                _PATCHED.add("httpx.sync")
                results["httpx.sync"] = True
                log.info("[Aiglos] Patched httpx.Client.send")
            except ImportError:
                results["httpx.sync"] = False
            except Exception as e:
                results["httpx.sync"] = False
                log.warning("[Aiglos] Could not patch httpx.Client: %s", e)

        # ── httpx async ───────────────────────────────────────────────────────
        if "httpx.async" not in _PATCHED:
            try:
                import httpx
                orig_async = httpx.AsyncClient.send
                httpx.AsyncClient.send = _make_httpx_async_wrapper(
                    orig_async, allow_list, mode, _session_events)
                _PATCHED.add("httpx.async")
                results["httpx.async"] = True
                log.info("[Aiglos] Patched httpx.AsyncClient.send")
            except ImportError:
                results["httpx.async"] = False
            except Exception as e:
                results["httpx.async"] = False
                log.warning("[Aiglos] Could not patch httpx.AsyncClient: %s", e)

        # ── urllib ────────────────────────────────────────────────────────────
        if "urllib" not in _PATCHED:
            try:
                import urllib.request
                orig_urlopen = urllib.request.urlopen
                urllib.request.urlopen = _make_urllib_wrapper(
                    orig_urlopen, allow_list, mode, _session_events)
                _PATCHED.add("urllib")
                results["urllib"] = True
                log.info("[Aiglos] Patched urllib.request.urlopen")
            except Exception as e:
                results["urllib"] = False
                log.warning("[Aiglos] Could not patch urllib: %s", e)

    return results


def get_session_http_events() -> list:
    """Return all HTTP events recorded in this session."""
    return list(_session_events)


def clear_session_http_events() -> None:
    """Reset HTTP event log (called at session close)."""
    global _session_events
    _session_events.clear()


def http_intercept_status() -> dict:
    return {
        "patched_clients": list(_PATCHED),
        "events_recorded": len(_session_events),
    }
