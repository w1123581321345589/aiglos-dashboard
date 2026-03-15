"""
Aiglos — AI Agent Security Runtime
===================================
Protocol-agnostic runtime security for AI agents. Intercepts every agent
action before execution — MCP tool calls, direct HTTP/API calls, CLI
execution, subprocess spawning — and applies T1–T36 threat detection.

Signed session artifacts cover all three execution surfaces in a single
compliance document. compliance artifact ready.

Quick start:
    import aiglos
    aiglos.attach(
        agent_name="my-agent",
        api_key=KEY,
        intercept_http=True,                    # optional: HTTP/API layer
        allow_http=["api.stripe.com"],          # optional: allow-list
        intercept_subprocess=True,              # optional: subprocess layer
        subprocess_tier3_mode="pause",          # optional: block | pause | warn
        tier3_approval_webhook="https://...",   # optional: PagerDuty / Slack
    )

    # MCP tool call inspection (manual API)
    result = aiglos.check("terminal", {"cmd": cmd})
    if result.blocked:
        raise RuntimeError(result.reason)

    aiglos.on_heartbeat()          # call at each cron/heartbeat cycle
    artifact = aiglos.close()      # signed session artifact -- all 3 surfaces

Framework integrations:
    from aiglos.integrations.openclaw import OpenClawGuard
    from aiglos.integrations.hermes   import HermesGuard
"""


import logging
from typing import Any, Dict, List, Optional

try:
    from importlib.metadata import version as _pkg_version
    _v = _pkg_version("aiglos")
    # importlib.metadata may return stale egg-info in dev installs;
    # if it looks stale (< 0.10), trust the hardcoded value instead.
    import re as _re
    _parts = [int(x) for x in _re.findall(r"\d+", _v)]
    if _parts and _parts[0] == 0 and (len(_parts) < 2 or _parts[1] < 10):
        raise ValueError("stale")
    __version__: str = _v
except Exception:
    __version__ = "0.10.0"  # canonical version for this release
__author__  = "Aiglos"
__email__   = "will@aiglos.io"
__license__ = "MIT"

log = logging.getLogger("aiglos")

# Re-export key types for external use
from aiglos.integrations.openclaw import (   # noqa: F401
    OpenClawGuard,
    SessionArtifact,
    GuardResult as CheckResult,
)
from aiglos.integrations.openclaw import (
    attach   as _oc_attach,
    check    as _oc_check,
    close    as _oc_close,
)
from aiglos.integrations.hermes import (     # noqa: F401
    HermesGuard,
)
from aiglos.integrations.multi_agent import (  # noqa: F401
    MultiAgentRegistry,
    AgentDefGuard,
    SessionIdentityChain,
    SpawnEvent,
    AgentDefViolation,
)
from aiglos.adaptive import (  # noqa: F401
    AdaptiveEngine,
    ObservationGraph,
    InspectionEngine,
    AmendmentEngine,
    PolicySerializer,
    SessionPolicy,
    CampaignAnalyzer,
    CampaignResult,
    MemoryProvenanceGraph,
    CrossSessionRisk,
    BeliefDriftReport,
)
from aiglos.integrations.memory_guard import (  # noqa: F401
    MemoryWriteGuard,
    MemoryWriteResult,
    inspect_memory_write,
    is_memory_tool,
)
from aiglos.core.intent_predictor import (  # noqa: F401
    IntentPredictor,
    PredictionResult,
    MarkovTransitionModel,
)
from aiglos.core.threat_forecast import (  # noqa: F401
    SessionForecaster,
    ForecastAdjustment,
    ForecastSnapshot,
)
from aiglos.core.causal_tracer import (  # noqa: F401
    CausalTracer,
    CausalChain,
    AttributionResult,
    ContextEntry,
    TaggedAction,
)
from aiglos.integrations.injection_scanner import (  # noqa: F401
    InjectionScanner,
    InjectionScanResult,
    scan_tool_output,
    score_content,
    is_injection,
)
from aiglos.integrations.rl_guard import (  # noqa: F401
    RLFeedbackGuard,
    RLFeedbackResult,
    score_opd_feedback,
    is_reward_poison,
)
from aiglos.autoresearch.coupling import (  # noqa: F401
    SecurityAwareReward,
    CoupledRewardResult,
)


# ---------------------------------------------------------------------------
# Module-level generic API  (framework-agnostic)
# ---------------------------------------------------------------------------

_http_intercept_active:    bool = False
_subproc_intercept_active: bool = False
_multi_agent_registry:     Optional["MultiAgentRegistry"] = None
_agent_def_guard:          Optional["AgentDefGuard"]      = None
_session_identity:         Optional["SessionIdentityChain"] = None
_adaptive_engine:          Optional["AdaptiveEngine"]     = None


def attach(
    agent_name:             str            = "aiglos",
    policy:                 str            = "enterprise",
    log_path:               str            = "./aiglos.log",
    # HTTP/API interception
    intercept_http:         bool           = False,
    allow_http:             Optional[List[str]] = None,
    # Subprocess interception
    intercept_subprocess:   bool           = False,
    subprocess_tier3_mode:  str            = "warn",
    tier3_approval_webhook: Optional[str]  = None,
    # Multi-agent (v0.3.0)
    enable_multi_agent:     bool           = True,
    guard_agent_defs:       bool           = True,
    session_id:             Optional[str]  = None,
    # Adaptive layer (v0.4.0)
    enable_adaptive:        bool           = True,
    adaptive_db_path:       Optional[str]  = None,
    **kwargs,
) -> "OpenClawGuard":
    """
    Attach Aiglos to the current session.

    Activates the MCP interception layer unconditionally.
    Optionally activates HTTP/API, subprocess, and multi-agent layers.

    v0.3.0 adds: multi-agent spawn registry, agent definition file integrity
    guard (T36_AGENTDEF), session identity chain (HMAC-signed events), T37
    financial transaction detection, and T38 sub-agent spawn classification.
    """
    global _http_intercept_active, _subproc_intercept_active
    global _multi_agent_registry, _agent_def_guard, _session_identity

    # 1. Always activate MCP layer
    guard = _oc_attach(agent_name=agent_name, policy=policy, log_path=log_path)

    # 2. HTTP/API interception
    import os
    _env_http = os.environ.get("AIGLOS_INTERCEPT_HTTP", "").strip().lower() in ("true", "1", "yes")

    if intercept_http or _env_http:
        try:
            from aiglos.integrations.http_intercept import attach_http_intercept
            mode = _policy_to_mode(policy)
            results = attach_http_intercept(allow_list=allow_http or [], mode=mode)
            _http_intercept_active = True
            patched = [k for k, v in results.items() if v]
            log.info("[Aiglos] HTTP interception active: %s", patched)
        except Exception as e:
            log.warning("[Aiglos] HTTP interception failed to attach: %s", e)

    # 3. Subprocess interception
    _env_subproc = os.environ.get("AIGLOS_INTERCEPT_SUBPROCESS", "").strip().lower() in ("true", "1", "yes")
    _tier3_mode  = os.environ.get("AIGLOS_TIER3_MODE", subprocess_tier3_mode).strip().lower()
    _webhook     = os.environ.get("AIGLOS_TIER3_WEBHOOK", tier3_approval_webhook or "").strip() or tier3_approval_webhook

    if intercept_subprocess or _env_subproc:
        try:
            from aiglos.integrations.subprocess_intercept import attach_subprocess_intercept
            mode = _policy_to_mode(policy)
            results = attach_subprocess_intercept(
                mode=mode, tier3_mode=_tier3_mode, approval_webhook=_webhook or None)
            _subproc_intercept_active = True
            patched = [k for k, v in results.items() if v]
            log.info("[Aiglos] Subprocess interception active: %s | tier3_mode=%s",
                     patched, _tier3_mode)
        except Exception as e:
            log.warning("[Aiglos] Subprocess interception failed to attach: %s", e)

    # 4. Session identity chain (v0.3.0)
    try:
        _session_identity = SessionIdentityChain(agent_name=agent_name, session_id=session_id)
        log.info("[Aiglos] Session identity active: %s", _session_identity.session_id[:12])
    except Exception as e:
        log.warning("[Aiglos] Session identity failed to init: %s", e)

    # 5. Multi-agent spawn registry (v0.3.0)
    if enable_multi_agent:
        try:
            sid = _session_identity.session_id if _session_identity else "unknown"
            _multi_agent_registry = MultiAgentRegistry(root_session_id=sid, root_agent_name=agent_name)
            log.info("[Aiglos] Multi-agent registry active: root=%s", sid[:12])
        except Exception as e:
            log.warning("[Aiglos] Multi-agent registry failed to init: %s", e)

    # 6. Agent definition file guard (v0.3.0)
    if guard_agent_defs:
        try:
            _agent_def_guard = AgentDefGuard(cwd=os.getcwd())
            baseline = _agent_def_guard.snapshot()
            log.info("[Aiglos] Agent def guard active: %d files snapshotted.", len(baseline))
        except Exception as e:
            log.warning("[Aiglos] Agent def guard failed to init: %s", e)

    # 6a. Intent prediction
    if kwargs.get("enable_intent_prediction", False):
        try:
            _active_guard.enable_intent_prediction()
        except Exception:
            pass

    # 6b. Causal tracing
    if kwargs.get("enable_causal_tracing", False):
        try:
            _active_guard.enable_causal_tracing()
        except Exception:
            pass

    # 7. Adaptive engine (v0.4.0)
    if enable_adaptive:
        try:
            _adaptive_engine = AdaptiveEngine(db_path=adaptive_db_path)
            log.info("[Aiglos] Adaptive engine active: %s", _adaptive_engine.graph._db_path)
        except Exception as e:
            log.warning("[Aiglos] Adaptive engine failed to init: %s", e)

    log.info(
        "[Aiglos v%s] Attached — agent=%s policy=%s mcp=on http=%s subprocess=%s "
        "multi_agent=%s agent_def_guard=%s adaptive=%s",
        __version__, agent_name, policy,
        "on" if _http_intercept_active else "off",
        "on" if _subproc_intercept_active else "off",
        "on" if _multi_agent_registry else "off",
        "on" if _agent_def_guard else "off",
        "on" if _adaptive_engine else "off",
    )
    return guard


def _policy_to_mode(policy: str) -> str:
    """Map guard policy to scanner mode."""
    return {
        "permissive": "warn",
        "enterprise": "block",
        "strict":     "block",
        "federal":    "block",
    }.get(policy, "block")


def check(
    tool_name: str,
    tool_args: Optional[Dict[str, Any]] = None,
) -> "CheckResult":
    """
    Evaluate an MCP tool call before execution.

    Returns a CheckResult with .blocked / .warned / .allowed verdict.
    If blocked, do not execute the call.
    """
    return _oc_check(tool_name, tool_args or {})


def on_heartbeat() -> None:
    """Notify Aiglos of a cron/heartbeat cycle boundary."""
    from aiglos.integrations import openclaw as _oc
    if _oc._active_guard:
        _oc._active_guard.on_heartbeat()


def close() -> "SessionArtifact":
    """
    Close the current session and return a signed SessionArtifact.

    The artifact covers all three interception surfaces (MCP, HTTP, subprocess)
    plus multi-agent spawn tree and agent definition integrity violations.
    Call once at agent shutdown or end of task.
    """
    global _multi_agent_registry, _agent_def_guard, _session_identity

    # Collect events from all active layers
    http_events    = _collect_http_events()
    subproc_events = _collect_subprocess_events()

    # Check agent def integrity one final time before closing
    agentdef_violations: list = []
    if _agent_def_guard:
        try:
            violations = _agent_def_guard.check()
            agentdef_violations = [v.to_dict() for v in violations]
            if violations:
                log.warning(
                    "[Aiglos] %d agent definition integrity violation(s) at session close.",
                    len(violations),
                )
        except Exception:
            pass

    # Collect multi-agent spawn tree
    multi_agent_data: dict = {}
    if _multi_agent_registry:
        try:
            multi_agent_data = _multi_agent_registry.to_dict()
        except Exception:
            pass

    # Session identity header
    identity_header: dict = {}
    if _session_identity:
        try:
            identity_header = _session_identity.header()
        except Exception:
            pass

    # Close the MCP guard and get base artifact
    artifact = _oc_close()

    # Attach all surface events and v0.3.0 data to artifact
    if artifact:
        _augment_artifact(
            artifact, http_events, subproc_events,
            agentdef_violations=agentdef_violations,
            multi_agent=multi_agent_data,
            identity=identity_header,
        )

    # v0.4.0: auto-ingest into adaptive observation graph
    if _adaptive_engine and artifact:
        try:
            _adaptive_engine.ingest(artifact)
        except Exception as e:
            log.debug("[Aiglos] Adaptive ingest (non-fatal): %s", e)

    return artifact


def adaptive_run() -> dict:
    """
    Run a full adaptive cycle: inspect + generate amendment proposals.

    Requires enable_adaptive=True in attach() (default).
    Returns a report dict with triggers fired and proposals made.
    """
    if _adaptive_engine is None:
        return {"error": "Adaptive engine not initialised. Call attach() first."}
    return _adaptive_engine.run()


def adaptive_stats() -> dict:
    """Return the current observation graph summary across all sessions."""
    if _adaptive_engine is None:
        return {"error": "Adaptive engine not initialised. Call attach() first."}
    return _adaptive_engine.stats()


def derive_child_policy(parent_session_id: str) -> "SessionPolicy":
    """Derive a policy for a spawned child agent from parent session history."""
    if _adaptive_engine is None:
        from aiglos.adaptive.policy import SessionPolicy
        return SessionPolicy.empty(parent_session_id)
    return _adaptive_engine.derive_child_policy(parent_session_id)


def _collect_http_events() -> list:
    if not _http_intercept_active:
        return []
    try:
        from aiglos.integrations.http_intercept import (
            get_session_http_events, clear_session_http_events)
        events = get_session_http_events()
        clear_session_http_events()
        return events
    except Exception:
        return []


def _collect_subprocess_events() -> list:
    if not _subproc_intercept_active:
        return []
    try:
        from aiglos.integrations.subprocess_intercept import (
            get_session_subprocess_events, clear_session_subprocess_events)
        events = get_session_subprocess_events()
        clear_session_subprocess_events()
        return events
    except Exception:
        return []


def _augment_artifact(artifact: "SessionArtifact",
                       http_events: list,
                       subproc_events: list,
                       agentdef_violations: list = [],
                       multi_agent: dict = {},
                       identity: dict = {}) -> None:
    """Attach all surface data to a session artifact."""
    try:
        if not hasattr(artifact, "extra"):
            artifact.extra = {}
        artifact.extra["http_events"]            = http_events
        artifact.extra["subproc_events"]         = subproc_events
        artifact.extra["http_blocked"]           = sum(
            1 for e in http_events if e.get("verdict") == "BLOCK")
        artifact.extra["subproc_blocked"]        = sum(
            1 for e in subproc_events if e.get("verdict") == "BLOCK")
        # v0.3.0 fields
        artifact.extra["agentdef_violations"]    = agentdef_violations
        artifact.extra["agentdef_violation_count"] = len(agentdef_violations)
        artifact.extra["multi_agent"]            = multi_agent
        artifact.extra["session_identity"]       = identity
        artifact.extra["aiglos_version"]         = __version__
    except Exception:
        pass


def status() -> dict:
    """Return current Aiglos runtime status across all layers (v0.3.0)."""
    mcp_status: dict = {}
    try:
        from aiglos.integrations import openclaw as _oc
        if _oc._active_guard:
            mcp_status = _oc._active_guard.status()
    except Exception:
        pass

    http_status: dict = {}
    if _http_intercept_active:
        try:
            from aiglos.integrations.http_intercept import http_intercept_status
            http_status = http_intercept_status()
        except Exception:
            pass

    subproc_status: dict = {}
    if _subproc_intercept_active:
        try:
            from aiglos.integrations.subprocess_intercept import subprocess_intercept_status
            subproc_status = subprocess_intercept_status()
        except Exception:
            pass

    agentdef_status: dict = {}
    if _agent_def_guard:
        try:
            violations = _agent_def_guard.check()
            agentdef_status = {
                "files_monitored": len(_agent_def_guard.baseline),
                "violations":      len(violations),
                "violation_types": [v.violation_type for v in violations],
            }
        except Exception:
            pass

    multi_agent_status: dict = {}
    if _multi_agent_registry:
        try:
            spawns = _multi_agent_registry.all_spawns()
            multi_agent_status = {
                "root_session":  _multi_agent_registry._root_id[:12],
                "spawn_count":   len(spawns),
                "child_count":   len(_multi_agent_registry._children),
            }
        except Exception:
            pass

    identity_status: dict = {}
    if _session_identity:
        try:
            identity_status = {
                "session_id":   _session_identity.session_id[:12],
                "event_count":  _session_identity._event_count,
                "public_token": _session_identity.public_token[:16] + "...",
            }
        except Exception:
            pass

    adaptive_status: dict = {}
    if _adaptive_engine:
        try:
            adaptive_status = _adaptive_engine.stats()
        except Exception:
            pass

    return {
        "version":                 __version__,
        "mcp_layer":               mcp_status,
        "http_layer_active":       _http_intercept_active,
        "http_layer":              http_status,
        "subprocess_layer_active": _subproc_intercept_active,
        "subprocess_layer":        subproc_status,
        "agent_def_guard_active":  _agent_def_guard is not None,
        "agent_def_guard":         agentdef_status,
        "multi_agent_active":      _multi_agent_registry is not None,
        "multi_agent":             multi_agent_status,
        "session_identity_active": _session_identity is not None,
        "session_identity":        identity_status,
        "adaptive_active":         _adaptive_engine is not None,
        "adaptive":                adaptive_status,
    }


__all__ = [
    "__version__",
    "attach",
    "check",
    "on_heartbeat",
    "close",
    "status",
    "adaptive_run",
    "adaptive_stats",
    "derive_child_policy",
    "OpenClawGuard",
    "HermesGuard",
    "CheckResult",
    "SessionArtifact",
    # v0.3.0
    "MultiAgentRegistry",
    "AgentDefGuard",
    "SessionIdentityChain",
    "SpawnEvent",
    "AgentDefViolation",
    # v0.4.0
    "AdaptiveEngine",
    "ObservationGraph",
    "InspectionEngine",
    "AmendmentEngine",
    "PolicySerializer",
    "SessionPolicy",
    "CampaignAnalyzer",
    "CampaignResult",
    # v0.5.0
    "MemoryWriteGuard",
    "MemoryWriteResult",
    "inspect_memory_write",
    "is_memory_tool",
    "MemoryProvenanceGraph",
    "CrossSessionRisk",
    "BeliefDriftReport",
]
