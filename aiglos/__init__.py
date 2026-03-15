__version__ = "0.8.0"

from aiglos.integrations.openclaw import (
    OpenClawGuard,
    GuardResult,
    SessionArtifact,
    attach,
    check,
    close,
    on_heartbeat,
)
from aiglos.integrations.openclaw import status as _oc_status
from aiglos.integrations.hermes import HermesGuard
from aiglos.integrations.memory_guard import (
    MemoryWriteGuard,
    MemoryWriteResult,
    inspect_memory_write,
    is_memory_tool,
)
from aiglos.integrations.injection_scanner import (
    InjectionScanner,
    InjectionScanResult,
    scan_tool_output,
    score_content,
    is_injection,
)
from aiglos.integrations.rl_guard import (
    RLFeedbackGuard,
    RLFeedbackResult,
    score_opd_feedback,
    is_reward_poison,
)
from aiglos.autoresearch.coupling import SecurityAwareReward, CoupledRewardResult
from aiglos.adaptive import (
    AdaptiveEngine,
    ObservationGraph,
    InspectionEngine,
    AmendmentEngine,
    PolicySerializer,
    SessionPolicy,
    CampaignAnalyzer,
    CampaignResult,
)
from aiglos.adaptive.memory import (
    MemoryProvenanceGraph,
    CrossSessionRisk,
    BeliefDriftReport,
)
from aiglos.integrations.multi_agent import (
    MultiAgentRegistry,
    AgentDefGuard,
    SessionIdentityChain,
    SpawnEvent,
    AgentDefViolation,
)

_adaptive_engine = None


def adaptive_run() -> dict:
    if _adaptive_engine is None:
        return {"error": "Adaptive engine not initialized"}
    return _adaptive_engine.run()


def adaptive_stats() -> dict:
    if _adaptive_engine is None:
        return {"error": "Adaptive engine not initialized"}
    return _adaptive_engine.stats()


def derive_child_policy(parent_id: str) -> SessionPolicy:
    if _adaptive_engine is None:
        return SessionPolicy(derived_from=parent_id)
    return _adaptive_engine.derive_child_policy(parent_id)


def status() -> dict:
    base = _oc_status()
    base["version"] = __version__
    base["adaptive_active"] = _adaptive_engine is not None
    base["adaptive"] = _adaptive_engine.stats() if _adaptive_engine else {}
    base["agent_def_guard_active"] = True
    base["multi_agent_active"] = True
    base["session_identity_active"] = True
    base["agent_def_guard"] = {}
    base["multi_agent"] = {}
    base["session_identity"] = {}
    return base
