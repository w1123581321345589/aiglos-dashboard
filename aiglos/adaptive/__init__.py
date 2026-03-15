"""
aiglos.adaptive
================
Adaptive security layer for Aiglos — the cognee-skills-inspired feedback loop
that makes threat detection rules living components rather than static files.

observe → inspect → amend → evaluate

Components:
  ObservationGraph   — SQLite-backed session history (Phase 1)
  InspectionEngine   — trigger conditions that surface rules needing attention (Phase 2)
  AmendmentEngine    — evidence-based proposals to rules/allow-lists (Phase 4)
  PolicySerializer   — derive child agent policies from parent history (Phase 5)

Semantic scoring (Phase 3) lives in aiglos.integrations.multi_agent.AgentDefGuard.

Quick start:
    from aiglos.adaptive import AdaptiveEngine

    engine = AdaptiveEngine()          # uses ~/.aiglos/observations.db
    engine.ingest(artifact)            # call after aiglos.close()
    report = engine.run()              # inspect + propose amendments
    print(report)
"""

import logging
from typing import Any

log = logging.getLogger("aiglos.adaptive")

from aiglos.adaptive.observation import ObservationGraph, RuleStats
from aiglos.adaptive.inspect import InspectionEngine, InspectionTrigger
from aiglos.adaptive.amend import AmendmentEngine, Amendment, PENDING, APPROVED, REJECTED
from aiglos.adaptive.policy import PolicySerializer, SessionPolicy
from aiglos.adaptive.campaign import CampaignAnalyzer, CampaignResult
from aiglos.adaptive.memory import MemoryProvenanceGraph, CrossSessionRisk, BeliefDriftReport

__all__ = [
    "AdaptiveEngine",
    "ObservationGraph",
    "InspectionEngine",
    "AmendmentEngine",
    "PolicySerializer",
    "CampaignAnalyzer",
    "MemoryProvenanceGraph",
    "RuleStats",
    "InspectionTrigger",
    "Amendment",
    "SessionPolicy",
    "CampaignResult",
    "CrossSessionRisk",
    "BeliefDriftReport",
]


class AdaptiveEngine:
    """
    Facade that wires the full adaptive loop: observe → inspect → amend.
    v0.4.0: T06 campaign-mode, memory provenance graph, memory guard integration.
    """

    def __init__(self, db_path: str | None = None):
        effective_path = db_path or ":memory:"
        self.graph = ObservationGraph(db_path=effective_path)
        self.inspector = InspectionEngine(self.graph)
        self.amender = AmendmentEngine(self.graph)
        self.policy = PolicySerializer(self.graph)
        self.campaign = CampaignAnalyzer(self.graph)
        mem_path = effective_path.replace(".db", "_memory.db") if effective_path != ":memory:" else ":memory:"
        self.memory = MemoryProvenanceGraph(db_path=mem_path)

    def ingest(self, artifact: Any) -> str:
        """Ingest a SessionArtifact. Returns session_id."""
        sid = self.graph.ingest(artifact)
        try:
            self.memory.ingest_session_artifact(artifact)
        except Exception:
            pass
        return sid

    def run(self) -> dict:
        """
        Full adaptive cycle: inspect + T06 campaign + memory drift + propose.
        """
        triggers = self.inspector.run()
        campaign_results = self.campaign.analyze_recent(hours=24)
        campaign_triggers = self.campaign.to_triggers(campaign_results)
        all_triggers = triggers + campaign_triggers
        proposals = self.amender.propose(all_triggers)
        summary = self.graph.summary()
        memory_summary = self.memory.summary()
        cross_session_risks = [r.to_dict() for r in self.memory.cross_session_risks()]
        drift = self.memory.detect_belief_drift()

        causal_stats = self.graph.causal_stats()

        report = {
            "graph_summary": summary,
            "memory_summary": memory_summary,
            "cross_session_risks": cross_session_risks,
            "belief_drift": drift.to_dict() if drift else None,
            "causal_stats": causal_stats,
            "triggers_fired": len(all_triggers),
            "triggers": [t.to_dict() for t in all_triggers],
            "campaign_patterns": len(campaign_results),
            "campaigns": [r.to_dict() for r in campaign_results],
            "proposals_made": len(proposals),
            "proposals": [p.to_dict() for p in proposals],
            "pending_amendments": len(self.amender.pending()),
        }
        if all_triggers or cross_session_risks:
            log.warning(
                "[AdaptiveEngine] %d trigger(s) (%d campaign), %d cross-session memory risks, %d proposal(s).",
                len(all_triggers), len(campaign_results),
                len(cross_session_risks), len(proposals),
            )
        return report

    def derive_child_policy(self, parent_session_id: str) -> SessionPolicy:
        return self.policy.derive(parent_session_id)

    def stats(self) -> dict:
        s = self.graph.summary()
        s["memory"] = self.memory.summary()
        s["causal"] = self.graph.causal_stats()
        return s
