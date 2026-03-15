from aiglos.adaptive.observation import ObservationGraph, RuleStats
from aiglos.adaptive.inspect import InspectionEngine, InspectionTrigger
from aiglos.adaptive.amend import AmendmentEngine, Amendment, PENDING, APPROVED, REJECTED
from aiglos.adaptive.policy import PolicySerializer, SessionPolicy
from aiglos.adaptive.campaign import CampaignAnalyzer, CampaignResult
from aiglos.adaptive.memory import MemoryProvenanceGraph, CrossSessionRisk, BeliefDriftReport


class AdaptiveEngine:

    def __init__(self, db_path: str = ":memory:"):
        self.graph = ObservationGraph(db_path=db_path)
        self.inspector = InspectionEngine(self.graph)
        self.amender = AmendmentEngine(self.graph)
        self.serializer = PolicySerializer(self.graph)
        self.campaign = CampaignAnalyzer(self.graph)
        self.memory = MemoryProvenanceGraph(db_path=db_path.replace(".db", "_memory.db") if db_path != ":memory:" else ":memory:")

    def ingest(self, artifact) -> str:
        return self.graph.ingest(artifact)

    def run(self) -> dict:
        triggers = self.inspector.run()
        proposals = self.amender.propose(triggers)
        mem_summary = self.memory.summary()
        cross_risks = self.memory.cross_session_risks()
        campaigns = self.campaign.analyze_all()
        campaign_triggers = self.campaign.to_triggers(campaigns)
        return {
            "triggers_fired": len(triggers),
            "triggers": [t.to_dict() for t in triggers],
            "proposals_made": len(proposals),
            "proposals": [p.to_dict() for p in proposals],
            "graph_summary": self.graph.summary(),
            "memory_summary": mem_summary,
            "cross_session_risks": [r.to_dict() for r in cross_risks],
            "campaign_patterns": len(campaigns),
            "campaigns": [c.to_dict() for c in campaigns],
        }

    def stats(self) -> dict:
        s = self.graph.summary()
        s["amendments"] = self.amender.summary()
        s["memory"] = self.memory.summary()
        return s

    def derive_child_policy(self, session_id: str) -> SessionPolicy:
        return self.serializer.derive(session_id)
