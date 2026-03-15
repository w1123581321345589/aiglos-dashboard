from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import time

from aiglos.adaptive.inspect import InspectionTrigger


@dataclass
class CampaignResult:
    pattern_id: str
    description: str = ""
    session_id: str = ""
    confidence: float = 0.0
    evidence: List[Dict] = field(default_factory=list)
    recommendation: str = ""

    @property
    def risk(self) -> str:
        if self.confidence >= 0.85:
            return "HIGH"
        elif self.confidence >= 0.70:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict:
        return {
            "pattern_id": self.pattern_id,
            "rule_id": "T06",
            "rule_name": "GOAL_DRIFT",
            "threat_family": "T06_CAMPAIGN",
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "risk": self.risk,
            "description": self.description,
            "session_id": self.session_id,
            "matched_rules": sorted({e.get("rule_id", "") for e in self.evidence}),
            "evidence_count": len(self.evidence),
        }


# Each pattern is a set of rule_id combos that indicate coordinated attack behavior.
# The analyzer checks every ingested session for matches against these.
_CAMPAIGN_PATTERNS = [
    {"name": "RECON_SWEEP",
     "requires": [{"T01", "T02"}, {"T01", "T03"}, {"T08", "T22"}],
     "rec": "Block reconnaissance tools"},
    {"name": "CREDENTIAL_ACCUMULATE",
     "requires": [{"T19"}],
     "min_events": 3,
     "rec": "Revoke credential access"},
    {"name": "EXFIL_SETUP",
     "requires": [{"T19", "T23"}, {"T13", "T07"}, {"T13", "T19"}, {"T08", "T23"}],
     "rec": "Block exfiltration channels — inspect T23 data-exfil subprocess calls"},
    {"name": "PERSISTENCE_CHAIN",
     "requires": [{"T10", "T11"}, {"T34", "T07"}, {"T34", "T30"}],
     "rec": "Remove persistence mechanisms"},
    {"name": "LATERAL_PREP",
     "requires": [{"T19", "T12"}, {"T19", "T22"}, {"T07", "T13"}, {"T38", "T07"}],
     "rec": "Isolate lateral movement"},
    {"name": "AGENTDEF_CHAIN",
     "requires": [{"T36_AGENTDEF"}],
     "special": "agentdef_read_write",
     "rec": "Lock agent definitions — McKinsey/Lilli-class silent reprogramming vector"},
    {"name": "MEMORY_PERSISTENCE_CHAIN",
     "requires": [{"T31", "T37"}, {"T31", "T19"}, {"T31", "T23"}, {"T31", "T07"}],
     "rec": "Enable ByteRover memory guard and audit memory writes"},
    {"name": "REWARD_MANIPULATION",
     "requires": [{"T37", "T39"}, {"T19", "T39"}, {"T36_AGENTDEF", "T39"},
                  {"T07", "T39"}, {"T_DEST", "T39"}],
     "rec": "Halt RL training pipeline and audit reward signals"},
    {"name": "EXTERNAL_INSTRUCTION_CHANNEL",
     "requires": [{"T11", "T22", "T31"}, {"T11", "T01", "T31"}],
     "rec": "Revoke cron/scheduled-task access, audit allow_http list, "
            "and inspect any disguised productivity tip or user message channel for C2 instructions"},
    {"name": "REPEATED_INJECTION_ATTEMPT",
     "requires": [{"T27"}],
     "min_events": 3,
     "rec": "T27 INBOUND_INJECTION fired 3+ times across distinct tool outputs in this session. "
            "Treat every tool output as potentially compromised. Review the injection_flagged "
            "section of the artifact for the full payload list. Consider whether the content "
            "sources themselves have been compromised."},
]


class CampaignAnalyzer:

    def __init__(self, graph):
        self._graph = graph

    def _get_session_events(self, session_id: str) -> List[Dict]:
        with self._graph._conn() as conn:
            rows = conn.execute(
                "SELECT rule_id, rule_name, verdict, surface, tier, cmd_hash, cmd_preview, "
                "latency_ms, timestamp FROM events WHERE session_id=?",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def analyze_session(self, session_id: str) -> List[CampaignResult]:
        events = self._get_session_events(session_id)
        if not events:
            return []

        rule_ids = {e["rule_id"] for e in events}
        results: List[CampaignResult] = []

        for pattern in _CAMPAIGN_PATTERNS:
            special = pattern.get("special")
            min_events = pattern.get("min_events", 0)

            if special == "agentdef_read_write":
                match = self._check_agentdef_chain(events)
                if match:
                    results.append(match)
                    match.session_id = session_id
                    match.recommendation = pattern["rec"]
                continue

            if min_events > 0:
                req_rules = list(pattern["requires"][0])
                matching = [e for e in events if e["rule_id"] in req_rules]
                if len(matching) >= min_events:
                    conf = min(1.0, 0.70 + (len(matching) - min_events) * 0.05)
                    results.append(CampaignResult(
                        pattern_id=pattern["name"],
                        description=f"{pattern['name']} detected: {len(matching)} events",
                        session_id=session_id,
                        confidence=conf,
                        evidence=matching,
                        recommendation=pattern["rec"],
                    ))
                continue

            for req_set in pattern["requires"]:
                if req_set.issubset(rule_ids):
                    matched_events = [e for e in events if e["rule_id"] in req_set]
                    if len(matched_events) < 2:
                        continue
                    confidence = min(1.0, 0.75 + len(req_set) * 0.05)
                    results.append(CampaignResult(
                        pattern_id=pattern["name"],
                        description=f"{pattern['name']} detected with rules {sorted(req_set)}",
                        session_id=session_id,
                        confidence=confidence,
                        evidence=matched_events,
                        recommendation=pattern["rec"],
                    ))
                    break

        return results

    def _check_agentdef_chain(self, events: List[Dict]) -> Optional[CampaignResult]:
        has_read = False
        has_write = False
        matched = []
        for e in events:
            if e["rule_id"] == "T36_AGENTDEF":
                rn = (e.get("rule_name") or "").upper()
                if "READ" in rn:
                    has_read = True
                    matched.append(e)
                if "WRITE" in rn:
                    has_write = True
                    matched.append(e)
        if has_read and has_write:
            return CampaignResult(
                pattern_id="AGENTDEF_CHAIN",
                description="Agent definition read-then-write chain detected",
                confidence=0.90,
                evidence=matched,
            )
        return None

    def analyze_recent(self, hours: float = 24) -> List[CampaignResult]:
        cutoff = time.time() - hours * 3600
        with self._graph._conn() as conn:
            rows = conn.execute(
                "SELECT session_id FROM sessions WHERE ingested_at >= ?", (cutoff,)
            ).fetchall()
        all_results: List[CampaignResult] = []
        for row in rows:
            all_results.extend(self.analyze_session(row[0]))
        return all_results

    def analyze_all(self) -> List[CampaignResult]:
        all_results = []
        with self._graph._conn() as conn:
            sids = [r[0] for r in conn.execute("SELECT session_id FROM sessions").fetchall()]
        for sid in sids:
            all_results.extend(self.analyze_session(sid))
        return all_results

    def to_triggers(self, results: List[CampaignResult]) -> List[InspectionTrigger]:
        triggers = []
        for r in results:
            triggers.append(InspectionTrigger(
                trigger_type="T06_CAMPAIGN",
                rule_id="T06",
                severity=r.risk,
                evidence_summary=f"Campaign pattern {r.pattern_id} confidence={r.confidence:.2f}",
                evidence_data=r.to_dict(),
                amendment_candidate=False,
            ))
        return triggers
