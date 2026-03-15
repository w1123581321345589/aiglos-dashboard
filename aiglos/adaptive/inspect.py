"""
aiglos.adaptive.inspect
========================
Phase 2: Inspection triggers — automated conditions that surface rules,
agent definitions, and deployment patterns that need attention.

An inspection trigger fires when the observation graph contains enough
evidence that something is wrong, degrading, or needs calibration.
Triggers are non-blocking: they surface findings, they do not change anything.
The amendment engine (Phase 4) acts on trigger findings.

Trigger types:
  RATE_DROP        — rule firing rate dropped >40% from 30-session baseline
  ZERO_FIRE        — rule has gone silent after being active
  HIGH_OVERRIDE    — T3 operations being consistently webhook-approved
  AGENTDEF_REPEAT  — same agent def path modified across multiple sessions
  SPAWN_NO_POLICY  — child agents spawning with no inherited policy
  FIN_EXEC_BYPASS  — T37 overrides accumulating on specific hosts
  FALSE_POSITIVE   — rule firing but consistently not blocking (high warn rate)

Usage:
    from aiglos.adaptive.inspect import InspectionEngine

    engine = InspectionEngine(graph)
    triggers = engine.run()
    for t in triggers:
        print(t.trigger_type, t.rule_id, t.evidence_summary)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("aiglos.adaptive.inspect")


@dataclass
class InspectionTrigger:
    trigger_type:     str
    rule_id:          Optional[str]
    severity:         str             # HIGH | MEDIUM | LOW
    evidence_summary: str
    evidence_data:    dict = field(default_factory=dict)
    fired_at:         float = field(default_factory=time.time)
    amendment_candidate: bool = False  # True if Phase 4 should act on this

    def to_dict(self) -> dict:
        return {
            "trigger_type":      self.trigger_type,
            "rule_id":           self.rule_id,
            "severity":          self.severity,
            "evidence_summary":  self.evidence_summary,
            "evidence_data":     self.evidence_data,
            "fired_at":          self.fired_at,
            "amendment_candidate": self.amendment_candidate,
        }


class InspectionEngine:
    """
    Runs all inspection trigger checks against an ObservationGraph.

    Designed to run at session close or on a periodic schedule.
    Each check is independent and safe to run in any order.
    """

    # Thresholds — tunable via constructor kwargs
    RATE_DROP_THRESHOLD    = 0.40   # 40% drop triggers RATE_DROP
    HIGH_OVERRIDE_MIN      = 3      # N consecutive approvals triggers HIGH_OVERRIDE
    AGENTDEF_REPEAT_MIN    = 2      # N cross-session violations triggers AGENTDEF_REPEAT
    SPAWN_NO_POLICY_MIN    = 3      # N policy-gap spawns triggers SPAWN_NO_POLICY
    FIN_BYPASS_MIN         = 3      # N T37 overrides triggers FIN_EXEC_BYPASS
    FALSE_POSITIVE_WARN_RATE = 0.60 # >60% warns (not blocks) triggers FALSE_POSITIVE
    MIN_SESSIONS_FOR_BASELINE = 5   # don't trigger RATE_DROP until N sessions seen

    def __init__(self, graph, **kwargs):
        self._graph = graph
        for k, v in kwargs.items():
            setattr(self, k.upper(), v)

    def run(self) -> List[InspectionTrigger]:
        """Run all inspection checks. Returns list of fired triggers."""
        triggers: List[InspectionTrigger] = []
        triggers.extend(self._check_rate_drops())
        triggers.extend(self._check_high_overrides())
        triggers.extend(self._check_agentdef_repeat())
        triggers.extend(self._check_spawn_no_policy())
        triggers.extend(self._check_fin_exec_bypass())
        triggers.extend(self._check_false_positives())
        triggers.extend(self._check_reward_drift())
        triggers.extend(self._check_causal_injection_confirmed())
        log.info("[InspectionEngine] %d trigger(s) fired.", len(triggers))
        return triggers

    # ── Rate drop ──────────────────────────────────────────────────────────────

    def _check_rate_drops(self) -> List[InspectionTrigger]:
        """Detect rules whose firing rate has dropped significantly."""
        triggers = []
        all_stats = self._graph.all_rule_stats()
        total_sessions = self._graph.session_count()

        for stats in all_stats:
            if stats.sessions_seen < self.MIN_SESSIONS_FOR_BASELINE:
                continue
            avg_per_session = stats.fires_total / stats.sessions_seen
            if avg_per_session < 0.01:
                continue  # essentially never fired, skip

            # Get recent firing rate (last 5 sessions vs historical)
            recent = self._recent_rule_rate(stats.rule_id, window=5)
            if recent is None:
                continue
            if stats.fires_total == 0:
                continue

            drop = 1.0 - (recent / avg_per_session)
            if drop >= self.RATE_DROP_THRESHOLD:
                if recent == 0:
                    triggers.append(InspectionTrigger(
                        trigger_type="ZERO_FIRE",
                        rule_id=stats.rule_id,
                        severity="HIGH",
                        evidence_summary=(
                            f"{stats.rule_id} has gone silent. Historical avg "
                            f"{avg_per_session:.2f} fires/session, zero in last 5 sessions. "
                            "Environment may have changed, or attack pattern shifted."
                        ),
                        evidence_data={
                            "historical_avg": round(avg_per_session, 4),
                            "recent_avg":     0,
                            "sessions_seen":  stats.sessions_seen,
                        },
                        amendment_candidate=False,
                    ))
                else:
                    triggers.append(InspectionTrigger(
                        trigger_type="RATE_DROP",
                        rule_id=stats.rule_id,
                        severity="MEDIUM",
                        evidence_summary=(
                            f"{stats.rule_id} firing rate dropped {drop*100:.0f}% from baseline. "
                            f"Historical avg {avg_per_session:.2f}/session, "
                            f"recent {recent:.2f}/session."
                        ),
                        evidence_data={
                            "historical_avg": round(avg_per_session, 4),
                            "recent_avg":     round(recent, 4),
                            "drop_pct":       round(drop * 100, 1),
                        },
                        amendment_candidate=False,
                    ))
        return triggers

    def _recent_rule_rate(self, rule_id: str, window: int = 5) -> Optional[float]:
        """Average firing rate in the most recent N sessions."""
        try:
            events = self._graph.events_for_rule(rule_id, limit=window * 10)
            recent_sessions = {e["session_id"] for e in events[:window * 5]}
            total_sessions = self._graph.session_count()
            if total_sessions < window:
                return None
            count = sum(1 for e in events if e["session_id"] in recent_sessions)
            return count / max(len(recent_sessions), 1)
        except Exception:
            return None

    # ── High override rate ─────────────────────────────────────────────────────

    def _check_high_overrides(self) -> List[InspectionTrigger]:
        """
        Detect Tier 3 operations that are consistently being approved via webhook.
        Candidate for Tier 2 reclassification in this deployment.
        """
        triggers = []
        try:
            warn_rules = [
                s for s in self._graph.all_rule_stats()
                if s.warns_total >= self.HIGH_OVERRIDE_MIN
                and s.fires_total > 0
                and (s.warns_total / s.fires_total) > 0.5
            ]
            for stats in warn_rules:
                triggers.append(InspectionTrigger(
                    trigger_type="HIGH_OVERRIDE",
                    rule_id=stats.rule_id,
                    severity="MEDIUM",
                    evidence_summary=(
                        f"{stats.rule_id} has been overridden (WARN/approved) "
                        f"{stats.warns_total} times out of {stats.fires_total} fires. "
                        "Candidate for allow-list amendment or tier reclassification."
                    ),
                    evidence_data={
                        "warns_total":  stats.warns_total,
                        "fires_total":  stats.fires_total,
                        "override_rate": round(stats.override_rate, 4),
                    },
                    amendment_candidate=True,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] high_override check error: %s", e)
        return triggers

    # ── Agent def repeat violations ────────────────────────────────────────────

    def _check_agentdef_repeat(self) -> List[InspectionTrigger]:
        """
        Detect agent definition paths that have been modified across multiple sessions.
        Repeated cross-session violations on the same path indicate a persistent
        adversarial modification pattern or an unreviewed supply chain change.
        """
        triggers = []
        try:
            violations = self._graph.agentdef_violations_for_path.__func__ if False else None
            # Query all agentdef observations with violations, group by path_hash
            import sqlite3
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT path_hash, path_preview, COUNT(DISTINCT session_id) as sessions,
                           COUNT(*) as total, MAX(semantic_risk) as max_risk
                    FROM agentdef_observations
                    WHERE violation_type IS NOT NULL
                    GROUP BY path_hash
                    HAVING sessions >= ?
                """, (self.AGENTDEF_REPEAT_MIN,)).fetchall()

            for row in rows:
                triggers.append(InspectionTrigger(
                    trigger_type="AGENTDEF_REPEAT",
                    rule_id="T36_AGENTDEF",
                    severity="HIGH" if row["max_risk"] == "HIGH" else "MEDIUM",
                    evidence_summary=(
                        f"Agent definition path '...{row['path_preview']}' "
                        f"modified in {row['sessions']} sessions "
                        f"({row['total']} total violations). "
                        f"Highest semantic risk: {row['max_risk'] or 'unscored'}."
                    ),
                    evidence_data={
                        "path_hash":    row["path_hash"],
                        "path_preview": row["path_preview"],
                        "sessions":     row["sessions"],
                        "total":        row["total"],
                        "max_risk":     row["max_risk"],
                    },
                    amendment_candidate=False,  # requires human review
                ))
        except Exception as e:
            log.debug("[InspectionEngine] agentdef_repeat check error: %s", e)
        return triggers

    # ── Spawn without policy propagation ──────────────────────────────────────

    def _check_spawn_no_policy(self) -> List[InspectionTrigger]:
        """
        Detect child agents that have spawned without inheriting the parent's policy.
        These children start from global defaults and may permit operations the
        parent fleet has learned to restrict.
        """
        triggers = []
        try:
            with self._graph._conn() as conn:
                row = conn.execute("""
                    SELECT COUNT(*) as c, COUNT(DISTINCT agent_name) as agents
                    FROM spawn_events WHERE policy_propagated=0
                """).fetchone()
            if row and row["c"] >= self.SPAWN_NO_POLICY_MIN:
                triggers.append(InspectionTrigger(
                    trigger_type="SPAWN_NO_POLICY",
                    rule_id="T38",
                    severity="MEDIUM",
                    evidence_summary=(
                        f"{row['c']} child agent spawns detected with no inherited policy "
                        f"across {row['agents']} agent type(s). "
                        "These children start from global defaults. "
                        "Enable policy inheritance in aiglos.attach()."
                    ),
                    evidence_data={
                        "spawn_count_no_policy": row["c"],
                        "agent_types":           row["agents"],
                    },
                    amendment_candidate=True,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] spawn_no_policy check error: %s", e)
        return triggers

    # ── T37 FIN_EXEC bypass accumulation ──────────────────────────────────────

    def _check_fin_exec_bypass(self) -> List[InspectionTrigger]:
        """
        Detect T37 financial execution blocks that are being repeatedly allowed
        via the allow_http list. Indicates the deployment legitimately needs
        certain financial endpoints and should have a targeted amendment.
        """
        triggers = []
        try:
            stats = self._graph.rule_stats("T37")
            if stats.warns_total >= self.FIN_BYPASS_MIN:
                triggers.append(InspectionTrigger(
                    trigger_type="FIN_EXEC_BYPASS",
                    rule_id="T37",
                    severity="MEDIUM",
                    evidence_summary=(
                        f"T37 FIN_EXEC has been bypassed {stats.warns_total} times. "
                        "Review which financial endpoints this deployment legitimately calls "
                        "and add them explicitly to allow_http."
                    ),
                    evidence_data={
                        "warns_total":  stats.warns_total,
                        "blocks_total": stats.blocks_total,
                        "fires_total":  stats.fires_total,
                    },
                    amendment_candidate=True,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] fin_exec_bypass check error: %s", e)
        return triggers

    # ── False positive detection ───────────────────────────────────────────────

    def _check_false_positives(self) -> List[InspectionTrigger]:
        """
        Detect rules with high warn rates relative to block rates.
        High warn rate = the rule fires but rarely results in a hard block,
        suggesting it may be over-triggering on legitimate operations.
        """
        triggers = []
        all_stats = self._graph.all_rule_stats()
        for stats in all_stats:
            if stats.fires_total < 10:
                continue
            warn_rate = stats.warns_total / stats.fires_total
            if warn_rate >= self.FALSE_POSITIVE_WARN_RATE:
                triggers.append(InspectionTrigger(
                    trigger_type="FALSE_POSITIVE",
                    rule_id=stats.rule_id,
                    severity="LOW",
                    evidence_summary=(
                        f"{stats.rule_id} fires {stats.fires_total} times but "
                        f"{warn_rate*100:.0f}% result in WARNs rather than BLOCKs. "
                        "Rule may be over-triggering. Consider tightening the pattern."
                    ),
                    evidence_data={
                        "fires_total":  stats.fires_total,
                        "warns_total":  stats.warns_total,
                        "blocks_total": stats.blocks_total,
                        "warn_rate":    round(warn_rate, 4),
                    },
                    amendment_candidate=True,
                ))
        return triggers

    # ── Reward drift ───────────────────────────────────────────────────────────

    REWARD_DRIFT_MIN_SIGNALS = 5    # need at least N signals to check drift
    REWARD_DRIFT_THRESHOLD   = 0.40 # positive reward for blocked ops above this rate

    def _check_reward_drift(self) -> List[InspectionTrigger]:
        """
        Detect when reward signals for security-relevant operations shift
        toward positive — indicating possible reward poisoning in an RL loop.

        Fires REWARD_DRIFT when:
        - Claimed rewards for operations Aiglos blocked are trending positive
        - T39 fires are accumulating (OPD injection in feedback text)
        - Reward signal quarantine rate exceeds threshold
        """
        triggers = []
        try:
            stats = self._graph.reward_signal_stats()
            total = stats.get("total_signals", 0)
            if total < self.REWARD_DRIFT_MIN_SIGNALS:
                return []

            quarantine_rate = stats.get("quarantined", 0) / total
            if quarantine_rate >= self.REWARD_DRIFT_THRESHOLD:
                triggers.append(InspectionTrigger(
                    trigger_type="REWARD_DRIFT",
                    rule_id="T39",
                    severity="HIGH",
                    evidence_summary=(
                        f"RL reward signals: {quarantine_rate*100:.0f}% of signals "
                        f"({stats.get('quarantined',0)}/{total}) were quarantined as "
                        "T39 REWARD_POISON or OPD_INJECTION. The RL training loop "
                        "is receiving systematically manipulated feedback."
                    ),
                    evidence_data={
                        "total_signals":    total,
                        "quarantined":      stats.get("quarantined", 0),
                        "quarantine_rate":  round(quarantine_rate, 4),
                        "t39_fires":        stats.get("t39_fires", 0),
                        "high_risk_opd":    stats.get("high_risk_opd", 0),
                    },
                    amendment_candidate=False,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] reward_drift check error: %s", e)
        return triggers

    # ── Causal injection confirmed ─────────────────────────────────────────────

    CAUSAL_MIN_SESSIONS = 2    # need at least N sessions with tracing data
    CAUSAL_CONF_THRESHOLD = 1  # fire if ANY session has a confirmed high-conf attribution

    def _check_causal_injection_confirmed(self) -> List[InspectionTrigger]:
        """
        Fire when causal attribution has confirmed a HIGH-confidence
        injection-to-action chain in one or more sessions.

        This is the highest-severity trigger — it means the observation graph
        contains evidence that a specific blocked action was caused by a
        specific injection source. This is not a suspicion; it is a traced
        attack chain.
        """
        triggers = []
        try:
            stats = self._graph.causal_stats()
            if stats.get("sessions_with_tracing", 0) < self.CAUSAL_MIN_SESSIONS:
                return []

            attacks = stats.get("attacks_confirmed", 0)
            high_conf = stats.get("high_conf_attributions", 0)

            if attacks >= 1 or high_conf >= self.CAUSAL_CONF_THRESHOLD:
                triggers.append(InspectionTrigger(
                    trigger_type="CAUSAL_INJECTION_CONFIRMED",
                    rule_id="T27",
                    severity="HIGH",
                    evidence_summary=(
                        f"Causal attribution has confirmed {high_conf} HIGH-confidence "
                        f"injection-to-action chain(s) across {stats.get('sessions_with_tracing',0)} "
                        f"traced sessions. {attacks} session(s) classified as ATTACK_CONFIRMED. "
                        "A specific blocked action has been traced to a specific injection source. "
                        "Run `python -m aiglos trace <session-id>` for the full investigation report."
                    ),
                    evidence_data={
                        "sessions_with_tracing": stats.get("sessions_with_tracing", 0),
                        "high_conf_attributions": high_conf,
                        "attacks_confirmed":      attacks,
                        "suspicious_sessions":    stats.get("suspicious_sessions", 0),
                        "total_attributed":       stats.get("total_attributed", 0),
                    },
                    amendment_candidate=False,
                ))
        except Exception as e:
            log.debug("[InspectionEngine] causal_injection check error: %s", e)
        return triggers
