"""
aiglos.adaptive.policy
=======================
Phase 5: Session policy serialization and propagation for spawned agents.

When a parent agent spawns a child (T38 AGENT_SPAWN), the child should
not start from global defaults. It should inherit the parent's learned
policy: which hosts are legitimately called, which command patterns have
been consistently approved, which Tier 3 operations have been
repeatedly approved via webhook.

This is the difference between:
  a) A child agent that blocks api.stripe.com (global default)
  b) A child agent that knows the parent fleet has approved api.stripe.com
     in N sessions, and starts with that context already built in

The policy is derived from the observation graph at spawn time.
It is not a static config file. It is a snapshot of learned behavior.

Usage:
    from aiglos.adaptive.policy import PolicySerializer

    serializer = PolicySerializer(graph)

    # At spawn time (called internally by MultiAgentRegistry):
    parent_policy = serializer.derive(parent_session_id)

    # Pass to child's attach():
    aiglos.attach(
        agent_name="child-agent",
        inherited_policy=parent_policy,
        ...
    )

    # Inspect what a child inherited:
    print(parent_policy.to_dict())
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

log = logging.getLogger("aiglos.adaptive.policy")

# Minimum evidence thresholds for policy items to be included
MIN_SESSIONS_FOR_ALLOW  = 3   # host must appear in N sessions before being inherited
MIN_APPROVALS_FOR_RECLASS = 3 # command pattern must be approved N times


@dataclass
class SessionPolicy:
    """
    A portable policy snapshot derived from a parent session's observation history.

    Passed to child agent's attach() call so it inherits calibrated behavior
    rather than starting from global defaults.
    """
    derived_from:    str                 # parent session ID
    derived_at:      float = field(default_factory=time.time)
    evidence_sessions: int = 0           # sessions of evidence this policy is based on

    # Allow-listed HTTP hosts (learned from parent's consistent calls)
    inherited_allow_http: List[str] = field(default_factory=list)

    # Tier reclassifications: rule_id -> "tier2" (learned from parent's approvals)
    tier_overrides:  Dict[str, str] = field(default_factory=dict)

    # Suppressed rule IDs (rule consistently fires but is always overridden)
    suppressed_rules: List[str] = field(default_factory=list)

    # Agent definition paths that are pre-approved for this deployment
    approved_agentdef_paths: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return (
            not self.inherited_allow_http
            and not self.tier_overrides
            and not self.suppressed_rules
        )

    def to_dict(self) -> dict:
        return {
            "derived_from":          self.derived_from,
            "derived_at":            self.derived_at,
            "evidence_sessions":     self.evidence_sessions,
            "inherited_allow_http":  self.inherited_allow_http,
            "tier_overrides":        self.tier_overrides,
            "suppressed_rules":      self.suppressed_rules,
            "approved_agentdef_paths": self.approved_agentdef_paths,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionPolicy":
        return cls(
            derived_from=d.get("derived_from", ""),
            derived_at=d.get("derived_at", time.time()),
            evidence_sessions=d.get("evidence_sessions", 0),
            inherited_allow_http=d.get("inherited_allow_http", []),
            tier_overrides=d.get("tier_overrides", {}),
            suppressed_rules=d.get("suppressed_rules", []),
            approved_agentdef_paths=d.get("approved_agentdef_paths", []),
        )

    @classmethod
    def empty(cls, parent_id: str) -> "SessionPolicy":
        return cls(derived_from=parent_id, evidence_sessions=0)


class PolicySerializer:
    """
    Derives a SessionPolicy from observation graph history.

    The derived policy represents the calibrated behavior of this specific
    deployment — what has been consistently approved, what has been consistently
    blocked, what endpoints are legitimately called.
    """

    def __init__(self, graph):
        self._graph = graph

    def derive(self, parent_session_id: str) -> SessionPolicy:
        """
        Build a SessionPolicy from the parent session's history in the graph.
        Falls back to an empty policy if insufficient data.
        """
        total_sessions = self._graph.session_count()
        if total_sessions < 1:
            return SessionPolicy.empty(parent_session_id)

        allow_http     = self._derive_allow_http()
        tier_overrides = self._derive_tier_overrides()
        suppressed     = self._derive_suppressed_rules()
        approved_paths = self._derive_approved_agentdef_paths()

        policy = SessionPolicy(
            derived_from=parent_session_id,
            evidence_sessions=total_sessions,
            inherited_allow_http=allow_http,
            tier_overrides=tier_overrides,
            suppressed_rules=suppressed,
            approved_agentdef_paths=approved_paths,
        )
        log.info(
            "[PolicySerializer] Derived policy from %d sessions: "
            "%d allow_http, %d tier_overrides, %d suppressed, %d approved_paths",
            total_sessions,
            len(allow_http), len(tier_overrides),
            len(suppressed), len(approved_paths),
        )
        return policy

    def _derive_allow_http(self) -> List[str]:
        """
        HTTP hosts that have appeared in WARN (override) events across
        MIN_SESSIONS_FOR_ALLOW or more sessions are candidates for inheritance.
        Only returns cmd_preview values — these are URL prefixes, not full URLs.
        The child operator should review before applying.
        """
        try:
            with self._graph._conn() as conn:
                rows = conn.execute("""
                    SELECT cmd_preview, COUNT(DISTINCT session_id) as sessions
                    FROM events
                    WHERE surface='http' AND verdict='WARN'
                    AND rule_id IN ('T37', 'T34', 'T35')
                    AND cmd_preview != ''
                    GROUP BY cmd_preview
                    HAVING sessions >= ?
                    ORDER BY sessions DESC
                    LIMIT 20
                """, (MIN_SESSIONS_FOR_ALLOW,)).fetchall()
            return [row["cmd_preview"] for row in rows]
        except Exception as e:
            log.debug("[PolicySerializer] allow_http derivation error: %s", e)
            return []

    def _derive_tier_overrides(self) -> Dict[str, str]:
        """
        Rules that have been consistently WARNed (approved) at high rates
        across multiple sessions are candidates for tier reclassification.
        """
        overrides: Dict[str, str] = {}
        try:
            all_stats = self._graph.all_rule_stats()
            for stats in all_stats:
                if (stats.sessions_seen >= MIN_SESSIONS_FOR_ALLOW
                        and stats.warns_total >= MIN_APPROVALS_FOR_RECLASS
                        and stats.fires_total > 0
                        and (stats.warns_total / stats.fires_total) >= 0.5):
                    overrides[stats.rule_id] = "tier2"
        except Exception as e:
            log.debug("[PolicySerializer] tier_overrides derivation error: %s", e)
        return overrides

    def _derive_suppressed_rules(self) -> List[str]:
        """
        Rules that fire but never result in a BLOCK (only WARNs/ALLOWs)
        across enough sessions suggest the rule may be miscalibrated
        for this deployment.
        """
        suppressed: List[str] = []
        try:
            all_stats = self._graph.all_rule_stats()
            for stats in all_stats:
                if (stats.sessions_seen >= MIN_SESSIONS_FOR_ALLOW * 2
                        and stats.fires_total >= 10
                        and stats.blocks_total == 0):
                    suppressed.append(stats.rule_id)
        except Exception as e:
            log.debug("[PolicySerializer] suppressed_rules derivation error: %s", e)
        return suppressed

    def _derive_approved_agentdef_paths(self) -> List[str]:
        """
        Agent definition paths that have ONLY appeared as clean (no violations)
        across all sessions — these are the known-good paths for this deployment.
        """
        approved: List[str] = []
        try:
            with self._graph._conn() as conn:
                # Paths that exist in agentdef_observations but only as clean reads
                rows = conn.execute("""
                    SELECT DISTINCT path_preview
                    FROM agentdef_observations
                    WHERE violation_type IS NULL
                    AND path_preview NOT IN (
                        SELECT path_preview FROM agentdef_observations
                        WHERE violation_type IS NOT NULL
                    )
                """).fetchall()
            approved = [row["path_preview"] for row in rows]
        except Exception as e:
            log.debug("[PolicySerializer] approved_paths derivation error: %s", e)
        return approved
