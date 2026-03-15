"""
Session-level causal attribution — walks backward from blocked/warned
actions to identify which inbound content was in the agent's context
when the decision was made.
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("aiglos.causal_tracer")

_LOOKBACK_STEPS = 15       # how far back to search for attribution sources
_SUSPICION_FLOOR = 0.20    # min injection score to be a candidate cause


@dataclass
class ContextEntry:
    step:           int
    tool_name:      str
    content_hash:   str
    content_preview: str
    injection_score: float
    risk:           str          # LOW | MEDIUM | HIGH
    phrase_hits:    List[str]
    encoding_anomalies: List[str]
    source_url:     Optional[str]
    ingested_at:    float = field(default_factory=time.time)

    @property
    def is_suspicious(self) -> bool:
        return self.injection_score >= _SUSPICION_FLOOR

    def to_dict(self) -> dict:
        return {
            "step":              self.step,
            "tool_name":         self.tool_name,
            "content_hash":      self.content_hash,
            "content_preview":   self.content_preview,
            "injection_score":   round(self.injection_score, 4),
            "risk":              self.risk,
            "phrase_hits":       self.phrase_hits,
            "encoding_anomalies": self.encoding_anomalies,
            "source_url":        self.source_url,
        }


@dataclass
class TaggedAction:
    step:            int
    tool_name:       str
    verdict:         str          # ALLOW | WARN | BLOCK
    rule_id:         str
    rule_name:       str
    details:         Dict[str, Any]
    context_snapshot: List[ContextEntry]   # copy of context window at this moment
    timestamp:       float = field(default_factory=time.time)

    @property
    def is_flagged(self) -> bool:
        return self.verdict in ("BLOCK", "WARN")

    def to_dict(self) -> dict:
        return {
            "step":       self.step,
            "tool_name":  self.tool_name,
            "verdict":    self.verdict,
            "rule_id":    self.rule_id,
            "rule_name":  self.rule_name,
            "details":    self.details,
            "context_snapshot": [e.to_dict() for e in self.context_snapshot],
        }


@dataclass
class CausalChain:
    action:              TaggedAction
    attributed_sources:  List[ContextEntry]   # ranked by injection score, desc
    confidence:          str                  # HIGH | MEDIUM | LOW | NONE
    confidence_score:    float                # 0.0-1.0
    narrative:           str                  # human-readable explanation
    steps_since_injection: Optional[int]      # steps between top source and action

    @property
    def has_attribution(self) -> bool:
        return self.confidence in ("HIGH", "MEDIUM")

    def to_dict(self) -> dict:
        return {
            "action":              self.action.to_dict(),
            "attributed_sources":  [s.to_dict() for s in self.attributed_sources],
            "confidence":          self.confidence,
            "confidence_score":    round(self.confidence_score, 4),
            "narrative":           self.narrative,
            "steps_since_injection": self.steps_since_injection,
        }


@dataclass
class AttributionResult:
    session_id:          str
    agent_name:          str
    total_actions:       int
    flagged_actions:     int
    attributed_actions:  int          # flagged with HIGH or MEDIUM attribution
    chains:              List[CausalChain]
    session_verdict:     str          # CLEAN | SUSPICIOUS | ATTACK_CONFIRMED
    session_narrative:   str
    timestamp:           float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "session_id":         self.session_id,
            "agent_name":         self.agent_name,
            "total_actions":      self.total_actions,
            "flagged_actions":    self.flagged_actions,
            "attributed_actions": self.attributed_actions,
            "chains":             [c.to_dict() for c in self.chains],
            "session_verdict":    self.session_verdict,
            "session_narrative":  self.session_narrative,
            "timestamp":          self.timestamp,
        }

    def render(self) -> str:
        """Human-readable investigation report for CLI output."""
        lines = [
            "",
            "  Aiglos Causal Attribution Report",
            f"  {'─' * 52}",
            f"  Session   : {self.session_id}",
            f"  Agent     : {self.agent_name}",
            f"  Verdict   : {self.session_verdict}",
            f"  Actions   : {self.total_actions} total · {self.flagged_actions} flagged · "
            f"{self.attributed_actions} attributed",
            "",
        ]

        if not self.chains:
            lines.append("  No flagged actions in this session.")
            return "\n".join(lines)

        for chain in self.chains:
            action = chain.action
            conf_color = {
                "HIGH":   "!",
                "MEDIUM": "~",
                "LOW":    "?",
                "NONE":   " ",
            }.get(chain.confidence, " ")

            lines += [
                f"  [{conf_color}] Step {action.step:>3}  {action.verdict:<7}  "
                f"{action.tool_name}  [{action.rule_id}]",
            ]

            if chain.attributed_sources:
                top = chain.attributed_sources[0]
                lines += [
                    f"      Attribution: {chain.confidence} confidence "
                    f"({chain.confidence_score:.0%})",
                    f"      Source:      step {top.step}  {top.tool_name}  "
                    f"[score {top.injection_score:.2f} · {top.risk}]",
                ]
                if top.source_url:
                    lines.append(f"      URL:         {top.source_url}")
                if top.phrase_hits:
                    lines.append(f"      Phrases:     {top.phrase_hits[:3]}")
                if chain.steps_since_injection is not None:
                    lines.append(
                        f"      Gap:         {chain.steps_since_injection} steps "
                        "between injection and action"
                    )
                lines.append(f"      Narrative:   {chain.narrative}")
            else:
                lines.append("      No injection source found in context.")
            lines.append("")

        lines += [
            f"  {'─' * 52}",
            f"  {self.session_narrative}",
            "",
        ]
        return "\n".join(lines)


class CausalTracer:
    """Rolling context window + outbound action tagging. Runs backward
    attribution at session close to connect flagged actions to injection
    sources."""

    def __init__(
        self,
        session_id:  str = "unknown",
        agent_name:  str = "unknown",
        window_size: int = 20,   # max context entries to track simultaneously
    ):
        self.session_id  = session_id
        self.agent_name  = agent_name
        self.window_size = window_size
        self._step       = 0
        self._context:   List[ContextEntry]  = []   # rolling context window
        self._actions:   List[TaggedAction]  = []   # all tagged actions
        self._result:    Optional[AttributionResult] = None

    def register_inbound(self, scan_result, step: Optional[int] = None) -> None:
        if hasattr(scan_result, "to_dict"):
            d = scan_result.to_dict()
        else:
            d = scan_result

        self._step = step if step is not None else self._step + 1

        entry = ContextEntry(
            step=self._step,
            tool_name=d.get("tool_name", "unknown"),
            content_hash=d.get("content_hash", ""),
            content_preview=d.get("content_preview", "")[:120],
            injection_score=d.get("score", 0.0),
            risk=d.get("risk", "LOW"),
            phrase_hits=d.get("phrase_hits", []),
            encoding_anomalies=d.get("encoding_anomalies", []),
            source_url=d.get("source_url"),
        )

        self._context.append(entry)

        # oldest entries fall off the end
        if len(self._context) > self.window_size:
            self._context = self._context[-self.window_size:]

        if entry.is_suspicious:
            log.debug(
                "[CausalTracer] Registered suspicious inbound content — "
                "step=%d tool=%s score=%.2f risk=%s",
                self._step, entry.tool_name, entry.injection_score, entry.risk,
            )

    def tag_outbound_action(
        self,
        tool_name: str,
        verdict:   str,
        rule_id:   str    = "none",
        rule_name: str    = "none",
        details:   Optional[Dict[str, Any]] = None,
        step:      Optional[int] = None,
    ) -> TaggedAction:
        self._step = step if step is not None else self._step + 1

        action = TaggedAction(
            step=self._step,
            tool_name=tool_name,
            verdict=verdict,
            rule_id=rule_id,
            rule_name=rule_name,
            details=details or {},
            context_snapshot=list(self._context),  # copy of current window
        )
        self._actions.append(action)
        return action

    def attribute(self) -> AttributionResult:
        """Run backward attribution across all flagged actions. Cached after
        the first call — attribute() is idempotent."""
        if self._result is not None:    # belt-and-suspenders, attribute() caches
            return self._result

        flagged    = [a for a in self._actions if a.is_flagged]
        chains:    List[CausalChain] = []
        attributed = 0

        for action in flagged:
            chain = self._build_chain(action)
            chains.append(chain)
            if chain.has_attribution:
                attributed += 1

        session_verdict, session_narrative = self._session_verdict(
            chains, len(flagged), attributed
        )

        self._result = AttributionResult(
            session_id=self.session_id,
            agent_name=self.agent_name,
            total_actions=len(self._actions),
            flagged_actions=len(flagged),
            attributed_actions=attributed,
            chains=chains,
            session_verdict=session_verdict,
            session_narrative=session_narrative,
        )
        return self._result

    def _build_chain(self, action: TaggedAction) -> CausalChain:
        """Build a CausalChain for a single flagged action."""
        # Candidates: suspicious context entries present at action time
        candidates = [
            e for e in action.context_snapshot
            if e.is_suspicious
        ]

        if not candidates:
            return CausalChain(
                action=action,
                attributed_sources=[],
                confidence="NONE",
                confidence_score=0.0,
                narrative=(
                    f"No suspicious inbound content was in context when the agent "
                    f"attempted {action.tool_name} ({action.rule_id}). "
                    "This action may have been triggered by a user instruction "
                    "or internal agent reasoning."
                ),
                steps_since_injection=None,
            )

        # Rank by injection score descending
        candidates.sort(key=lambda e: e.injection_score, reverse=True)
        top = candidates[0]
        steps_since = action.step - top.step

        if top.risk == "HIGH" and steps_since <= _LOOKBACK_STEPS:
            conf = "HIGH"
            conf_score = min(
                top.injection_score * (1.0 - steps_since / (_LOOKBACK_STEPS * 2)),
                0.99,
            )
        elif top.risk in ("HIGH", "MEDIUM") and steps_since <= _LOOKBACK_STEPS * 2:
            conf = "MEDIUM"
            conf_score = min(top.injection_score * 0.6, 0.70)
        else:
            conf = "LOW"
            conf_score = min(top.injection_score * 0.3, 0.35)

        # Build narrative
        action_desc = f"{action.tool_name} ({action.rule_id})"
        source_desc = f"step {top.step} ({top.tool_name}"
        if top.source_url:
            source_desc += f" · {top.source_url}"
        source_desc += ")"

        if conf == "HIGH":
            narrative = (
                f"HIGH confidence: the {action.verdict.lower()} action at step "
                f"{action.step} ({action_desc}) is very likely caused by the "
                f"HIGH-risk injection in {source_desc}, "
                f"{steps_since} steps earlier. "
            )
        elif conf == "MEDIUM":
            narrative = (
                f"MEDIUM confidence: the {action.verdict.lower()} action at step "
                f"{action.step} ({action_desc}) may have been caused by the "
                f"injection in {source_desc}, {steps_since} steps earlier. "
            )
        else:
            narrative = (
                f"LOW confidence: suspicious content from {source_desc} was in "
                f"context when the agent attempted {action_desc}, but the "
                f"connection is uncertain. "
            )

        if top.phrase_hits:
            narrative += (
                f"The injection phrase '{top.phrase_hits[0]}' "
                f"in the source content is consistent with causing this action."
            )

        return CausalChain(
            action=action,
            attributed_sources=candidates,
            confidence=conf,
            confidence_score=conf_score,
            narrative=narrative,
            steps_since_injection=steps_since,
        )

    def _session_verdict(
        self,
        chains: List[CausalChain],
        flagged: int,
        attributed: int,
    ) -> tuple[str, str]:
        """Determine session-level verdict and narrative."""
        high_conf = sum(1 for c in chains if c.confidence == "HIGH")
        med_conf  = sum(1 for c in chains if c.confidence == "MEDIUM")

        if high_conf >= 2:
            verdict = "ATTACK_CONFIRMED"
            narrative = (
                f"ATTACK CONFIRMED: {high_conf} blocked actions have HIGH confidence "
                "attribution to injection sources. This session shows systematic "
                "injection-to-action exploitation. Review the causal chains above "
                "and the full injection provenance log."
            )
        elif high_conf >= 1 or (med_conf >= 2 and flagged >= 2):
            verdict = "SUSPICIOUS"
            narrative = (
                f"SUSPICIOUS: {flagged} flagged actions, {attributed} with attribution. "
                "At least one blocked action has a plausible injection cause. "
                "This session warrants investigation."
            )
        elif flagged > 0:
            verdict = "SUSPICIOUS"
            narrative = (
                f"{flagged} action(s) were flagged but no high-confidence injection "
                "source was identified. The actions may have been triggered by "
                "legitimate user instructions, or by injections that have since "
                "scrolled out of the attribution window."
            )
        else:
            verdict = "CLEAN"
            narrative = (
                "No flagged actions in this session. No causal attribution required."
            )

        return verdict, narrative

    def current_context(self) -> List[ContextEntry]:
        return list(self._context)

    def suspicious_in_context(self) -> List[ContextEntry]:
        return [e for e in self._context if e.is_suspicious]

    def to_artifact_section(self) -> dict:
        result = self.attribute()
        return {
            "causal_attribution": result.to_dict(),
        }
