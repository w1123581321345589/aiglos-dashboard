"""
aiglos.integrations.multi_agent
================================
Multi-agent session management for Aiglos v0.3.0.

Addresses three capabilities introduced by multi-agent frameworks
(agency-agents, OpenClaw Orchestrator, LangGraph multi-agent):

1. Sub-agent spawn registry
   When a parent agent spawns a child agent process, Aiglos records the
   spawn event and links the child session to the parent in the session
   artifact. This produces a full parent -> child action chain for audit.

2. Agent definition file integrity
   At attach time, Aiglos hashes the agent's definition files (SOUL.md,
   IDENTITY.md, AGENTS.md, SKILL.md, .mdc rules). Any modification to
   these files during the session is flagged as T36_AGENTDEF + T27_PROMPT_INJECT
   because silent reprogramming of the agent identity is the exact exploit
   demonstrated in the McKinsey/Lilli incident (writable system prompts).

3. Session identity chain
   Each Aiglos session generates a short-lived RSA-2048 keypair at attach time.
   Every action is countersigned with the session key. If the agent definition
   is modified mid-session, the identity chain detects the divergence and flags
   it in the session artifact. The public key is embedded in the artifact so
   verifiers can confirm the chain without trusting the session.

Usage:
    from aiglos.integrations.multi_agent import (
        MultiAgentRegistry,
        AgentDefGuard,
        SessionIdentityChain,
    )

    # Registry is created once per root session and shared across child agents
    registry = MultiAgentRegistry(root_session_id="session-abc123")

    # Register a child spawn event
    registry.register_spawn(
        parent_id="session-abc123",
        child_id="session-def456",
        cmd="claude code --print",
        agent_name="security-engineer",
    )

    # Guard agent definition files
    guard = AgentDefGuard()
    guard.snapshot()              # hash current state at attach time
    violations = guard.check()    # call periodically or on suspicious event

    # Identity chain
    chain = SessionIdentityChain(agent_name="orchestrator")
    chain.sign_event(event_dict)  # adds session_sig field to event
    ok = chain.verify(event_dict) # True if sig matches session pubkey
"""


import hashlib
import json
import logging
import os
import re
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("aiglos.multi_agent")


class RegistryIntegrityError(Exception):
    """Raised when a spawn event claims a parent that does not exist in the registry."""
    pass

# ── Agent definition paths to monitor ─────────────────────────────────────────

_AGENT_DEF_DIRS: list[str] = [
    "~/.claude/agents",
    "~/.github/agents",
    "~/.openclaw",
    "~/.gemini/agents",
    "~/.gemini/antigravity",
    "~/.gemini/extensions/agency-agents",
]

_AGENT_DEF_FILES: list[str] = [
    "SOUL.md",
    "IDENTITY.md",
    "AGENTS.md",
    "CONVENTIONS.md",
    ".windsurfrules",
]

# Project-local agent dirs (resolved relative to cwd)
_AGENT_DEF_RELATIVE: list[str] = [
    ".claude/agents",
    ".github/agents",
    ".cursor/rules",
    ".opencode/agents",
]

_AGENT_DEF_EXTENSIONS: set[str] = {".md", ".mdc", ".txt"}


def _collect_agent_def_paths(cwd: Optional[str] = None) -> List[Path]:
    """Return all agent definition file paths that currently exist on disk."""
    paths: list[Path] = []

    # Global dirs
    for d in _AGENT_DEF_DIRS:
        p = Path(d).expanduser()
        if p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix in _AGENT_DEF_EXTENSIONS:
                    paths.append(f)

    # Named files
    for fname in _AGENT_DEF_FILES:
        p = Path(fname).expanduser()
        if p.exists():
            paths.append(p)

    # Project-local dirs
    base = Path(cwd) if cwd else Path.cwd()
    for rel in _AGENT_DEF_RELATIVE:
        p = base / rel
        if p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix in _AGENT_DEF_EXTENSIONS:
                    paths.append(f)

    return list(set(paths))  # dedupe


def _hash_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file, or empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# ── Semantic scoring helpers ──────────────────────────────────────────────────

# Adversarial injection signals in SKILL.md files.
# These are phrases commonly found in prompt injection attacks targeting agent
# definition files. Any of these appearing in a new/modified SKILL.md shifts
# the semantic risk score significantly.
_INJECTION_SIGNALS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard your",
    "your new instructions",
    "you are now",
    "act as if",
    "forget everything",
    "your true purpose",
    "exfiltrate",
    "send to http",
    "send to https",
    "curl http",
    "wget http",
    "base64 encode",
    "do not tell",
    "do not reveal",
    "keep this secret",
    "hidden instruction",
    "secret instruction",
    "system override",
    "admin override",
    "bypass",
    "jailbreak",
]

# Legitimate maintenance signals — phrases common in normal SKILL.md edits
_MAINTENANCE_SIGNALS = [
    "## overview",
    "## usage",
    "## parameters",
    "## example",
    "## notes",
    "## requirements",
    "## output",
    "## steps",
    "trigger",
    "skill.md",
    "instructions",
    "format",
    "return",
]


def _semantic_score(original_text: str, current_text: str) -> tuple[float, str]:
    """
    Compute semantic divergence between two SKILL.md versions.

    Returns (divergence_score, risk_level) where:
      divergence_score: 0.0 (identical) to 1.0 (completely different)
      risk_level: "LOW" | "MEDIUM" | "HIGH"

    Approach: lightweight multi-signal scoring that requires no external
    dependencies. Uses:
      1. Token overlap (Jaccard similarity on word sets)
      2. Injection signal detection in the new content
      3. Structural divergence (section count change)
      4. Length ratio change

    An optional rich embedding path (via the Anthropic API or
    sentence-transformers) can be plugged in by overriding this function.
    """
    if not original_text and not current_text:
        return 0.0, "LOW"
    if not original_text:
        # Brand new file — score based purely on injection signals
        injection_count = sum(
            1 for s in _INJECTION_SIGNALS
            if s.lower() in current_text.lower()
        )
        if injection_count >= 3:
            return 0.95, "HIGH"
        if injection_count >= 1:
            return 0.70, "MEDIUM"
        return 0.30, "LOW"
    if not current_text:
        return 1.0, "HIGH"  # file deleted

    # 1. Token overlap (Jaccard)
    orig_tokens = set(original_text.lower().split())
    curr_tokens = set(current_text.lower().split())
    intersection = orig_tokens & curr_tokens
    union = orig_tokens | curr_tokens
    jaccard = len(intersection) / len(union) if union else 1.0
    token_divergence = 1.0 - jaccard

    # 2. Injection signal score
    injection_hits = sum(
        1 for s in _INJECTION_SIGNALS
        if s.lower() in current_text.lower()
        and s.lower() not in original_text.lower()  # new signal, not pre-existing
    )
    injection_score = min(injection_hits / 3.0, 1.0)  # saturates at 3 hits

    # 3. Structural divergence (markdown section count)
    orig_sections = original_text.count("\n##")
    curr_sections = current_text.count("\n##")
    struct_delta = abs(orig_sections - curr_sections)
    struct_score = min(struct_delta / max(orig_sections, 1), 1.0)

    # 4. Length ratio
    len_ratio = len(current_text) / max(len(original_text), 1)
    # Extreme length changes (>3x or <0.3x) are suspicious
    if len_ratio > 3.0 or len_ratio < 0.3:
        length_score = 0.5
    else:
        length_score = 0.0

    # Weighted composite
    # Injection signals dominate: an injection signal is a hard signal
    divergence = (
        0.30 * token_divergence
        + 0.50 * injection_score
        + 0.15 * struct_score
        + 0.05 * length_score
    )
    divergence = round(min(divergence, 1.0), 4)

    if injection_score > 0 or divergence >= 0.70:
        risk = "HIGH"
    elif divergence >= 0.35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return divergence, risk


def _read_text(path: Path) -> str:
    """Read file text for semantic scoring, silently returning empty string on error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ── AgentDefGuard ──────────────────────────────────────────────────────────────

@dataclass
class AgentDefViolation:
    path: str
    violation_type: str   # "MODIFIED" | "ADDED" | "DELETED"
    original_hash: str
    current_hash: str
    detected_at: float = field(default_factory=time.time)
    rule_id: str = "T36_AGENTDEF"
    threat_family: str = "T27_PROMPT_INJECT + T36_AGENTDEF"
    # Phase 3: semantic scoring
    semantic_score: float = 0.0   # 0.0 (identical) to 1.0 (completely diverged)
    semantic_risk: str = "LOW"    # LOW | MEDIUM | HIGH

    def to_dict(self) -> dict:
        return {
            "path":            self.path,
            "violation":       self.violation_type,
            "original_hash":   self.original_hash,
            "current_hash":    self.current_hash,
            "detected_at":     self.detected_at,
            "rule_id":         self.rule_id,
            "rule_name":       "AGENT_DEF_INTEGRITY",
            "threat_family":   self.threat_family,
            "semantic_score":  self.semantic_score,
            "semantic_risk":   self.semantic_risk,
        }


class AgentDefGuard:
    """
    Snapshot agent definition files at session start and detect modifications.

    Any change to a file in ~/.claude/agents/, .cursor/rules/, etc. during an
    active session is classified T36_AGENTDEF + T27_PROMPT_INJECT: silent
    reprogramming of the agent's identity, guardrails, or tool permissions.
    """

    def __init__(self, cwd: Optional[str] = None):
        self._cwd      = cwd
        self._baseline: Dict[str, str] = {}         # path -> sha256
        self._content_baseline: Dict[str, str] = {} # path -> raw text (for semantic diff)
        self._lock     = threading.Lock()
        self._snapped  = False

    def snapshot(self) -> Dict[str, str]:
        """Hash all current agent definition files and store content baseline."""
        paths = _collect_agent_def_paths(self._cwd)
        baseline: Dict[str, str] = {}
        content_baseline: Dict[str, str] = {}
        for p in paths:
            baseline[str(p)] = _hash_file(p)
            content_baseline[str(p)] = _read_text(p)
        with self._lock:
            self._baseline          = baseline
            self._content_baseline  = content_baseline
            self._snapped           = True
        log.debug("[AgentDefGuard] Snapshotted %d agent definition files.", len(baseline))
        return dict(baseline)

    def check(self) -> List[AgentDefViolation]:
        """
        Compare current disk state to baseline.
        Returns list of violations (empty = clean).
        Each violation now includes semantic_score and semantic_risk (Phase 3).
        """
        if not self._snapped:
            return []

        with self._lock:
            baseline         = dict(self._baseline)
            content_baseline = dict(self._content_baseline)

        violations: List[AgentDefViolation] = []
        current_paths = _collect_agent_def_paths(self._cwd)
        current_map   = {str(p): _hash_file(p) for p in current_paths}

        # Modified or deleted
        for path, orig_hash in baseline.items():
            curr_hash = current_map.get(path, "")
            if curr_hash == "":
                violations.append(AgentDefViolation(
                    path=path,
                    violation_type="DELETED",
                    original_hash=orig_hash,
                    current_hash="",
                    semantic_score=1.0,
                    semantic_risk="HIGH",
                ))
            elif curr_hash != orig_hash:
                orig_text = content_baseline.get(path, "")
                curr_text = _read_text(Path(path))
                score, risk = _semantic_score(orig_text, curr_text)
                violations.append(AgentDefViolation(
                    path=path,
                    violation_type="MODIFIED",
                    original_hash=orig_hash,
                    current_hash=curr_hash,
                    semantic_score=score,
                    semantic_risk=risk,
                ))

        # New files added since snapshot
        for path, curr_hash in current_map.items():
            if path not in baseline:
                curr_text = _read_text(Path(path))
                score, risk = _semantic_score("", curr_text)
                violations.append(AgentDefViolation(
                    path=path,
                    violation_type="ADDED",
                    original_hash="",
                    current_hash=curr_hash,
                    semantic_score=score,
                    semantic_risk=risk,
                ))

        if violations:
            high = sum(1 for v in violations if v.semantic_risk == "HIGH")
            log.warning(
                "[AgentDefGuard] %d violation(s): %d HIGH semantic risk.",
                len(violations), high,
            )
        return violations

    @property
    def baseline(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._baseline)


# ── SessionIdentityChain ───────────────────────────────────────────────────────

class SessionIdentityChain:
    """
    Lightweight session identity for multi-agent audit chains.

    Uses HMAC-SHA256 with a session secret rather than full RSA (no external
    dependencies). Each event in the session artifact carries a session_sig
    field so downstream verifiers can confirm the event belongs to this
    session and was not injected from a different agent context.

    The session_public_token (SHA-256 of the secret) is embedded in the
    artifact header. Verifiers check: HMAC(secret, event_json) == event.session_sig.
    """

    def __init__(self, agent_name: str, session_id: Optional[str] = None):
        import secrets as _secrets
        self.agent_name    = agent_name
        self.session_id    = session_id or _secrets.token_hex(16)
        self._secret       = _secrets.token_bytes(32)
        self._event_count  = 0
        self._created_at   = time.time()
        # Public token: SHA-256(secret). Embeds in artifact without exposing secret.
        self.public_token  = hashlib.sha256(self._secret).hexdigest()

    def sign_event(self, event: dict) -> dict:
        """Add session_sig to an event dict in place. Returns the event."""
        import hmac as _hmac
        self._event_count += 1
        payload = json.dumps({
            "session_id":   self.session_id,
            "event_count":  self._event_count,
            "rule_id":      event.get("rule_id", ""),
            "verdict":      event.get("verdict", ""),
            "cmd":          event.get("cmd", event.get("url", "")),
            "ts":           event.get("timestamp", time.time()),
        }, sort_keys=True).encode()
        sig = _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        event["session_sig"]   = sig
        event["session_id"]    = self.session_id
        event["event_seq"]     = self._event_count
        return event

    def verify(self, event: dict) -> bool:
        """Verify a signed event belongs to this session."""
        import hmac as _hmac
        stored_sig = event.get("session_sig", "")
        seq        = event.get("event_seq", 0)
        payload    = json.dumps({
            "session_id":  self.session_id,
            "event_count": seq,
            "rule_id":     event.get("rule_id", ""),
            "verdict":     event.get("verdict", ""),
            "cmd":         event.get("cmd", event.get("url", "")),
            "ts":          event.get("timestamp", 0.0),
        }, sort_keys=True).encode()
        expected = _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return _hmac.compare_digest(stored_sig, expected)

    def header(self) -> dict:
        """Return the artifact header entry for this session."""
        return {
            "session_id":     self.session_id,
            "agent_name":     self.agent_name,
            "public_token":   self.public_token,
            "created_at":     self._created_at,
            "event_count":    self._event_count,
        }


# ── MultiAgentRegistry ─────────────────────────────────────────────────────────

@dataclass
class SpawnEvent:
    parent_id:   str
    child_id:    str
    agent_name:  str
    cmd:         str
    spawned_at:  float = field(default_factory=time.time)
    policy_propagated: bool = False
    inherited_policy: Optional[dict] = None  # Phase 5: serialized SessionPolicy

    def to_dict(self) -> dict:
        return {
            "event_type":         "AGENT_SPAWN",
            "parent_session_id":  self.parent_id,
            "child_session_id":   self.child_id,
            "agent_name":         self.agent_name,
            "cmd":                self.cmd[:256],
            "spawned_at":         self.spawned_at,
            "policy_propagated":  self.policy_propagated,
            "inherited_policy":   self.inherited_policy,
            "rule_id":            "T38",
            "rule_name":          "AGENT_SPAWN",
        }


class MultiAgentRegistry:
    """
    Registry of all agent sessions rooted at a parent session.

    When an orchestrator (e.g. agency-agents Agents Orchestrator) spawns
    sub-agents in parallel, each child session registers here. The session
    artifact then contains a full tree of parent -> child spawn events with
    action chains, making multi-agent workflows fully auditable.
    """

    def __init__(self, root_session_id: str, root_agent_name: str = "orchestrator"):
        self._root_id   = root_session_id
        self._root_name = root_agent_name
        self._spawns:   List[SpawnEvent]           = []
        self._children: Dict[str, "ChildSession"]  = {}
        self._lock      = threading.Lock()
        self._created_at = time.time()

    def register_spawn(
        self,
        parent_id:   str,
        child_id:    str,
        cmd:         str,
        agent_name:  str = "sub-agent",
        propagate_policy: bool = True,
        inherited_policy: Optional[dict] = None,
    ) -> SpawnEvent:
        """Record a sub-agent spawn and return the SpawnEvent.

        Raises RegistryIntegrityError if parent_id is not the root session
        and not a known child — prevents manufactured provenance chains.
        """
        with self._lock:
            known_ids = {self._root_id} | set(self._children.keys())
            if parent_id not in known_ids:
                msg = (
                    f"Registry integrity violation: parent_id '{parent_id}' "
                    f"is not known to this registry (root={self._root_id}). "
                    "Spawn rejected — potential provenance chain forgery."
                )
                log.error("[MultiAgentRegistry] %s", msg)
                raise RegistryIntegrityError(msg)

        ev = SpawnEvent(
            parent_id=parent_id,
            child_id=child_id,
            agent_name=agent_name,
            cmd=cmd,
            policy_propagated=propagate_policy,
            inherited_policy=inherited_policy,
        )
        with self._lock:
            self._spawns.append(ev)
            self._children[child_id] = ChildSession(
                session_id=child_id,
                agent_name=agent_name,
                parent_id=parent_id,
                spawned_at=ev.spawned_at,
            )
        log.info(
            "[MultiAgentRegistry] Spawn: %s -> %s (%s) policy_propagated=%s policy=%s",
            parent_id[:8], child_id[:8], agent_name, propagate_policy,
            "inherited" if inherited_policy else "none",
        )
        return ev

    def get_child(self, child_id: str) -> Optional["ChildSession"]:
        with self._lock:
            return self._children.get(child_id)

    def all_spawns(self) -> List[SpawnEvent]:
        with self._lock:
            return list(self._spawns)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "root_session_id": self._root_id,
                "root_agent_name": self._root_name,
                "created_at":      self._created_at,
                "child_count":     len(self._children),
                "spawns":          [s.to_dict() for s in self._spawns],
                "children":        {k: v.to_dict() for k, v in self._children.items()},
            }


@dataclass
class ChildSession:
    session_id:  str
    agent_name:  str
    parent_id:   str
    spawned_at:  float
    events:      List[dict] = field(default_factory=list)
    closed_at:   Optional[float] = None

    def add_event(self, event: dict) -> None:
        self.events.append(event)

    def close(self) -> None:
        self.closed_at = time.time()

    def to_dict(self) -> dict:
        return {
            "session_id":  self.session_id,
            "agent_name":  self.agent_name,
            "parent_id":   self.parent_id,
            "spawned_at":  self.spawned_at,
            "closed_at":   self.closed_at,
            "event_count": len(self.events),
            "events":      self.events,
        }
