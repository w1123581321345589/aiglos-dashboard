import hashlib
import hmac
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

_INJECTION_SIGNALS = [
    "ignore previous instructions",
    "ignore all previous",
    "your new instructions",
    "do not tell",
    "keep this secret",
    "exfiltrate",
    "base64 encode",
    "you are now",
    "bypass",
    "jailbreak",
]

_URL_PATTERN = re.compile(r"https?://[^\s\"']+")

_AGENT_DEF_DIRS = [
    os.path.join(".claude", "agents"),
    os.path.join(".github", "agents"),
    os.path.join(".cursor", "rules"),
    os.path.join(".openclaw"),
    os.path.join(".gemini", "agents"),
]

_AGENT_DEF_FILES = [
    "SOUL.md", "IDENTITY.md", "AGENTS.md", "SKILL.md",
    "CONVENTIONS.md", ".windsurfrules",
]


def _hash_file(path: str) -> str:
    try:
        with open(path, "r") as f:
            content = f.read()
        return hashlib.sha256(content.encode()).hexdigest()
    except Exception:
        return ""


def _collect_agent_def_paths(cwd: str) -> List[str]:
    paths = []
    for d in _AGENT_DEF_DIRS:
        full = os.path.join(cwd, d)
        if os.path.isdir(full):
            for fn in os.listdir(full):
                fp = os.path.join(full, fn)
                if os.path.isfile(fp):
                    paths.append(fp)
    for fn in _AGENT_DEF_FILES:
        fp = os.path.join(cwd, fn)
        if os.path.isfile(fp):
            paths.append(fp)
    return paths


def _semantic_score(original: str, current: str) -> Tuple[float, str]:
    if not original and not current:
        return 0.0, "LOW"
    if original and not current:
        return 1.0, "HIGH"

    score = 0.0
    lower = current.lower()

    signal_count = 0
    for sig in _INJECTION_SIGNALS:
        if sig in lower:
            signal_count += 1

    if signal_count > 0:
        score += min(0.5, signal_count * 0.15)

    urls = _URL_PATTERN.findall(current)
    orig_urls = set(_URL_PATTERN.findall(original))
    new_urls = [u for u in urls if u not in orig_urls]
    if new_urls:
        score += 0.15

    if original:
        orig_words = set(original.lower().split())
        curr_words = set(lower.split())
        if orig_words:
            overlap = len(orig_words & curr_words) / len(orig_words)
            divergence = 1.0 - overlap
            score += divergence * 0.4
        else:
            score += 0.2
    else:
        if signal_count > 0:
            score += 0.3
        else:
            score += 0.1

    score = max(0.0, min(1.0, score))

    if score >= 0.50:
        risk = "HIGH"
    elif score >= 0.30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk


@dataclass
class AgentDefViolation:
    path: str
    violation_type: str
    original_hash: str
    current_hash: str
    detected_at: float = 0.0
    semantic_score: float = 0.0
    semantic_risk: str = "LOW"
    rule_id: str = "T36_AGENTDEF"

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "violation": self.violation_type,
            "original_hash": self.original_hash,
            "current_hash": self.current_hash,
            "detected_at": self.detected_at,
            "semantic_score": self.semantic_score,
            "semantic_risk": self.semantic_risk,
            "rule_id": self.rule_id,
            "threat_family": "T36_AGENTDEF",
        }


class AgentDefGuard:

    AGENT_DIRS = _AGENT_DEF_DIRS

    def __init__(self, cwd: str = "."):
        self._cwd = cwd
        self._snapshots: Dict[str, Tuple[str, str]] = {}
        self._snapshot_taken = False

    def snapshot(self) -> Dict[str, str]:
        self._snapshots.clear()
        self._snapshot_taken = True
        result: Dict[str, str] = {}
        paths = _collect_agent_def_paths(self._cwd)
        for fp in paths:
            try:
                content = open(fp).read()
                h = hashlib.sha256(content.encode()).hexdigest()
                self._snapshots[fp] = (h, content)
                result[fp] = h
            except Exception:
                continue
        return result

    def check(self) -> List[AgentDefViolation]:
        if not self._snapshot_taken:
            return []
        violations = []
        current_files: Dict[str, Tuple[str, str]] = {}
        paths = _collect_agent_def_paths(self._cwd)
        for fp in paths:
            try:
                content = open(fp).read()
                h = hashlib.sha256(content.encode()).hexdigest()
                current_files[fp] = (h, content)
            except Exception:
                continue

        for fp, (orig_hash, orig_content) in self._snapshots.items():
            if fp not in current_files:
                score, risk = _semantic_score(orig_content, "")
                violations.append(AgentDefViolation(
                    path=fp, violation_type="DELETED",
                    original_hash=orig_hash, current_hash="",
                    detected_at=time.time(),
                    semantic_score=score, semantic_risk=risk,
                ))
            else:
                curr_hash, curr_content = current_files[fp]
                if curr_hash != orig_hash:
                    score, risk = _semantic_score(orig_content, curr_content)
                    violations.append(AgentDefViolation(
                        path=fp, violation_type="MODIFIED",
                        original_hash=orig_hash, current_hash=curr_hash,
                        detected_at=time.time(),
                        semantic_score=score, semantic_risk=risk,
                    ))

        for fp, (curr_hash, curr_content) in current_files.items():
            if fp not in self._snapshots:
                score, risk = _semantic_score("", curr_content)
                violations.append(AgentDefViolation(
                    path=fp, violation_type="ADDED",
                    original_hash="", current_hash=curr_hash,
                    detected_at=time.time(),
                    semantic_score=score, semantic_risk=risk,
                ))

        return violations


@dataclass
class SpawnEvent:
    parent_id: str
    child_id: str
    cmd: str
    agent_name: str = ""
    policy_propagated: bool = True
    spawned_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "event_type": "AGENT_SPAWN",
            "rule_id": "T38",
            "rule_name": "AGENT_SPAWN",
            "parent_session_id": self.parent_id,
            "child_session_id": self.child_id,
            "cmd": self.cmd,
            "agent_name": self.agent_name,
            "policy_propagated": self.policy_propagated,
            "spawned_at": self.spawned_at,
        }


@dataclass
class ChildSession:
    child_id: str
    parent_id: str
    agent_name: str = ""
    cmd: str = ""
    policy_propagated: bool = True
    events: List[Dict] = field(default_factory=list)

    def add_event(self, event: Dict):
        self.events.append(event)

    def to_dict(self) -> Dict:
        return {
            "child_id": self.child_id,
            "parent_id": self.parent_id,
            "agent_name": self.agent_name,
            "cmd": self.cmd,
            "policy_propagated": self.policy_propagated,
            "event_count": len(self.events),
        }


class MultiAgentRegistry:

    def __init__(self, root_session_id: str = "", root_agent_name: str = ""):
        self._root_id = root_session_id
        self._root_name = root_agent_name
        self._spawns: List[SpawnEvent] = []
        self._children: Dict[str, ChildSession] = {}

    def register_spawn(self, parent_id: str, child_id: str, cmd: str,
                        agent_name: str = "", policy_propagated: bool = True) -> SpawnEvent:
        ev = SpawnEvent(
            parent_id=parent_id, child_id=child_id, cmd=cmd,
            agent_name=agent_name, policy_propagated=policy_propagated,
        )
        self._spawns.append(ev)
        child = ChildSession(
            child_id=child_id, parent_id=parent_id,
            agent_name=agent_name, cmd=cmd,
            policy_propagated=policy_propagated,
        )
        self._children[child_id] = child
        return ev

    def get_child(self, child_id: str) -> Optional[ChildSession]:
        return self._children.get(child_id)

    def all_spawns(self) -> List[SpawnEvent]:
        return list(self._spawns)

    def to_dict(self) -> Dict:
        return {
            "root_session_id": self._root_id,
            "root_agent_name": self._root_name,
            "child_count": len(self._children),
            "spawns": [s.to_dict() for s in self._spawns],
            "children": {k: v.to_dict() for k, v in self._children.items()},
        }


class SessionIdentityChain:

    def __init__(self, agent_name: str = "", session_id: str = None):
        self.agent_name = agent_name
        self.session_id = session_id or uuid.uuid4().hex
        self._secret = os.urandom(32)
        self.public_token = hashlib.sha256(self._secret).hexdigest()
        self._event_count = 0
        self._created_at = time.time()

    def sign_event(self, event: Dict) -> Dict:
        self._event_count += 1
        event["session_id"] = self.session_id
        event["event_seq"] = self._event_count
        payload = f"{self.session_id}:{self._event_count}:{event.get('rule_id','')}:{event.get('verdict','')}:{event.get('cmd','')}"
        sig = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()
        event["session_sig"] = sig
        return event

    def verify(self, event: Dict) -> bool:
        seq = event.get("event_seq")
        sig = event.get("session_sig")
        sid = event.get("session_id")
        if not sig or sid != self.session_id:
            return False
        payload = f"{sid}:{seq}:{event.get('rule_id','')}:{event.get('verdict','')}:{event.get('cmd','')}"
        expected = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)

    def header(self) -> Dict:
        return {
            "agent_name": self.agent_name,
            "session_id": self.session_id,
            "public_token": self.public_token,
            "created_at": self._created_at,
        }
