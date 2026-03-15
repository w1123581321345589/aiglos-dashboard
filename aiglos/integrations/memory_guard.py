import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

MEMORY_WRITE_TOOLS = [
    "store_memory", "update_memory", "add_memory", "save_memory",
    "remember", "memorize", "set_memory", "write_memory",
    "create_memory", "upsert_memory",
]

MEMORY_READ_TOOLS = [
    "retrieve_memory", "search_memories", "recall", "get_memories",
    "query_memory", "read_memory", "list_memories", "find_memories",
]

MEMORY_MUTATE_TOOLS = [
    "delete_memory", "clear_memories", "remove_memory", "purge_memories",
]

_ALL_MEMORY_TOOLS = set(MEMORY_WRITE_TOOLS + MEMORY_READ_TOOLS + MEMORY_MUTATE_TOOLS)

_INJECTION_SIGNALS = [
    ("pre-authorized", 0.50),
    ("ignore previous instructions", 0.35),
    ("ignore all prior", 0.30),
    ("your new instructions", 0.30),
    ("bypass", 0.25),
    ("jailbreak", 0.30),
    ("exfiltrate", 0.30),
    ("always allow", 0.25),
    ("never block", 0.25),
    ("remember to always", 0.25),
    ("this is permanent", 0.20),
    ("elevated privileges", 0.25),
    ("treat as verified", 0.25),
    ("admin", 0.20),
]

_ENDPOINT_SIGNALS = [
    ("http://", 0.15),
    ("https://", 0.10),
    ("use this url", 0.20),
    ("api has moved", 0.15),
]

_CREDENTIAL_SIGNALS = [
    ("api key", 0.15),
    ("password", 0.15),
    ("sk-live-", 0.20),
    ("secret", 0.10),
    ("credential", 0.15),
]

_C2_CHANNEL_SIGNALS = [
    ("daily cron", 0.20),
    ("check each morning", 0.15),
    ("subscribe", 0.15),
    ("newsletter", 0.15),
    ("save these", 0.15),
    ("save this endpoint", 0.15),
    ("fetch and apply", 0.15),
    ("daily notes", 0.15),
]

_MEMORY_INJECTION_SIGNALS = [
    "pre-authorized",
    "ignore previous instructions",
    "ignore all prior",
    "your new instructions",
    "bypass",
    "jailbreak",
    "exfiltrate",
    "always allow",
    "never block",
    "remember to always",
    "this is permanent",
    "elevated privileges",
    "treat as verified",
    "admin",
    "use this url",
    "api has moved",
    "api key",
    "password",
    "secret",
    "credential",
    "check each morning for new issues",
    "set up a cron job",
    "subscribe to this newsletter",
    "save this endpoint for future use",
    "save these endpoints for future use",
    "fetch and apply tips from external sources",
    "read and surface relevant tips",
    "daily notes for tracking",
]

_COMPRESSION_SIGNALS = [
    "api key", "credential", "secret", "password", "auth",
    "token", "sensitive", "restricted", "confidential", "private",
]


def _score_memory_content(content: str) -> Tuple[float, str, List[str]]:
    if not content:
        return 0.0, "LOW", []

    lower = content.lower()
    score = 0.0
    signals = []

    for sig, weight in _INJECTION_SIGNALS:
        if sig in lower:
            score += weight
            signals.append(sig)

    for sig, weight in _ENDPOINT_SIGNALS:
        if sig in lower:
            score += weight
            if sig not in signals:
                signals.append(sig)

    for sig, weight in _CREDENTIAL_SIGNALS:
        if sig in lower:
            score += weight
            if sig not in signals:
                signals.append(sig)

    for sig, weight in _C2_CHANNEL_SIGNALS:
        if sig in lower:
            score += weight
            if sig not in signals:
                signals.append(sig)

    word_count = len(content.split())
    if word_count > 100:
        score += min(0.10, word_count / 2000)

    score = max(0.0, min(1.0, score))

    if score >= 0.35:
        risk = "HIGH"
    elif score >= 0.20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk, signals


def _check_compression_loss(old_content) -> bool:
    if not old_content:
        return False
    lower = old_content.lower()
    found = sum(1 for s in _COMPRESSION_SIGNALS if s in lower)
    return found >= 2


def is_memory_tool(tool_name: str) -> bool:
    lower = tool_name.lower()
    if lower in {t.lower() for t in _ALL_MEMORY_TOOLS}:
        return True
    if "memory" in lower or "remember" in lower or "memorize" in lower:
        return True
    return False


@dataclass
class MemoryWriteResult:
    verdict: str = "ALLOW"
    rule_id: str = "none"
    rule_name: str = "none"
    reason: str = ""
    content_preview: str = ""
    content_hash: str = ""
    semantic_score: float = 0.0
    semantic_risk: str = "LOW"
    signals_found: List[str] = field(default_factory=list)
    session_id: str = ""
    tool_name: str = ""
    timestamp: float = 0.0
    memory_category: Optional[str] = None
    compression_warning: bool = False
    surface: str = "mcp"

    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "content_preview": self.content_preview,
            "content_hash": self.content_hash,
            "semantic_score": self.semantic_score,
            "semantic_risk": self.semantic_risk,
            "signals_found": self.signals_found,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "memory_category": self.memory_category,
            "compression_warning": self.compression_warning,
            "surface": self.surface,
        }


class MemoryWriteGuard:

    def __init__(self, session_id: str = "", agent_name: str = "", mode: str = "block"):
        self.session_id = session_id
        self.agent_name = agent_name
        self.mode = mode
        self._provenance: List[Dict] = []
        self._write_count = 0
        self._block_count = 0

    def before_tool_call(self, tool_name: str, args: Dict) -> MemoryWriteResult:
        lower_tool = tool_name.lower()

        if lower_tool in {t.lower() for t in MEMORY_READ_TOOLS}:
            return MemoryWriteResult(
                verdict="ALLOW", rule_id="none", rule_name="none",
                session_id=self.session_id, tool_name=tool_name,
                timestamp=time.time(), surface="mcp",
            )

        if lower_tool in {t.lower() for t in MEMORY_MUTATE_TOOLS}:
            return MemoryWriteResult(
                verdict="WARN", rule_id="T31", rule_name="MEMORY_MUTATE",
                reason="Memory mutation operation",
                session_id=self.session_id, tool_name=tool_name,
                timestamp=time.time(), surface="mcp",
            )

        content = args.get("content", args.get("memory", args.get("text", "")))
        old_content = args.get("old_content", "")
        category = args.get("category", None)

        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]
        preview = content[:100]
        score, risk, signals = _score_memory_content(content)
        comp_warn = _check_compression_loss(old_content) if old_content else False

        if risk == "HIGH":
            verdict = "BLOCK" if self.mode == "block" else "WARN"
            rule_id = "T31"
            rule_name = "MEMORY_POISON"
            self._block_count += 1
        elif risk == "MEDIUM":
            verdict = "WARN" if self.mode == "block" else "WARN"
            rule_id = "T31"
            rule_name = "MEMORY_WARN"
        else:
            verdict = "ALLOW"
            rule_id = "none"
            rule_name = "none"

        self._write_count += 1
        result = MemoryWriteResult(
            verdict=verdict, rule_id=rule_id, rule_name=rule_name,
            content_preview=preview, content_hash=content_hash,
            semantic_score=score, semantic_risk=risk,
            signals_found=signals, session_id=self.session_id,
            tool_name=tool_name, timestamp=time.time(),
            memory_category=category, compression_warning=comp_warn,
            surface="mcp",
        )
        self._provenance.append(result.to_dict())
        return result

    def provenance(self) -> List[Dict]:
        return list(self._provenance)

    def high_risk_writes(self) -> List[Dict]:
        return [p for p in self._provenance if p.get("semantic_risk") in ("HIGH", "MEDIUM")]

    def summary(self) -> Dict:
        return {
            "session_id": self.session_id,
            "total_writes": self._write_count,
            "blocked_writes": self._block_count,
            "high_risk": len(self.high_risk_writes()),
        }

    def to_artifact_section(self) -> Dict:
        return {
            "memory_guard_summary": self.summary(),
            "memory_guard_provenance": self._provenance,
            "memory_guard_high_risk": self.high_risk_writes(),
        }


def inspect_memory_write(content: str, session_id: str = "", category: str = None, mode: str = "block") -> MemoryWriteResult:
    guard = MemoryWriteGuard(session_id=session_id, mode=mode)
    args = {"content": content}
    if category:
        args["category"] = category
    return guard.before_tool_call("store_memory", args)
