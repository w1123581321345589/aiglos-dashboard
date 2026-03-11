"""
aiglos.scanner
Fast-path inline threat scanner.

Runs synchronously in <1 ms on every tool call.  No network, no subprocess,
no async -- pure rule evaluation.

Three-tier architecture matching the full proxy stack:
  BLOCK  -- definitive attack pattern, call is stopped immediately
  WARN   -- suspicious pattern, call proceeds, finding logged to session
  CLEAN  -- no signal, call proceeds unremarked

This is the entry-point security layer.  It covers the highest-frequency,
lowest-ambiguity attack patterns.  The semantic GIE (T6) runs async after
the call and catches goal-level drift.

Rule families:
  F1  Credential exfiltration       (read .env, .ssh, keychain calls)
  F2  Prompt injection in args      (ignore/override/system patterns)
  F3  Command injection             (shell metacharacters in tool args)
  F4  Path traversal                (../../ patterns, /etc/passwd etc)
  F5  SSRF                          (tool args containing internal URLs)
  F6  Data exfiltration URLs        (webhook / ngrok / suspicious TLDs)
  F7  Privilege escalation          (sudo, chmod 777, crontab writes)
  F8  Persistence mechanisms        (cron, launchctl, systemctl enable)
  F9  Overly broad file access      (/* globs, home directory sweeps)
  F10 Sensitive tool name patterns  (tool names that should not exist)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .config import AiglosConfig


class ScanVerdict(str, Enum):
    CLEAN = "clean"
    WARN  = "warn"
    BLOCK = "block"


@dataclass
class ScanResult:
    verdict: ScanVerdict
    risk_type: str
    reason: str
    rule_family: str
    matched_value: str = ""
    tool_name: str = ""
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "risk_type": self.risk_type,
            "reason": self.reason,
            "rule_family": self.rule_family,
            "matched_value": self.matched_value,
            "tool_name": self.tool_name,
            "latency_ms": round(self.latency_ms, 3),
        }


_CLEAN = ScanResult(
    verdict=ScanVerdict.CLEAN,
    risk_type="none",
    reason="",
    rule_family="none",
)

# ─── Rule tables ──────────────────────────────────────────────────────────────

# F1: Credential exfiltration -- argument VALUES that reference credential files
_F1_BLOCK = [
    r"\.env\b",
    r"\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)",
    r"/(etc/passwd|etc/shadow|etc/sudoers)",
    r"Library/Keychains",
    r"\.aws/(credentials|config)",
    r"\.netrc\b",
    r"\.pgpass\b",
    r"\.docker/config\.json",
    r"\.npmrc\b",
    r"\.pypirc\b",
    r"api[-_]?key[s]?\b",
    r"access[-_]?token\b",
    r"secret[-_]?key\b",
    r"private[-_]?key\b",
    r"client[-_]?secret\b",
    r"password[-_]?file\b",
    r"credentials?\.json",
    r"service[-_]?account.*\.json",
    r"auth[-_]?token",
    r"\.openclaw/",
    r"\.config/\w+/token",
]

# F2: Prompt injection in argument VALUES
_F2_BLOCK = [
    r"ignore\s+(previous|all|prior|your)\s+instructions?",
    r"disregard\s+(all|your|the|previous)\s+(rules?|instructions?|constraints?)",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"<\s*/?system\s*>",
    r"\[SYSTEM\]|\[INSTRUCTION\]|\[OVERRIDE\]",
    r"new\s+(directive|instruction|rule|override)\s*:",
    r"act\s+as\s+if\s+you\s+(have\s+no|are\s+without)",
    r"DAN\s+mode|jailbreak|unrestricted\s+mode",
    r"disregard\s+(?:\w+\s+){0,3}(rules?|instructions?|constraints?|guidelines?)",
]

# F3: Command injection in argument VALUES
_F3_BLOCK = [
    r"[;&|]\s*(rm|dd|mkfs|shutdown|reboot|halt|poweroff)\b",
    r"\$\([^)]{0,80}\)",    # command substitution $(...)
    r"`[^`]{0,80}`",        # backtick execution
    r"\|\s*(bash|sh|zsh|python3?|ruby|perl)\b",   # pipe to shell
    r"curl\s+.*\|\s*(bash|sh|zsh)",
    r"wget\s+.*-\s*\|",
    r"eval\s*\(",
    r"exec\s*\(\s*[\"']",
    r"os\.system\s*\(",
    r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True",
    r"__import__\s*\(",
]

# F4: Path traversal in argument VALUES
_F4_BLOCK = [
    r"\.\./\.\./",
    r"\.\.[/\\]\.\.[/\\]",
    r"%2e%2e[/\\]",          # URL-encoded ../
    r"\.\.%2f",
    r"[/\\]etc[/\\](passwd|shadow|sudoers|cron)",
    r"[/\\]proc[/\\]self",
    r"[/\\]sys[/\\]class",
]

# F5: SSRF -- internal metadata/cloud endpoints in argument VALUES
_F5_BLOCK = [
    r"169\.254\.169\.254",          # AWS/GCP/Azure metadata
    r"metadata\.google\.internal",
    r"fd00:|fe80:",                  # link-local IPv6
    r"127\.\d+\.\d+\.\d+(?!:80|:443|:18789)",  # localhost (non-standard ports)
    r"::1\b",
    r"0\.0\.0\.0",
]

# F6: Data exfiltration URLs in argument VALUES
_F6_BLOCK = [
    r"discord\.com/api/webhooks/",
    r"hooks\.slack\.com/services/",   # Slack incoming webhooks (legitimate ones go through proper OAuth)
    r"ngrok\.io|localhost\.run|serveo\.net",
    r"requestbin\.|webhook\.site",
    r"t\.me/\w+/sendMessage",        # Telegram bot
    r"https?://[a-z0-9\-]{3,}\.xyz/[a-z0-9]{8,}",  # random subdomain on .xyz
    r"pastebin\.com/(raw|api)",
]

# F7: Privilege escalation in argument VALUES
_F7_BLOCK = [
    r"\bsudo\s+(rm|chmod|chown|dd|bash|sh|python)",
    r"chmod\s+[0-7]*7[0-7]*\s+",    # chmod 777 / 755 etc
    r"chown\s+root",
    r"setuid|setgid",
    r"visudo",
    r"/etc/sudoers",
]

# F8: Persistence mechanisms in argument VALUES (BLOCK = system-wide; WARN = user-level)
_F8_BLOCK = [
    r"crontab\s+-[lei]",             # editing system crontab
    r"launchctl\s+load\s+/Library/LaunchDaemons",   # system-level daemon
    r"systemctl\s+enable\b",
    r"/etc/cron\.(d|daily|hourly|weekly|monthly)/",
    r"/etc/rc\.local",
    r"/etc/init\.d/",
    r"HKLM\\.*\\CurrentVersion\\Run",   # Windows registry run key
]

_F8_WARN = [
    r"launchctl\s+load\s+~/Library/LaunchAgents",   # user-level (suspicious but not always malicious)
    r"crontab\s+-e",
    r"~/\.bashrc|~/\.zshrc|~/\.profile",    # shell init modification
    r"~/.config/autostart",
]

# F9: Overly broad file access (WARN only -- agent may legitimately need to read dirs)
_F9_WARN = [
    r'["\']?\s*/\s*["\']?\s*(?:$|,|\))',     # literal "/" as path
    r"\*\*/\*",                               # ** glob
    r"~/\*",                                  # home dir wildcard
    r"/home/\*/",                             # all home dirs
    r"/Users/\*/",
]

# F10: Suspicious tool names that should not be callable
_F10_BLOCK_TOOL_NAMES = {
    "execute_system_command",
    "run_shell",
    "exec_code",
    "eval_python",
    "run_bash",
    "drop_table",
    "delete_all",
    "wipe_database",
    "format_drive",
}
_F10_WARN_TOOL_NAMES = {
    "write_file_raw",
    "overwrite_file",
    "bulk_delete",
    "mass_send",
    "send_to_all",
}


def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


class FastPathScanner:
    """
    Sub-millisecond synchronous scanner applied to every tool call.

    Scans both the tool_name and all string values in the arguments dict.
    Returns on first BLOCK hit.  Collects all WARN hits before returning.

    Target latency: <0.5ms on a modern laptop for typical tool call payloads.
    """

    def __init__(self, config: AiglosConfig | None = None):
        self.config = config or AiglosConfig.from_env()
        # Compile all rule families
        self._f1 = _compile(_F1_BLOCK)
        self._f2 = _compile(_F2_BLOCK)
        self._f3 = _compile(_F3_BLOCK)
        self._f4 = _compile(_F4_BLOCK)
        self._f5 = _compile(_F5_BLOCK)
        self._f6 = _compile(_F6_BLOCK)
        self._f7 = _compile(_F7_BLOCK)
        self._f8_block = _compile(_F8_BLOCK)
        self._f8_warn  = _compile(_F8_WARN)
        self._f9_warn  = _compile(_F9_WARN)

    def scan(self, tool_name: str, arguments: dict[str, Any]) -> ScanResult:
        t0 = time.perf_counter()

        # F10: tool name check (fastest -- no regex needed)
        tname_lower = tool_name.lower()
        if tname_lower in _F10_BLOCK_TOOL_NAMES:
            return self._result(ScanVerdict.BLOCK, "SUSPICIOUS_TOOL_NAME", "F10",
                                f"Blocked tool name: '{tool_name}'", tool_name, t0)
        if tname_lower in _F10_WARN_TOOL_NAMES:
            return self._result(ScanVerdict.WARN, "SUSPICIOUS_TOOL_NAME", "F10",
                                f"Suspicious tool name: '{tool_name}'", tool_name, t0)

        # Flatten argument values to strings for scanning
        values = _extract_strings(arguments)

        # Apply BLOCK rule families in priority order
        for family, patterns, risk_type in [
            ("F2", self._f2, "PROMPT_INJECTION"),
            ("F3", self._f3, "COMMAND_INJECTION"),
            ("F4", self._f4, "PATH_TRAVERSAL"),
            ("F1", self._f1, "CREDENTIAL_EXFILTRATION"),
            ("F7", self._f7, "PRIVILEGE_ESCALATION"),
            ("F8_BLOCK", self._f8_block, "PERSISTENCE"),
            ("F5", self._f5, "SSRF"),
            ("F6", self._f6, "DATA_EXFILTRATION"),
        ]:
            for val in values:
                for pattern in patterns:
                    m = pattern.search(val)
                    if m:
                        return self._result(
                            ScanVerdict.BLOCK, risk_type, family,
                            f"{risk_type} pattern in tool '{tool_name}' argument",
                            m.group(0)[:80], tool_name, t0,
                        )

        # Apply WARN rule families
        for family, patterns, risk_type in [
            ("F8_WARN", self._f8_warn, "PERSISTENCE"),
            ("F9",      self._f9_warn,  "BROAD_FILE_ACCESS"),
        ]:
            for val in values:
                for pattern in patterns:
                    m = pattern.search(val)
                    if m:
                        return self._result(
                            ScanVerdict.WARN, risk_type, family,
                            f"{risk_type} pattern in tool '{tool_name}' argument",
                            m.group(0)[:80], tool_name, t0,
                        )

        elapsed = (time.perf_counter() - t0) * 1000
        result = ScanResult(
            verdict=ScanVerdict.CLEAN,
            risk_type="none",
            reason="",
            rule_family="none",
            tool_name=tool_name,
            latency_ms=elapsed,
        )
        return result

    @staticmethod
    def _result(verdict: ScanVerdict, risk_type: str, family: str,
                reason: str, matched: str, tool_name: str = "",
                t0: float = 0.0) -> ScanResult:
        elapsed = (time.perf_counter() - t0) * 1000 if t0 else 0.0
        return ScanResult(
            verdict=verdict,
            risk_type=risk_type,
            reason=reason,
            rule_family=family,
            matched_value=matched,
            tool_name=tool_name,
            latency_ms=elapsed,
        )


def _extract_strings(obj: Any, _depth: int = 0) -> list[str]:
    """Recursively extract all string values from a JSON-like structure."""
    if _depth > 8:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_extract_strings(v, _depth + 1))
        return out
    if isinstance(obj, (list, tuple)):
        out = []
        for v in obj:
            out.extend(_extract_strings(v, _depth + 1))
        return out
    return []
