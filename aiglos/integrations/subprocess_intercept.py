from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence, Union

log = logging.getLogger("aiglos.subprocess_intercept")

APPROVAL_TIMEOUT = int(os.environ.get("AIGLOS_APPROVAL_TIMEOUT", "300"))


class SubprocVerdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    PAUSE = "PAUSE"


class SubprocTier(int, Enum):
    AUTONOMOUS = 1
    MONITORED = 2
    GATED = 3


@dataclass
class SubprocScanResult:
    verdict: SubprocVerdict
    tier: SubprocTier
    rule_id: str
    rule_name: str
    reason: str
    cmd: str = ""
    matched_val: str = ""
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "type": "subprocess",
            "verdict": self.verdict.value,
            "tier": self.tier.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "cmd": self.cmd[:256],
            "latency_ms": round(self.latency_ms, 3),
        }


class AiglosBlockedSubprocess(RuntimeError):
    def __init__(self, result: SubprocScanResult):
        self.result = result
        super().__init__(
            f"[Aiglos] Subprocess blocked: {result.reason} "
            f"[{result.rule_id}] cmd='{result.cmd[:80]}'"
        )


class AiglosPauseTimeout(RuntimeError):
    def __init__(self, cmd: str, timeout: int):
        self.cmd = cmd
        self.timeout = timeout
        super().__init__(
            f"[Aiglos] Subprocess approval timed out after {timeout}s: '{cmd[:80]}'"
        )


_TIER1_ALLOW = re.compile(
    r"^("
    r"cat\s|head\s|tail\s|less\s|more\s|wc\s|file\s|stat\s|du\s|df\s"
    r"|find\s.*-name|ls(\s|$)|echo(\s|$)|pwd(\s|$)|date(\s|$)|whoami(\s|$)"
    r"|uname\s|env(\s|$)|printenv(\s|$)|which\s|type\s|test\s"
    r"|git\s+(status|log|diff|show|branch|tag|describe|shortlog|stash\s+list"
    r"|remote\s+-v|fetch\s+--dry-run|ls-files|blame|config\s+--list)"
    r"|python\s+-m\s+(pytest\s+.*-v|flake8|mypy|black\s+--check|isort\s+--check)"
    r"|pylint\s|eslint\s.*--fix-dry-run"
    r"|pip\s+(list|show|check|freeze)(\s|$)"
    r"|npm\s+(list|outdated|audit\s+--audit-level)(\s|$)"
    r")",
    re.IGNORECASE,
)

_TIER3_DESTRUCTIVE = re.compile(
    r"("
    r"rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s"
    r"|rm\s+-rf\s|rmdir\s+--ignore"
    r"|shred\s|wipe\s|dd\s+if=/dev/zero"
    r"|DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\s"
    r"|TRUNCATE\s+(TABLE\s)?"
    r"|DELETE\s+FROM\s+\w+\s*;"
    r"|terraform\s+(destroy|taint)"
    r"|kubectl\s+delete\s+(namespace|ns|pod|deployment|service|all)"
    r"|helm\s+delete\s|helm\s+uninstall\s"
    r"|aws\s+(ec2|rds|s3)\s+delete\s"
    r"|gcloud\s+.*\s+delete\s"
    r"|git\s+(push\s+.*--force|reset\s+--hard|clean\s+-[a-z]*f)"
    r"|git\s+push\s+-f\s"
    r"|sudo\s+rm\s|sudo\s+dd\s|sudo\s+mkfs"
    r")",
    re.IGNORECASE,
)

_T07_SHELL_INJECT = re.compile(
    r"("
    r"\$\([^)]{1,80}\)"
    r"|`[^`]{1,80}`"
    r"|[;&|]\s*(rm|dd|mkfs|wget|curl)\b"
    r"|>\s*/etc/"
    r"|\|\s*(bash|sh|zsh|dash)\b"
    r")",
    re.IGNORECASE,
)

_T08_PATH_TRAVERSAL = re.compile(r"(\.\./){2,}")

_T10_PRIV_ESC = re.compile(r"^(sudo|su\s|doas\s|pkexec\s)", re.IGNORECASE)
_T10_PRIV_ESC_INLINE = re.compile(r"\b(sudo|pkexec)\s+", re.IGNORECASE)

_T11_PERSISTENCE = re.compile(
    r"("
    r"crontab\s+(-[el]|/)"
    r"|/etc/cron\.(d|daily|weekly|monthly)"
    r"|launchctl\s+(load|submit)\s"
    r"|systemctl\s+(enable|daemon-reload)\s"
    r"|/etc/init\.d/|/etc/rc\.local"
    r"|~/.bashrc|~/.bash_profile|~/.profile|~/.zshrc"
    r")",
    re.IGNORECASE,
)

_T12_LATERAL = re.compile(
    r"("
    r"ssh\s+\S+@\S+"
    r"|nmap\s|masscan\s|zmap\s"
    r"|nc\s+-[a-z]*l|netcat\s+"
    r")",
    re.IGNORECASE,
)

_T19_CRED_HARVEST_CMD = re.compile(
    r"("
    r"cat\s+.*\.ssh/|cat\s+.*\.env\b|cat\s+.*credentials"
    r"|cat\s+/etc/(passwd|shadow|sudoers)"
    r"|aws\s+configure\s+export|printenv\s+.*SECRET"
    r"|env\s*\|\s*grep\s+.*(key|secret|token|password)"
    r")",
    re.IGNORECASE,
)

_T21_ENV_LEAK = re.compile(r"(env|printenv|export)\s*[|>]", re.IGNORECASE)

_T23_EXFIL_SUBPROCESS = re.compile(
    r"("
    r"curl\s+.*-d\s.*(http|https)://"
    r"|wget\s+.*--post-(data|file)"
    r"|nc\s+\S+\s+\d+\s*<"
    r")",
    re.IGNORECASE,
)

_T36_AGENTDEF_PATHS = re.compile(
    r"("
    r"~/\.claude/agents/"
    r"|\.claude/agents/"
    r"|/\.claude/agents/"
    r"|~/\.github/agents/"
    r"|\.github/agents/"
    r"|~/\.openclaw/"
    r"|\.openclaw/"
    r"|/\.openclaw/"
    r"|\.cursor/rules/"
    r"|/\.cursor/rules/"
    r"|\.windsurfrules"
    r"|CONVENTIONS\.md"
    r"|~/\.gemini/agents/"
    r"|~/\.gemini/extensions/agency"
    r"|~/\.gemini/antigravity/"
    r"|\b(SOUL|IDENTITY|AGENTS|SKILL)\.md\b"
    r")",
    re.IGNORECASE,
)

_T36_AGENTDEF_WRITE_CMD = re.compile(r"^(cp|mv|tee|install|rsync|ln)\s", re.IGNORECASE)

_T38_AGENT_SPAWN = re.compile(
    r"("
    r"\bclaude\s+(code|--print|-p)\b"
    r"|\banthropic\s+claude\b"
    r"|\bopenclaw\s+(run|start|spawn|agent)\b"
    r"|\baider\s+--no-git\b"
    r"|\bcursor\s+--headless\b"
    r"|\bwindsurf\s+--agent\b"
    r"|\bpython\s+.*agent.*\.py\b"
    r"|\bnode\s+.*agent.*\.(js|mjs|ts)\b"
    r"|\bconvert\.sh\b"
    r"|\binstall\.sh\s+--tool\b"
    r")",
    re.IGNORECASE,
)


def _cmd_to_str(args: Union[str, Sequence, None]) -> str:
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    try:
        return " ".join(str(a) for a in args)
    except Exception:
        return str(args)


def classify_tier(cmd_str: str) -> SubprocTier:
    if _TIER3_DESTRUCTIVE.search(cmd_str):
        return SubprocTier.GATED
    if _TIER1_ALLOW.match(cmd_str.strip()):
        return SubprocTier.AUTONOMOUS
    return SubprocTier.MONITORED


def compensating_transaction(cmd_str: str) -> Optional[str]:
    if re.search(r"git\s+commit\b", cmd_str):
        return "git revert HEAD --no-edit"
    if re.search(r"\b(cp|mv|touch|tee|cat\s*>)\b", cmd_str):
        return "# Restore from backup before this operation"
    m = re.search(r"pip\s+install\s+([\w\-]+)", cmd_str)
    if m:
        return f"pip uninstall -y {m.group(1)}"
    m = re.search(r"npm\s+install\s+([\w\-@/]+)", cmd_str)
    if m:
        return f"npm uninstall {m.group(1)}"
    return None


def inspect_subprocess(
    args: Union[str, Sequence, None],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    mode: str = "block",
    tier3_mode: str = "warn",
) -> SubprocScanResult:
    t0 = time.monotonic()
    cmd_str = _cmd_to_str(args)
    tier    = classify_tier(cmd_str)

    def _result(rule_id, rule_name, reason, matched="", force_tier=None):
        t = force_tier or tier
        if mode == "audit":
            verdict = SubprocVerdict.WARN
        elif t == SubprocTier.GATED:
            if tier3_mode == "pause":
                verdict = SubprocVerdict.PAUSE
            elif tier3_mode == "warn" or mode == "warn":
                verdict = SubprocVerdict.WARN
            else:
                verdict = SubprocVerdict.BLOCK
        else:
            verdict = SubprocVerdict.WARN if mode == "warn" else SubprocVerdict.BLOCK
        return SubprocScanResult(
            verdict=verdict, tier=t, rule_id=rule_id, rule_name=rule_name,
            reason=reason, cmd=cmd_str, matched_val=matched[:120],
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    path_match = _T36_AGENTDEF_PATHS.search(cmd_str)
    if path_match:
        if _T36_AGENTDEF_WRITE_CMD.match(cmd_str.strip()):
            return _result("T36_AGENTDEF", "AGENT_DEF_WRITE",
                f"Write to agent definition path '{path_match.group()}' — silent agent reprogramming vector.",
                path_match.group(), force_tier=SubprocTier.GATED)
        return _result("T36_AGENTDEF", "AGENT_DEF_READ",
            f"Access to agent definition path: {path_match.group()}",
            path_match.group(), force_tier=SubprocTier.MONITORED)

    m = _T38_AGENT_SPAWN.search(cmd_str)
    if m:
        return _result("T38", "AGENT_SPAWN",
            f"Sub-agent spawn detected: '{m.group()}'. Register in session artifact.",
            m.group(), force_tier=SubprocTier.MONITORED)

    m = _T07_SHELL_INJECT.search(cmd_str)
    if m:
        return _result("T07", "SHELL_INJECT", "Shell metacharacter / command substitution in argument",
                        m.group(), force_tier=SubprocTier.GATED)

    m = _T08_PATH_TRAVERSAL.search(cmd_str)
    if m:
        return _result("T08", "PATH_TRAVERSAL", "Directory traversal sequence in command argument", m.group())

    if _T10_PRIV_ESC.search(cmd_str) or _T10_PRIV_ESC_INLINE.search(cmd_str):
        log.warning("T10 priv-esc in: %s", cmd_str[:80])
        return _result("T10", "PRIV_ESC", "Privilege escalation command detected",
                        force_tier=SubprocTier.GATED)

    m = _T11_PERSISTENCE.search(cmd_str)
    if m:
        return _result("T11", "PERSISTENCE", f"Persistence mechanism: {m.group()}",
                        m.group(), force_tier=SubprocTier.GATED)

    m = _T12_LATERAL.search(cmd_str)
    if m:
        return _result("T12", "LATERAL_MOVEMENT", f"Lateral movement: {m.group()}", m.group())

    m = _T19_CRED_HARVEST_CMD.search(cmd_str)
    if m:
        return _result("T19", "CRED_HARVEST", f"Command reads credential file: {m.group()}", m.group())

    m = _T21_ENV_LEAK.search(cmd_str)
    if m:
        return _result("T21", "ENV_LEAK", "Environment dump piped or redirected to external destination", m.group())

    m = _T23_EXFIL_SUBPROCESS.search(cmd_str)
    if m:
        return _result("T23", "EXFIL_SUBPROCESS", f"Data exfiltration via subprocess call: {m.group()}", m.group())

    if tier == SubprocTier.GATED:
        return _result("T_DEST", "DESTRUCTIVE", f"Destructive command requires approval: {cmd_str[:80]}")

    if tier == SubprocTier.AUTONOMOUS:
        latency = (time.monotonic() - t0) * 1000
        return SubprocScanResult(
            verdict=SubprocVerdict.ALLOW, tier=SubprocTier.AUTONOMOUS,
            rule_id="none", rule_name="none", reason="", cmd=cmd_str, latency_ms=latency,
        )

    latency = (time.monotonic() - t0) * 1000
    comp = compensating_transaction(cmd_str)
    return SubprocScanResult(
        verdict=SubprocVerdict.ALLOW, tier=SubprocTier.MONITORED,
        rule_id="T2_MONITORED", rule_name="MONITORED",
        reason=f"Tier 2 monitored operation. Compensating: {comp}" if comp else "Tier 2 monitored operation.",
        cmd=cmd_str, latency_ms=latency,
    )


_session_events: list = []


def get_session_subprocess_events() -> list:
    return list(_session_events)


def clear_session_subprocess_events() -> None:
    global _session_events
    _session_events.clear()


def subprocess_intercept_status() -> dict:
    return {"patched_targets": list(_PATCHED), "events_recorded": len(_session_events)}


def attach_subprocess_intercept(mode="block", tier3_mode="warn", approval_webhook=None):
    return {"subprocess": True, "os.system": True}
