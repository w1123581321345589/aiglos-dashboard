"""
aiglos.integrations.subprocess_intercept
==========================================
CLI and subprocess execution monitoring layer.

Wraps Python's subprocess module and os.system at attach time. Every shell
command or child process spawned by the agent passes through threat inspection
and tier classification before execution.

Three-tier blast radius system:
  Tier 1  AUTONOMOUS   -- read-only ops, git status/log/diff, linters
                          Action: auto-allow, log only
  Tier 2  MONITORED    -- file writes, git commits, pip/npm installs
                          Action: allow + log compensating transaction
  Tier 3  GATED        -- rm -rf, DROP TABLE, terraform destroy, kubectl delete,
                          git push --force, destructive command pairs
                          Action: configurable -- block | pause | warn

Threat families inspected:
  T07  SHELL_INJECT         -- metacharacters / command substitution in args
  T08  PATH_TRAVERSAL       -- ../  sequences in file path arguments
  T10  PRIV_ESC             -- sudo/su/doas / setuid binary execution
  T11  PERSISTENCE          -- crontab / launchd / systemd modifications
  T12  LATERAL_MOVEMENT     -- SSH spawning to non-declared hosts / network scans
  T19  CRED_HARVEST         -- commands that read credential files
  T21  ENV_LEAK             -- env dump piped to external destination
  T23  EXFIL_SUBPROCESS     -- curl/wget/nc with data arguments to external hosts
  T_DEST                    -- destructive command sequences (Kiro pattern)

Modes (set via subprocess_tier3_mode in aiglos.attach()):
  "block"  -- hard block Tier 3, raise AiglosBlockedSubprocess (default: federal)
  "pause"  -- block + emit webhook, resume on signed approval token (default: Pro)
  "warn"   -- log and allow (default: free tier)

Usage:
    aiglos.attach(
        agent_name="devops-agent",
        api_key=KEY,
        intercept_subprocess=True,
        subprocess_tier3_mode="pause",
        tier3_approval_webhook="https://hooks.pagerduty.com/...",
    )
"""

from __future__ import annotations

import functools
import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, List, Optional, Sequence, Union

log = logging.getLogger("aiglos.subprocess_intercept")

_LOCK    = threading.Lock()
_PATCHED: set[str] = set()

# How long to wait for external approval before timing out (seconds)
APPROVAL_TIMEOUT = int(os.environ.get("AIGLOS_APPROVAL_TIMEOUT", "300"))


# ── Result types ──────────────────────────────────────────────────────────────

class SubprocVerdict(str, Enum):
    ALLOW = "ALLOW"
    WARN  = "WARN"
    BLOCK = "BLOCK"
    PAUSE = "PAUSE"   # blocked pending external approval


class SubprocTier(int, Enum):
    AUTONOMOUS = 1
    MONITORED  = 2
    GATED      = 3


@dataclass
class SubprocScanResult:
    verdict:     SubprocVerdict
    tier:        SubprocTier
    rule_id:     str
    rule_name:   str
    reason:      str
    cmd:         str        = ""
    matched_val: str        = ""
    latency_ms:  float      = 0.0
    timestamp:   float      = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "type":       "subprocess",
            "verdict":    self.verdict.value,
            "tier":       self.tier.value,
            "rule_id":    self.rule_id,
            "rule_name":  self.rule_name,
            "reason":     self.reason,
            "cmd":        self.cmd[:256],
            "latency_ms": round(self.latency_ms, 3),
        }


class AiglosBlockedSubprocess(RuntimeError):
    """Raised when Aiglos blocks a subprocess call."""
    def __init__(self, result: SubprocScanResult):
        self.result = result
        super().__init__(
            f"[Aiglos] Subprocess blocked: {result.reason} "
            f"[{result.rule_id}] cmd='{result.cmd[:80]}'"
        )


class AiglосPauseTimeout(RuntimeError):
    """Raised when pause mode times out waiting for approval."""
    def __init__(self, cmd: str, timeout: int):
        self.cmd = cmd
        self.timeout = timeout
        super().__init__(
            f"[Aiglos] Subprocess approval timed out after {timeout}s: '{cmd[:80]}'"
        )


# ── Tier 1: auto-allow patterns ───────────────────────────────────────────────

_TIER1_ALLOW = re.compile(
    r"^("
    # read-only filesystem
    r"cat\s|head\s|tail\s|less\s|more\s|wc\s|file\s|stat\s|du\s|df\s"
    r"|find\s.*-name|ls(\s|$)|echo(\s|$)|pwd(\s|$)|date(\s|$)|whoami(\s|$)"
    r"|uname\s|env(\s|$)|printenv(\s|$)|which\s|type\s|test\s"
    # git read-only
    r"|git\s+(status|log|diff|show|branch|tag|describe|shortlog|stash\s+list"
    r"|remote\s+-v|fetch\s+--dry-run|ls-files|blame|config\s+--list)"
    # linters / test reporters (no side effects)
    r"|python\s+-m\s+(pytest\s+.*-v|flake8|mypy|black\s+--check|isort\s+--check)"
    r"|pylint\s|eslint\s.*--fix-dry-run"
    # package listing (not installing)
    r"|pip\s+(list|show|check|freeze)(\s|$)"
    r"|npm\s+(list|outdated|audit\s+--audit-level)(\s|$)"
    r")",
    re.IGNORECASE,
)


# ── Tier 3: destructive / gated patterns ─────────────────────────────────────

_TIER3_DESTRUCTIVE = re.compile(
    r"("
    # filesystem destruction
    r"rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\s"
    r"|rm\s+-rf\s|rmdir\s+--ignore"
    r"|shred\s|wipe\s|dd\s+if=/dev/zero"
    # database destruction
    r"|DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\s"
    r"|TRUNCATE\s+(TABLE\s)?"
    r"|DELETE\s+FROM\s+\w+\s*;"
    # infrastructure destruction
    r"|terraform\s+(destroy|taint)"
    r"|kubectl\s+delete\s+(namespace|ns|pod|deployment|service|all)"
    r"|helm\s+delete\s|helm\s+uninstall\s"
    r"|aws\s+(ec2|rds|s3)\s+delete\s"
    r"|gcloud\s+.*\s+delete\s"
    # git force operations
    r"|git\s+(push\s+.*--force|reset\s+--hard|clean\s+-[a-z]*f)"
    r"|git\s+push\s+-f\s"
    # privilege operations always tier 3
    r"|sudo\s+rm\s|sudo\s+dd\s|sudo\s+mkfs"
    r")",
    re.IGNORECASE,
)


# ── Threat rule tables ────────────────────────────────────────────────────────

_T07_SHELL_INJECT = re.compile(
    r"("
    r"\$\([^)]{1,80}\)"           # command substitution
    r"|`[^`]{1,80}`"              # backtick substitution
    r"|[;&|]\s*(rm|dd|mkfs|wget|curl)\b"
    r"|>\s*/etc/"                 # redirect into /etc
    r"|\|\s*(bash|sh|zsh|dash)\b"
    r")",
    re.IGNORECASE,
)

_T08_PATH_TRAVERSAL = re.compile(
    r"(\.\./){2,}",
)

_T10_PRIV_ESC = re.compile(
    r"^(sudo|su\s|doas\s|pkexec\s)",
    re.IGNORECASE,
)

_T10_PRIV_ESC_INLINE = re.compile(
    r"\b(sudo|pkexec)\s+",
    re.IGNORECASE,
)

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

_T21_ENV_LEAK = re.compile(
    r"(env|printenv|export)\s*[|>]",
    re.IGNORECASE,
)

_T23_EXFIL_SUBPROCESS = re.compile(
    r"("
    r"curl\s+.*-d\s.*(http|https)://"
    r"|wget\s+.*--post-(data|file)"
    r"|nc\s+\S+\s+\d+\s*<"
    r")",
    re.IGNORECASE,
)


# ── Command normalizer ────────────────────────────────────────────────────────

def _cmd_to_str(args: Union[str, Sequence, None]) -> str:
    """Normalize subprocess args to a single inspectable string."""
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    try:
        return " ".join(str(a) for a in args)
    except Exception:
        return str(args)


# ── Tier classifier ───────────────────────────────────────────────────────────

def classify_tier(cmd_str: str) -> SubprocTier:
    """Return the blast radius tier for a command string."""
    if _TIER3_DESTRUCTIVE.search(cmd_str):
        return SubprocTier.GATED
    if _TIER1_ALLOW.match(cmd_str.strip()):
        return SubprocTier.AUTONOMOUS
    return SubprocTier.MONITORED


# ── Compensating transaction generator ───────────────────────────────────────

def compensating_transaction(cmd_str: str) -> Optional[str]:
    """
    Return a best-effort compensating command for a Tier 2 operation.
    Used for rollback suggestions in the session artifact.
    """
    # git commit -> git revert HEAD
    if re.search(r"git\s+commit\b", cmd_str):
        return "git revert HEAD --no-edit"
    # file write -> note backup path
    if re.search(r"\b(cp|mv|touch|tee|cat\s*>)\b", cmd_str):
        return "# Restore from backup before this operation"
    # pip install -> pip uninstall
    m = re.search(r"pip\s+install\s+([\w\-]+)", cmd_str)
    if m:
        return f"pip uninstall -y {m.group(1)}"
    # npm install -> npm uninstall
    m = re.search(r"npm\s+install\s+([\w\-@/]+)", cmd_str)
    if m:
        return f"npm uninstall {m.group(1)}"
    return None


# ── Core inspection logic ─────────────────────────────────────────────────────

def inspect_subprocess(
    args: Union[str, Sequence, None],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    mode: str = "block",
    tier3_mode: str = "warn",
) -> SubprocScanResult:
    """
    Inspect a subprocess call against all applicable threat families.

    Parameters
    ----------
    args       : Command and arguments (string or list)
    cwd        : Working directory (informational)
    env        : Environment (checked for leaks)
    mode       : Overall Aiglos mode: "block" | "warn" | "audit"
    tier3_mode : How to handle Tier 3: "block" | "pause" | "warn"

    Returns
    -------
    SubprocScanResult with verdict ALLOW | WARN | BLOCK | PAUSE
    """
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
            verdict=verdict,
            tier=t,
            rule_id=rule_id,
            rule_name=rule_name,
            reason=reason,
            cmd=cmd_str,
            matched_val=matched[:120],
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    # T07: Shell injection (always Tier 3 -- attacker-controlled execution)
    m = _T07_SHELL_INJECT.search(cmd_str)
    if m:
        return _result("T07", "SHELL_INJECT",
                       "Shell metacharacter / command substitution in argument",
                       m.group(), force_tier=SubprocTier.GATED)

    # T08: Path traversal
    m = _T08_PATH_TRAVERSAL.search(cmd_str)
    if m:
        return _result("T08", "PATH_TRAVERSAL",
                       "Directory traversal sequence in command argument", m.group())

    # T10: Privilege escalation
    if _T10_PRIV_ESC.search(cmd_str) or _T10_PRIV_ESC_INLINE.search(cmd_str):
        return _result("T10", "PRIV_ESC",
                       "Privilege escalation command detected",
                       force_tier=SubprocTier.GATED)

    # T11: Persistence mechanisms
    m = _T11_PERSISTENCE.search(cmd_str)
    if m:
        return _result("T11", "PERSISTENCE",
                       f"Persistence mechanism: {m.group()}",
                       m.group(), force_tier=SubprocTier.GATED)

    # T12: Lateral movement
    m = _T12_LATERAL.search(cmd_str)
    if m:
        return _result("T12", "LATERAL_MOVEMENT",
                       f"Lateral movement: {m.group()}", m.group())

    # T19: Credential harvest via command
    m = _T19_CRED_HARVEST_CMD.search(cmd_str)
    if m:
        return _result("T19", "CRED_HARVEST",
                       f"Command reads credential file: {m.group()}", m.group())

    # T21: Environment leak
    m = _T21_ENV_LEAK.search(cmd_str)
    if m:
        return _result("T21", "ENV_LEAK",
                       "Environment dump piped or redirected to external destination",
                       m.group())

    # T23: Exfil via subprocess
    m = _T23_EXFIL_SUBPROCESS.search(cmd_str)
    if m:
        return _result("T23", "EXFIL_SUBPROCESS",
                       f"Data exfiltration via subprocess call: {m.group()}", m.group())

    # Tier 3 destructive (detected by classify_tier above, no specific threat rule match)
    if tier == SubprocTier.GATED:
        return _result("T_DEST", "DESTRUCTIVE",
                       f"Destructive command requires approval: {cmd_str[:80]}")

    # Tier 1: auto-allow
    if tier == SubprocTier.AUTONOMOUS:
        latency = (time.monotonic() - t0) * 1000
        return SubprocScanResult(
            verdict=SubprocVerdict.ALLOW,
            tier=SubprocTier.AUTONOMOUS,
            rule_id="none",
            rule_name="none",
            reason="",
            cmd=cmd_str,
            latency_ms=latency,
        )

    # Tier 2: monitored, allow with log
    latency = (time.monotonic() - t0) * 1000
    compensating = compensating_transaction(cmd_str)
    r = SubprocScanResult(
        verdict=SubprocVerdict.ALLOW,
        tier=SubprocTier.MONITORED,
        rule_id="T2_MONITORED",
        rule_name="MONITORED",
        reason=f"Tier 2 monitored operation. Compensating: {compensating}" if compensating else "Tier 2 monitored operation.",
        cmd=cmd_str,
        latency_ms=latency,
    )
    return r


# ── Webhook approval for pause mode ──────────────────────────────────────────

def _emit_approval_request(cmd_str: str, result: SubprocScanResult,
                            webhook_url: str, session_events: list) -> bool:
    """
    POST an approval request to the configured webhook.
    Returns True if approval is received within APPROVAL_TIMEOUT seconds.
    In this initial implementation: emits the webhook and returns False
    (treated as block) so the operation does not proceed without explicit
    external integration. PagerDuty/Slack/ServiceNow integrations in v0.4.0.
    """
    payload = json.dumps({
        "aiglos_event": "tier3_approval_request",
        "cmd":          cmd_str[:256],
        "rule_id":      result.rule_id,
        "rule_name":    result.rule_name,
        "reason":       result.reason,
        "timestamp":    time.time(),
    }).encode()

    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
        log.warning("[Aiglos PAUSE] Approval request sent to webhook: %s", webhook_url)
    except Exception as e:
        log.warning("[Aiglos PAUSE] Webhook delivery failed: %s", e)

    # v0.4.0 will poll for a signed approval token; for now treat as block
    return False


# ── Subprocess wrapper factory ────────────────────────────────────────────────

def _make_popen_class(original_popen_cls,
                      mode: str,
                      tier3_mode: str,
                      approval_webhook: Optional[str],
                      session_events: list):
    """Return a patched Popen subclass that inspects before __init__."""

    class AiglosPopen(original_popen_cls):
        def __init__(self_inner, args, **kwargs):
            result = inspect_subprocess(
                args=args,
                cwd=kwargs.get("cwd"),
                env=kwargs.get("env"),
                mode=mode,
                tier3_mode=tier3_mode,
            )
            session_events.append(result.to_dict())

            if result.verdict == SubprocVerdict.BLOCK:
                log.warning("[Aiglos BLOCK SUBPROCESS] %s: %s",
                            result.cmd[:60], result.reason)
                raise AiglosBlockedSubprocess(result)

            if result.verdict == SubprocVerdict.PAUSE:
                log.warning("[Aiglos PAUSE SUBPROCESS] %s: %s",
                            result.cmd[:60], result.reason)
                if approval_webhook:
                    approved = _emit_approval_request(
                        result.cmd, result, approval_webhook, session_events)
                    if not approved:
                        raise AiglosBlockedSubprocess(result)
                else:
                    raise AiglosBlockedSubprocess(result)

            if result.verdict == SubprocVerdict.WARN:
                log.warning("[Aiglos WARN SUBPROCESS] %s: %s",
                            result.cmd[:60], result.reason)

            if result.tier == SubprocTier.MONITORED:
                comp = compensating_transaction(_cmd_to_str(args))
                if comp:
                    log.info("[Aiglos T2] Compensating transaction: %s", comp)

            super().__init__(args, **kwargs)

    AiglosPopen.__name__ = "AiglosPopen"
    return AiglosPopen


# ── Session event log ─────────────────────────────────────────────────────────

_session_events: list = []


# ── Public attach API ─────────────────────────────────────────────────────────

def attach_subprocess_intercept(
    mode: str = "block",
    tier3_mode: str = "warn",
    approval_webhook: Optional[str] = None,
) -> dict[str, bool]:
    """
    Patch subprocess module and os.system in the current process.

    Parameters
    ----------
    mode              : "block" | "warn" | "audit"
    tier3_mode        : "block" | "pause" | "warn"  for Tier 3 commands
    approval_webhook  : URL to POST Tier 3 approval requests (pause mode)

    Returns
    -------
    dict mapping target_name -> successfully_patched
    """
    global _session_events
    results: dict[str, bool] = {}

    with _LOCK:
        if "subprocess.Popen" not in _PATCHED:
            try:
                orig_popen = subprocess.Popen
                patched_cls = _make_popen_class(
                    orig_popen, mode, tier3_mode, approval_webhook, _session_events)
                subprocess.Popen          = patched_cls
                subprocess.run            = _make_run_wrapper(patched_cls)
                subprocess.call           = _make_call_wrapper(patched_cls)
                subprocess.check_call     = _make_check_call_wrapper(patched_cls)
                subprocess.check_output   = _make_check_output_wrapper(patched_cls)
                _PATCHED.add("subprocess.Popen")
                results["subprocess"] = True
                log.info("[Aiglos] Patched subprocess module (Popen + run/call/check_*)")
            except Exception as e:
                results["subprocess"] = False
                log.warning("[Aiglos] Could not patch subprocess: %s", e)
        else:
            results["subprocess"] = True

        if "os.system" not in _PATCHED:
            try:
                orig_os_system = os.system

                @functools.wraps(orig_os_system)
                def _aiglos_os_system(cmd):
                    result = inspect_subprocess(
                        args=cmd,
                        mode=mode,
                        tier3_mode=tier3_mode,
                    )
                    _session_events.append(result.to_dict())
                    if result.verdict == SubprocVerdict.BLOCK:
                        log.warning("[Aiglos BLOCK os.system] %s", cmd[:80])
                        raise AiglosBlockedSubprocess(result)
                    if result.verdict == SubprocVerdict.PAUSE:
                        if approval_webhook:
                            _emit_approval_request(cmd, result, approval_webhook, _session_events)
                        raise AiglosBlockedSubprocess(result)
                    if result.verdict == SubprocVerdict.WARN:
                        log.warning("[Aiglos WARN os.system] %s", cmd[:80])
                    return orig_os_system(cmd)

                os.system = _aiglos_os_system
                _PATCHED.add("os.system")
                results["os.system"] = True
                log.info("[Aiglos] Patched os.system")
            except Exception as e:
                results["os.system"] = False
                log.warning("[Aiglos] Could not patch os.system: %s", e)
        else:
            results["os.system"] = True

    return results


# ── Convenience wrappers for subprocess.run / call / check_* ─────────────────

def _make_run_wrapper(patched_popen):
    """Re-implement subprocess.run using patched Popen."""
    def _run(args, *, stdin=None, input=None, capture_output=False,
             timeout=None, check=False, **kwargs):
        if capture_output:
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.PIPE
        if input is not None:
            kwargs["stdin"] = subprocess.PIPE
        with patched_popen(args, stdin=stdin, **kwargs) as proc:
            try:
                stdout, stderr = proc.communicate(input=input, timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise
            except Exception:
                proc.kill()
                raise
            rc = proc.poll()
            if check and rc:
                raise subprocess.CalledProcessError(rc, args, stdout, stderr)
            return subprocess.CompletedProcess(args, rc, stdout, stderr)
    return _run


def _make_call_wrapper(patched_popen):
    def _call(args, **kwargs):
        with patched_popen(args, **kwargs) as p:
            return p.wait()
    return _call


def _make_check_call_wrapper(patched_popen):
    def _check_call(args, **kwargs):
        rc = _make_call_wrapper(patched_popen)(args, **kwargs)
        if rc:
            raise subprocess.CalledProcessError(rc, args)
        return 0
    return _check_call


def _make_check_output_wrapper(patched_popen):
    def _check_output(args, **kwargs):
        kwargs["stdout"] = subprocess.PIPE
        kwargs.setdefault("stderr", subprocess.PIPE)
        with patched_popen(args, **kwargs) as p:
            stdout, _ = p.communicate()
            if p.returncode:
                raise subprocess.CalledProcessError(p.returncode, args, stdout)
            return stdout
    return _check_output


def get_session_subprocess_events() -> list:
    """Return all subprocess events recorded in this session."""
    return list(_session_events)


def clear_session_subprocess_events() -> None:
    """Reset subprocess event log (called at session close)."""
    global _session_events
    _session_events.clear()


def subprocess_intercept_status() -> dict:
    return {
        "patched_targets":  list(_PATCHED),
        "events_recorded":  len(_session_events),
    }
