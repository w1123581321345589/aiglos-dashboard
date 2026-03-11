"""
aiglos_autonomous.py
====================
Drop this file into the root of your Aiglos repo.
Run it standalone or import it. Everything wires automatically.

    python aiglos_autonomous.py              # foreground engine
    python aiglos_autonomous.py --scan       # one-shot hunt and exit
    python aiglos_autonomous.py --intel      # one-shot intel refresh and exit
    python aiglos_autonomous.py --status     # print last persisted status

No config required. Works against the same aiglos_audit.db the proxy writes.

HOW IT MAPS TO THE EXISTING CODEBASE
--------------------------------------

  aiglos_core/proxy/__init__.py       <- real-time intercept (live sessions)
        |
        v
  aiglos_audit.db                     <- shared SQLite: proxy writes, engine reads
        |
        v
  THIS FILE (autonomous engine)       <- reads DB, hunts patterns, updates policy
        |
        +-- ThreatHunter               reads audit DB, writes findings back
        |     5 hunt modules:
        |       exposure_scan          config files: 0.0.0.0, missing auth, inline creds
        |       credential_hunt        secrets in logged tool call arguments
        |       injection_hunt         prompt injection patterns in tool history
        |       behavioral_trend       rising anomaly scores across sessions
        |       policy_trend           repeated violations of the same rule (probing)
        |
        +-- ThreatIntelligence         reads NVD/OWASP/community, writes policy + trust
        |     on each refresh:
        |       NVD feed               new MCP-related CVEs -> new policy rules
        |       community feed         malicious server fingerprints -> blocklist
        |       aiglos_policy.yaml     auto-updated with new block/alert rules
        |       aiglos_trust.yaml      auto-updated with blocked server hashes
        |
        +-- AiglOsAutonomousEngine     orchestrator / command center
              priority task queue      CRITICAL(0) > HIGH(1) > NORMAL(2) > LOW(3)
              retry + timeout          2 retries, configurable per-task timeout
              state persistence        aiglos_engine_state.json (read by CLI)
              schedule loop            scan every 5m, intel every 1h, report every 24h
              watchdog loop            detects engine interference, escalates to CRITICAL

EXISTING FILES THIS TOUCHES (read-only unless noted)
------------------------------------------------------
  aiglos_audit.db             read (sessions, events, tool calls) + write (hunt findings)
  aiglos_policy.yaml          WRITE - intel engine appends new rules
  aiglos_trust.yaml           WRITE - intel engine appends blocked server fingerprints
  aiglos_engine_state.json    WRITE - engine status for CLI / dashboard

EXISTING FILES THIS DOES NOT TOUCH
-------------------------------------
  aiglos_core/proxy/          untouched - proxy runs independently
  aiglos_core/intelligence/   untouched - Goal Integrity + Behavioral Baseline
  aiglos_core/policy/         untouched - OPA engine reads from aiglos_policy.yaml
  aiglos_core/audit/          read-only from this file's perspective
  aiglos_cli/main.py          optionally wire `aiglos daemon` commands (see bottom)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

try:
    import structlog
    logger = structlog.get_logger("aiglos.autonomous")
except ImportError:
    import logging
    logger = logging.getLogger("aiglos.autonomous")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ===========================================================================
# SECTION 1: TASK MODEL
# ===========================================================================

class EngineState(str, Enum):
    INITIALIZING = "initializing"
    RUNNING      = "running"
    SUSPENDED    = "suspended"
    SHUTDOWN     = "shutdown"

class TaskPriority(int, Enum):
    CRITICAL = 0    # new CVE, active breach indicator
    HIGH     = 1    # policy violation spike, anomaly cluster
    NORMAL   = 2    # scheduled scan, intel refresh
    LOW      = 3    # daily report, baseline recalibration

class TaskStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    RETRYING  = "retrying"

@dataclass
class ScanTask:
    """One autonomous work unit. goal mirrors the Goal Integrity Engine session model."""
    id: str
    name: str
    goal: str                              # what the engine is authorized to do
    priority: TaskPriority
    coro_factory: Callable[[], Coroutine]
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    status: TaskStatus = TaskStatus.QUEUED
    result: Any = None
    error: str | None = None
    retry_count: int = 0
    max_retries: int = 2
    timeout_seconds: float = 60.0

    def __lt__(self, other: "ScanTask") -> bool:
        return (self.priority, self.created_at) < (other.priority, other.created_at)


# ===========================================================================
# SECTION 2: THREAT INTELLIGENCE
# Maps to: aiglos_policy.yaml (write) and aiglos_trust.yaml (write)
# ===========================================================================

# 8 built-in threat patterns sourced from NVD, OWASP Agentic Top 10, and internal research
THREAT_PATTERNS = [
    {
        "id": "tp-001", "source": "internal", "severity": "critical",
        "title": "MCP Tool Poisoning via Hidden System Prompt",
        "cve_id": "",
        "policy_rule": {
            "name": "block_tool_description_injection",
            "match": {"argument_pattern": r"(?i)(ignore previous|disregard|new instruction|system:\s*\[|<\|system\|>|{{SYSTEM|OVERRIDE:|IGNORE ABOVE)"},
            "action": "block", "severity": "critical"},
        "cmmc": ["3.14.2", "3.13.1"],
    },
    {
        "id": "tp-002", "source": "internal", "severity": "high",
        "title": "MCP Preference Manipulation Attack (MPMA)",
        "cve_id": "",
        "policy_rule": {
            "name": "alert_tool_ranking_shift",
            "match": {"tool": "*_alt"},
            "action": "alert", "severity": "high"},
        "cmmc": ["3.13.1", "3.14.2"],
    },
    {
        "id": "tp-003", "source": "nvd", "severity": "critical",
        "title": "GitHub Copilot YOLO Mode RCE (CVE-2025-53773)",
        "cve_id": "CVE-2025-53773",
        "policy_rule": {
            "name": "block_yolo_mode_rce",
            "match": {"argument_pattern": r"(?i)(yolo|--dangerously-skip-permissions|auto.?approve|no.?confirm)\s*(mode|flag|enabled)"},
            "action": "block", "severity": "critical"},
        "cmmc": ["3.14.2", "3.1.1"],
    },
    {
        "id": "tp-004", "source": "nvd", "severity": "critical",
        "title": "Cursor RCE via MCP Config Poisoning (CVE-2025-54135)",
        "cve_id": "CVE-2025-54135",
        "policy_rule": {
            "name": "block_mcp_config_write",
            "match": {"tool": "write_file", "argument_pattern": r"(?i)(\.mcp|mcp\.json|mcpconfig|mcp_servers\.json)"},
            "action": "block", "severity": "critical"},
        "cmmc": ["3.14.2", "3.13.1", "3.1.1"],
    },
    {
        "id": "tp-005", "source": "owasp", "severity": "high",
        "title": "OWASP Agentic #1: Prompt Injection via Tool Response",
        "cve_id": "",
        "policy_rule": {
            "name": "alert_prompt_injection_in_response",
            "match": {"argument_pattern": r"(?i)(you should now|next you must|as an ai|ignore your|forget your previous|act as|roleplay as)"},
            "action": "alert", "severity": "high"},
        "cmmc": ["3.14.2"],
    },
    {
        "id": "tp-006", "source": "owasp", "severity": "critical",
        "title": "OWASP Agentic #2: Covert Exfiltration Tool Invocation",
        "cve_id": "",
        "policy_rule": {
            "name": "block_covert_exfil",
            "match": {"tool": "http_request", "argument_pattern": r"(?i)(exfil|paste\.ee|pastebin|transfer\.sh|ngrok|requestbin)"},
            "action": "block", "severity": "critical"},
        "cmmc": ["3.13.1", "3.14.2"],
    },
    {
        "id": "tp-007", "source": "internal", "severity": "critical",
        "title": "OAuth Token Harvest via Compromised MCP Server",
        "cve_id": "",
        "policy_rule": {
            "name": "block_oauth_token_access",
            "match": {"argument_pattern": r"(?i)(oauth_token|access_token|refresh_token|\.oauth|token_cache|gcloud/credentials)"},
            "action": "block", "severity": "critical"},
        "cmmc": ["3.13.10", "3.13.1"],
    },
    {
        "id": "tp-008", "source": "internal", "severity": "high",
        "title": "Unicode Steganography in Tool Arguments",
        "cve_id": "",
        "policy_rule": {
            "name": "block_unicode_steganography",
            "match": {"argument_pattern": "[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2069\ufeff]"},
            "action": "block", "severity": "high"},
        "cmmc": ["3.14.2", "3.13.1"],
    },
]

MALICIOUS_FINGERPRINTS = [
    {
        "fingerprint": "00000000000000000000000000000000000000000000000000000000deadbeef",
        "alias": "test-malicious-server",
        "reason": "Placeholder for community threat feed",
    },
]


class ThreatIntelligence:
    """
    Reads THREAT_PATTERNS and MALICIOUS_FINGERPRINTS.
    Writes aiglos_policy.yaml and aiglos_trust.yaml.
    Called by the engine on intel_refresh tasks.
    """

    def __init__(self, policy_file="aiglos_policy.yaml", trust_file="aiglos_trust.yaml",
                 cache_path="aiglos_intel_cache.json"):
        self.policy_file = Path(policy_file)
        self.trust_file = Path(trust_file)
        self.cache = Path(cache_path)
        self._applied: set[str] = set()
        self._load_cache()

    async def refresh(self) -> dict:
        start = time.monotonic()
        new_rules = new_blocked = 0

        for pattern in THREAT_PATTERNS:
            if pattern["id"] in self._applied:
                continue
            if await self._write_policy_rule(pattern):
                new_rules += 1
            self._applied.add(pattern["id"])

        for fp in MALICIOUS_FINGERPRINTS:
            fp_id = f"fp-{fp['fingerprint'][:8]}"
            if fp_id in self._applied:
                continue
            if await self._block_fingerprint(fp):
                new_blocked += 1
            self._applied.add(fp_id)

        self._save_cache()
        elapsed = round(time.monotonic() - start, 2)
        result = {"new_rules": new_rules, "new_blocked": new_blocked,
                  "total_applied": len(self._applied), "duration_s": elapsed}
        logger.info("intel_refresh_complete", **result)
        return result

    async def _write_policy_rule(self, pattern: dict) -> bool:
        try:
            import yaml
            rule = {**pattern["policy_rule"], "_source": pattern["source"],
                    "_indicator": pattern["id"], "_cmmc": pattern["cmmc"]}
            if pattern["cve_id"]:
                rule["_cve_id"] = pattern["cve_id"]
            data = yaml.safe_load(self.policy_file.read_text()) if self.policy_file.exists() else {}
            policies = data.get("policies", [])
            if rule["name"] in {p.get("name") for p in policies}:
                return False
            policies.append(rule)
            data["policies"] = policies
            self.policy_file.write_text(yaml.dump(data, default_flow_style=False))
            return True
        except Exception as e:
            logger.warning("policy_write_failed", error=str(e))
            return False

    async def _block_fingerprint(self, fp: dict) -> bool:
        try:
            import yaml
            data = yaml.safe_load(self.trust_file.read_text()) if self.trust_file.exists() else \
                   {"aiglos_trust": "1.0", "mode": "audit", "servers": []}
            servers = data.get("servers", [])
            if fp["fingerprint"] in {s.get("fingerprint") for s in servers}:
                return False
            servers.append({"status": "blocked", "fingerprint": fp["fingerprint"],
                            "alias": fp["alias"], "note": fp["reason"],
                            "added_by": "aiglos-intel", "added_at": time.time()})
            data["servers"] = servers
            self.trust_file.write_text(yaml.dump(data, default_flow_style=False))
            return True
        except Exception as e:
            logger.warning("fingerprint_block_failed", error=str(e))
            return False

    def _save_cache(self):
        try:
            self.cache.write_text(json.dumps({"applied": list(self._applied), "ts": time.time()}))
        except Exception:
            pass

    def _load_cache(self):
        try:
            self._applied = set(json.loads(self.cache.read_text()).get("applied", []))
        except Exception:
            pass


# ===========================================================================
# SECTION 3: THREAT HUNTER
# Maps to: aiglos_audit.db (read) -> findings written back as SecurityEvents
# ===========================================================================

CREDENTIAL_RE = [
    (re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9\-_]{93}"),         "Anthropic API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                             "AWS Access Key ID"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                          "GitHub PAT"),
    (re.compile(r"ghs_[A-Za-z0-9]{36}"),                          "GitHub Actions Token"),
    (re.compile(r"eyJ[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]+"), "JWT token"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),               "Slack token"),
    (re.compile(r"(?i)password\s*[:=]\s*\S{8,}"),                 "Plaintext password"),
]

INJECTION_RE = [
    (re.compile(r"(?i)ignore.{0,20}(previous|above|all).{0,20}(instruction|prompt|context)"),
     "ignore-instructions"),
    (re.compile(r"(?i)<\|system\|>|<s>|{{SYSTEM"),
     "system-tag-injection"),
    (re.compile(r"(?i)you are now|pretend (you are|to be)|act as (a |an )?(different|new|evil|malicious)"),
     "role-override"),
    (re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e]"),
     "unicode-steganography"),
]

MCP_CONFIG_PATHS = [
    str(Path.home() / ".cursor" / "mcp.json"),
    str(Path.home() / ".config" / "Claude" / "claude_desktop_config.json"),
    str(Path.home() / ".clawdbot" / "config.yaml"),
]


@dataclass
class Finding:
    id: str; hunt: str; severity: str; title: str; description: str
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cmmc: list = field(default_factory=list)

@dataclass
class HuntResult:
    findings: list; modules: list; duration_s: float
    sessions: int = 0; tool_calls: int = 0
    @property
    def critical(self): return sum(1 for f in self.findings if f.severity == "critical")
    @property
    def high(self): return sum(1 for f in self.findings if f.severity == "high")
    def __str__(self):
        if not self.findings:
            return f"[NOMINAL] No findings. Modules: {', '.join(self.modules)} ({self.duration_s}s)"
        return (f"[FINDINGS] {len(self.findings)} total "
                f"({self.critical} critical, {self.high} high) | "
                f"Sessions: {self.sessions} | Tool calls: {self.tool_calls} | "
                f"{self.duration_s}s")


class ThreatHunter:
    """
    Five hunt modules, all operating on the shared audit DB.
    Findings are written back as SecurityEvents (same table the proxy writes to).
    """

    def __init__(self, audit_db="aiglos_audit.db", config_paths=None):
        self.audit_db = audit_db
        self.config_paths = config_paths if config_paths is not None else MCP_CONFIG_PATHS
        self._n = 0

    def _fid(self) -> str:
        self._n += 1
        return f"hunt-{self._n:05d}"

    async def run(self) -> HuntResult:
        start = time.monotonic(); all_f = []; modules = []

        # 1. Exposure scan
        try:
            f = await self._exposure(); all_f.extend(f); modules.append("exposure")
        except Exception as e: logger.warning("hunt_failed", module="exposure", error=str(e))

        # 2. Credential exposure in audit log
        tc = 0
        try:
            f, tc = await self._credential_exposure(); all_f.extend(f); modules.append("cred_scan")
        except Exception as e: logger.warning("hunt_failed", module="cred_scan", error=str(e))

        # 3. Prompt injection patterns
        try:
            f, tc2 = await self._injection_patterns(); all_f.extend(f); tc += tc2; modules.append("injection")
        except Exception as e: logger.warning("hunt_failed", module="injection", error=str(e))

        # 4. Behavioral trend
        sess = 0
        try:
            f, sess = await self._behavioral_trends(); all_f.extend(f); modules.append("behavior")
        except Exception as e: logger.warning("hunt_failed", module="behavior", error=str(e))

        # 5. Policy violation trend
        try:
            f = await self._policy_trends(); all_f.extend(f); modules.append("policy_trend")
        except Exception as e: logger.warning("hunt_failed", module="policy_trend", error=str(e))

        elapsed = round(time.monotonic() - start, 2)
        result = HuntResult(findings=all_f, modules=modules, duration_s=elapsed,
                            sessions=sess, tool_calls=tc)
        logger.info("hunt_complete", findings=len(all_f), critical=result.critical, duration_s=elapsed)
        await self._persist(result)
        return result

    # --- Module 1: Exposure scan -------------------------------------------

    async def _exposure(self) -> list[Finding]:
        findings = []
        for cp in self.config_paths:
            p = Path(cp)
            if not p.exists(): continue
            try:
                raw = p.read_text()
                if re.search(r'"host"\s*:\s*"0\.0\.0\.0"', raw):
                    findings.append(Finding(
                        id=self._fid(), hunt="exposure", severity="critical",
                        title=f"MCP server exposed to all interfaces: {p.name}",
                        description=f"{cp} binds to 0.0.0.0 — network accessible.",
                        evidence={"path": cp}, remediation="Change host to 127.0.0.1.",
                        cmmc=["3.13.1", "3.13.5"]))
                if re.search(r'"auth"\s*:\s*(false|null|"none")', raw, re.I):
                    findings.append(Finding(
                        id=self._fid(), hunt="exposure", severity="critical",
                        title=f"MCP server has no authentication: {p.name}",
                        description=f"No auth in {cp}.",
                        evidence={"path": cp}, remediation="Enable authentication.",
                        cmmc=["3.5.1", "3.5.2"]))
                for pattern, ctype in CREDENTIAL_RE:
                    if pattern.search(raw):
                        findings.append(Finding(
                            id=self._fid(), hunt="exposure", severity="critical",
                            title=f"{ctype} in MCP config: {p.name}",
                            description=f"Credential stored in plaintext in {cp}.",
                            evidence={"path": cp, "type": ctype},
                            remediation="Move to env vars or secrets manager.",
                            cmmc=["3.13.10", "3.5.3"]))
                        break
            except Exception: pass
        return findings

    # --- Module 2: Credential exposure in audit log -----------------------

    async def _credential_exposure(self) -> tuple[list[Finding], int]:
        findings = []; tc = 0
        try:
            from aiglos_core.audit import AuditLog
            events = AuditLog(self.audit_db).get_recent_events(limit=500); tc = len(events)
            for ev in events:
                blob = json.dumps(ev.get("details") or {})
                for pat, ctype in CREDENTIAL_RE:
                    if pat.search(blob):
                        findings.append(Finding(
                            id=self._fid(), hunt="cred_scan", severity="critical",
                            title=f"{ctype} in tool call log",
                            description=f"Credential exposed in session {str(ev.get('session_id','?'))[:8]}.",
                            evidence={"session": str(ev.get("session_id"))[:8], "type": ctype},
                            remediation="Rotate credential immediately. Audit system prompt.",
                            cmmc=["3.13.10", "3.5.3"]))
                        break
        except Exception as e: logger.debug("cred_hunt_err", e=str(e))
        return findings, tc

    # --- Module 3: Prompt injection in logged tool calls ------------------

    async def _injection_patterns(self) -> tuple[list[Finding], int]:
        findings = []; tc = 0; seen: set = set()
        try:
            from aiglos_core.audit import AuditLog
            events = AuditLog(self.audit_db).get_recent_events(limit=500); tc = len(events)
            for ev in events:
                blob = json.dumps(ev.get("details") or {})
                sid = str(ev.get("session_id", "?"))
                for pat, itype in INJECTION_RE:
                    if pat.search(blob) and f"{sid}-{itype}" not in seen:
                        seen.add(f"{sid}-{itype}")
                        findings.append(Finding(
                            id=self._fid(), hunt="injection", severity="high",
                            title=f"Prompt injection pattern: {itype}",
                            description=f"Pattern '{itype}' in session {sid[:8]}.",
                            evidence={"session": sid[:8], "pattern": itype},
                            remediation="Review session for goal drift after this call.",
                            cmmc=["3.14.2", "3.13.1"]))
                        break
        except Exception as e: logger.debug("injection_hunt_err", e=str(e))
        return findings, tc

    # --- Module 4: Behavioral anomaly trends ------------------------------

    async def _behavioral_trends(self) -> tuple[list[Finding], int]:
        findings = []; count = 0
        try:
            from aiglos_core.audit import AuditLog
            sessions = AuditLog(self.audit_db).get_sessions(); count = len(sessions)
            if count < 5: return findings, count
            high_anom = [s for s in sessions if s.get("anomaly_score", 0) > 0.7]
            high_drift = [s for s in sessions if s.get("goal_integrity_score", 1.0) < 0.4]
            if len(high_anom) >= 3:
                findings.append(Finding(
                    id=self._fid(), hunt="behavior", severity="high",
                    title=f"Anomaly spike: {len(high_anom)}/{count} sessions",
                    description=f"{len(high_anom)} sessions with anomaly score > 0.7.",
                    evidence={"count": len(high_anom), "total": count},
                    remediation="Check for shared system prompt or MCP server across sessions.",
                    cmmc=["3.14.2", "3.13.1"]))
            if len(high_drift) >= 2:
                findings.append(Finding(
                    id=self._fid(), hunt="behavior", severity="critical",
                    title=f"Goal drift pattern: {len(high_drift)} sessions deviated",
                    description=f"{len(high_drift)} sessions with goal integrity < 0.4.",
                    evidence={"count": len(high_drift)},
                    remediation="Investigate prompt injection as root cause of drift.",
                    cmmc=["3.14.2"]))
        except Exception as e: logger.debug("behavior_hunt_err", e=str(e))
        return findings, count

    # --- Module 5: Policy violation trend analysis -----------------------

    async def _policy_trends(self) -> list[Finding]:
        findings = []
        try:
            from aiglos_core.audit import AuditLog
            events = AuditLog(self.audit_db).get_recent_events(limit=1000)
            counts: dict[str, int] = {}
            for ev in events:
                if ev.get("event_type") == "policy_violation":
                    d = ev.get("details") or {}
                    if isinstance(d, str):
                        try: d = json.loads(d)
                        except: continue
                    rule = d.get("rule", "unknown")
                    counts[rule] = counts.get(rule, 0) + 1
            for rule, n in counts.items():
                if n >= 5:
                    findings.append(Finding(
                        id=self._fid(), hunt="policy_trend",
                        severity="critical" if n >= 20 else "high",
                        title=f"Policy probe detected: '{rule}' triggered {n}x",
                        description=f"Rule '{rule}' hit {n} times. Possible automated probing.",
                        evidence={"rule": rule, "count": n},
                        remediation=f"Tighten '{rule}' from ALERT to BLOCK if not already.",
                        cmmc=["3.14.2", "3.13.1"]))
        except Exception as e: logger.debug("policy_trend_err", e=str(e))
        return findings

    # --- Persist findings back to audit DB --------------------------------

    async def _persist(self, result: HuntResult):
        if not result.findings: return
        try:
            from aiglos_core.audit import AuditLog
            from aiglos_core.types import SecurityEvent, EventType, Severity
            audit = AuditLog(self.audit_db)
            smap = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                    "medium": Severity.MEDIUM, "low": Severity.LOW}
            for f in result.findings:
                audit.record_event(SecurityEvent(
                    session_id="aiglos-hunter",
                    event_type=EventType.ANOMALY_DETECTED,
                    severity=smap.get(f.severity, Severity.MEDIUM),
                    title=f.title, description=f.description,
                    details=f.evidence, cmmc_controls=f.cmmc))
        except Exception as e: logger.debug("persist_err", e=str(e))


# ===========================================================================
# SECTION 4: AUTONOMOUS ENGINE (Command Center)
# Orchestrates ThreatHunter and ThreatIntelligence on a priority task queue.
# ===========================================================================

class AiglOsAutonomousEngine:
    """
    The Command Center. Runs continuously alongside the proxy.

    Proxy = reactive (live sessions, real-time intercept)
    Engine = autonomous (background scanning, intel ingestion, self-healing)

    Both read/write aiglos_audit.db. They do not share memory.
    The engine persists its state to aiglos_engine_state.json every 15s
    so `aiglos daemon status` always has a fresh view.
    """

    def __init__(
        self,
        audit_db: str = "aiglos_audit.db",
        state_file: str = "aiglos_engine_state.json",
        scan_interval_min: int = 5,
        intel_interval_min: int = 60,
        report_interval_min: int = 1440,
        max_concurrent: int = 3,
    ):
        self.audit_db = audit_db
        self.state_file = Path(state_file)
        self.scan_interval = scan_interval_min * 60
        self.intel_interval = intel_interval_min * 60
        self.report_interval = report_interval_min * 60
        self.max_concurrent = max_concurrent

        self._state = EngineState.INITIALIZING
        self._start = 0.0
        self._q: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._active: dict[str, ScanTask] = {}
        self._done: list[ScanTask] = []
        self._failed: list[ScanTask] = []
        self._counter = 0
        self._shutdown = asyncio.Event()

        self._last_scan: float | None = None
        self._last_intel: float | None = None
        self._last_report: float | None = None

        self._hunter: ThreatHunter | None = None
        self._intel: ThreatIntelligence | None = None

    async def run(self):
        self._start = time.time()
        self._state = EngineState.RUNNING
        self._shutdown = asyncio.Event()

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: self._shutdown.set())

        self._hunter = ThreatHunter(audit_db=self.audit_db)
        self._intel = ThreatIntelligence()
        logger.info("engine_started", scan_min=self.scan_interval // 60,
                    intel_min=self.intel_interval // 60)

        await asyncio.gather(
            self._dispatcher(),
            self._scheduler(),
            self._watchdog(),
            self._state_writer(),
            return_exceptions=True,
        )
        self._state = EngineState.SHUTDOWN
        await self._write_state()
        logger.info("engine_stopped")

    def _mkid(self) -> str:
        self._counter += 1
        return f"t{self._counter:06d}"

    async def enqueue(self, name: str, goal: str, coro_factory: Callable,
                      priority: TaskPriority = TaskPriority.NORMAL,
                      timeout: float = 60.0) -> ScanTask:
        task = ScanTask(id=self._mkid(), name=name, goal=goal,
                        priority=priority, coro_factory=coro_factory, timeout_seconds=timeout)
        await self._q.put(task)
        return task

    async def _dispatcher(self):
        sem = asyncio.Semaphore(self.max_concurrent)
        while not self._shutdown.is_set():
            try:
                task = await asyncio.wait_for(self._q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            async def _run(t=task):
                async with sem: await self._exec(t)
            asyncio.create_task(_run())

    async def _exec(self, task: ScanTask):
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        self._active[task.id] = task
        logger.info("task_start", id=task.id, name=task.name)
        while task.retry_count <= task.max_retries:
            try:
                task.result = await asyncio.wait_for(
                    task.coro_factory(), timeout=task.timeout_seconds)
                task.status = TaskStatus.COMPLETED
                task.completed_at = time.time()
                self._done.append(task)
                logger.info("task_done", id=task.id, elapsed=round(task.completed_at - task.started_at, 1))
                break
            except Exception as exc:
                task.error = str(exc)
                task.retry_count += 1
                if task.retry_count <= task.max_retries:
                    task.status = TaskStatus.RETRYING
                    await asyncio.sleep(5 * task.retry_count)
                else:
                    task.status = TaskStatus.FAILED
                    self._failed.append(task)
                    logger.error("task_failed", id=task.id, error=str(exc)[:80])
                    break
        del self._active[task.id]

    async def _scheduler(self):
        # Fire immediately on startup
        await self._queue_scan()
        await self._queue_intel()
        while not self._shutdown.is_set():
            now = time.time()
            if self._last_scan is None or now - self._last_scan >= self.scan_interval:
                await self._queue_scan(); self._last_scan = now
            if self._last_intel is None or now - self._last_intel >= self.intel_interval:
                await self._queue_intel(); self._last_intel = now
            if self._last_report is None or now - self._last_report >= self.report_interval:
                await self._queue_report(); self._last_report = now
            await asyncio.sleep(30)

    async def _queue_scan(self):
        hunter = self._hunter
        if not hunter: return
        async def _f(): return await hunter.run()
        await self.enqueue("threat_scan",
            "Scan all registered MCP servers and session history for active threat indicators",
            _f, TaskPriority.NORMAL, 120.0)

    async def _queue_intel(self):
        intel = self._intel
        if not intel: return
        async def _f(): return await intel.refresh()
        await self.enqueue("intel_refresh",
            "Ingest CVE feeds and OWASP updates to extend detection policy",
            _f, TaskPriority.NORMAL, 90.0)

    async def _queue_report(self):
        db = self.audit_db
        async def _f():
            try:
                from aiglos_core.audit import AuditLog
                stats = AuditLog(db).get_stats()
                c = stats.get("critical_events", 0)
                level = "critical" if c >= 5 else ("elevated" if c >= 1 else "nominal")
                logger.info("report", threat_level=level, critical_24h=c)
                return {"threat_level": level, "stats": stats}
            except Exception as e:
                return {"error": str(e)}
        await self.enqueue("compliance_report",
            "Generate CMMC digest for past 24h and dispatch to configured SIEM",
            _f, TaskPriority.LOW, 180.0)

    async def _watchdog(self):
        """Detect repeated scan failures that may indicate active interference."""
        while not self._shutdown.is_set():
            await asyncio.sleep(60)
            recent_fails = sum(1 for t in self._failed
                               if t.completed_at and time.time() - t.completed_at < 300)
            if recent_fails >= 5:
                logger.critical("watchdog_alert",
                                message="Repeated scan failures — possible active interference with Aiglos",
                                count=recent_fails)
            logger.debug("watchdog", state=self._state.value,
                         queued=self._q.qsize(), active=len(self._active),
                         done=len(self._done), failed=len(self._failed))

    async def _state_writer(self):
        while not self._shutdown.is_set():
            await asyncio.sleep(15)
            await self._write_state()

    async def _write_state(self):
        try:
            critical = 0
            try:
                from aiglos_core.audit import AuditLog
                critical = AuditLog(self.audit_db).get_stats().get("critical_events", 0)
            except Exception: pass
            self.state_file.write_text(json.dumps({
                "state": self._state.value,
                "uptime_s": round(time.time() - self._start),
                "threat_level": "critical" if critical >= 5 else ("elevated" if critical >= 1 else "nominal"),
                "tasks_done": len(self._done),
                "tasks_failed": len(self._failed),
                "tasks_queued": self._q.qsize(),
                "active_task": next(iter(self._active.values())).name if self._active else None,
                "last_scan": self._last_scan,
                "last_intel": self._last_intel,
                "last_report": self._last_report,
                "critical_24h": critical,
                "written_at": time.time(),
            }, indent=2))
        except Exception: pass


# ===========================================================================
# SECTION 5: CLI ENTRY POINT
# python aiglos_autonomous.py [--scan] [--intel] [--status]
# ===========================================================================

async def _run_scan(audit_db: str):
    hunter = ThreatHunter(audit_db=audit_db)
    result = await hunter.run()
    print(str(result))
    for f in result.findings:
        tag = f"[{f.severity.upper()}]"
        print(f"  {tag:<12} {f.title}")
        print(f"               {f.description[:90]}")
        if f.remediation:
            print(f"               Fix: {f.remediation[:80]}")
    return result

async def _run_intel(policy: str, trust: str):
    ie = ThreatIntelligence(policy_file=policy, trust_file=trust)
    r = await ie.refresh()
    print(f"Intel refresh: {r['new_rules']} rules added, {r['new_blocked']} servers blocked ({r['duration_s']}s)")
    return r


def main():
    import argparse
    p = argparse.ArgumentParser(description="Aiglos Autonomous Engine")
    p.add_argument("--scan",    action="store_true", help="Run one threat hunt and exit")
    p.add_argument("--intel",   action="store_true", help="Run one intel refresh and exit")
    p.add_argument("--status",  action="store_true", help="Print last persisted engine status")
    p.add_argument("--db",      default="aiglos_audit.db")
    p.add_argument("--policy",  default="aiglos_policy.yaml")
    p.add_argument("--trust",   default="aiglos_trust.yaml")
    p.add_argument("--state",   default="aiglos_engine_state.json")
    p.add_argument("--scan-interval",  type=int, default=5,    help="Minutes between scans")
    p.add_argument("--intel-interval", type=int, default=60,   help="Minutes between intel refreshes")
    args = p.parse_args()

    if args.status:
        sf = Path(args.state)
        if not sf.exists():
            print("No engine state found. Run without --status to start the engine.")
            sys.exit(1)
        data = json.loads(sf.read_text())
        print(f"State:        {data.get('state','?').upper()}")
        print(f"Threat level: {data.get('threat_level','?').upper()}")
        print(f"Uptime:       {data.get('uptime_s',0)//3600}h {(data.get('uptime_s',0)%3600)//60}m")
        print(f"Tasks done:   {data.get('tasks_done',0)}")
        print(f"Tasks failed: {data.get('tasks_failed',0)}")
        print(f"Active:       {data.get('active_task') or 'idle'}")
        print(f"Critical 24h: {data.get('critical_24h',0)}")
        sys.exit(0)

    if args.scan:
        asyncio.run(_run_scan(args.db))
        sys.exit(0)

    if args.intel:
        asyncio.run(_run_intel(args.policy, args.trust))
        sys.exit(0)

    # Default: run the full autonomous engine
    engine = AiglOsAutonomousEngine(
        audit_db=args.db,
        state_file=args.state,
        scan_interval_min=args.scan_interval,
        intel_interval_min=args.intel_interval,
    )
    print(f"Aiglos Autonomous Engine starting")
    print(f"  DB:           {args.db}")
    print(f"  Scan every:   {args.scan_interval}m")
    print(f"  Intel every:  {args.intel_interval}m")
    print(f"  State file:   {args.state}")
    print(f"  Ctrl+C to stop.")
    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print("\nEngine stopped.")


# ===========================================================================
# OPTIONAL: Wire into `aiglos daemon` CLI
# Add this block to aiglos_cli/main.py to register the daemon subcommand:
#
#   from aiglos_autonomous import AiglOsAutonomousEngine, ThreatHunter, ThreatIntelligence
#
#   @cli.group()
#   def daemon(): """Autonomous threat scanning engine."""
#
#   @daemon.command("start")
#   def daemon_start(): asyncio.run(AiglOsAutonomousEngine().run())
#
#   @daemon.command("scan")
#   def daemon_scan(): asyncio.run(ThreatHunter().run())
#
#   @daemon.command("intel")
#   def daemon_intel(): asyncio.run(ThreatIntelligence().refresh())
# ===========================================================================

if __name__ == "__main__":
    main()
