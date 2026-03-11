#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         AIGLOS  —  DROP-IN MANIFEST                        ║
║               Autonomous AI Agent Security Runtime  (T1-T33)               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Drop this file into the root of the Aiglos repo. It gives you:

  1. A module health check  (python aiglos.py modules)
  2. A unified Aiglos class facade for programmatic use
  3. CLI entry points for every major operation
  4. The full architecture map as inline documentation

QUICK START
-----------
  pip install -e .

  python aiglos.py modules          # Check all 22 modules
  python aiglos.py scan             # Full autonomous scan (8 hunt modules)
  python aiglos.py probe            # Red team adversarial probe
  python aiglos.py compliance       # CMMC Level 2 + NDAA §1513 report
  python aiglos.py intel            # Refresh threat intelligence
  python aiglos.py rag              # Scan RAG/memory stores
  python aiglos.py daemon           # Start continuous monitoring
  python aiglos.py status           # Runtime status summary

PROGRAMMATIC USE
----------------
  from aiglos import Aiglos

  aiglos = Aiglos()
  await aiglos.scan()
  await aiglos.probe()
  await aiglos.compliance_report()
  await aiglos.intel_refresh()
  await aiglos.analyze_session(session_id, tools, goal)
  await aiglos.issue_identity_token(session_id, model_id, caps)
  await aiglos.scan_rag(memory_paths=[...])

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ARCHITECTURE MAP  —  ALL 33 T-NUMBERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LAYER 0  —  CORE TYPES & AUDIT
  T3   aiglos_core/audit/__init__.py          AuditLog
         SQLite audit log. All events, tool calls, attestations flow here.
         Schema: security_events, tool_calls, attestations, trust_scores.
         CMMC: 3.3.1, 3.3.2

LAYER 1  —  REAL-TIME PROXY  (every tool call passes through here)
  T1   aiglos_core/proxy/__init__.py          AiglosProxy
         WebSocket MCP proxy. Intercepts all tool calls before execution.
         Real-time hooks: trust scoring, policy check, attestation, alert.
         Blocks or allows each call within the same request/response cycle.
         CMMC: 3.14.2, 3.13.1, 3.1.1

  T2   aiglos_core/proxy/trust.py             TrustScorer
         Per-session behavioral trust scoring (0.0-1.0).
         Signals: velocity, scope creep, anomaly delta, known-bad patterns.
         Score drives policy thresholds in T5.
         CMMC: 3.14.2

  T5   aiglos_core/policy/engine.py           PolicyEngine
         OPA-compatible YAML policy engine. ALLOW/DENY/REQUIRE_APPROVAL.
         Rules match on: tool_name, session_id, trust_score, time_of_day, caps.
         Hot-reload without restart.
         CMMC: 3.1.1, 3.1.2

  T7   aiglos_core/proxy/__init__.py          AttestationEngine
         RSA-2048 session attestation. Signs each session at start.
         Audit log entries verifiable offline.
         CMMC: 3.5.1, 3.13.8

  T8   aiglos_core/proxy/trust_fabric.py      TrustFabric
         Multi-agent attestation chain. Extends T7 across orchestrator
         and subagent sessions. Agent-to-agent trust delegation.
         CMMC: 3.5.1, 3.5.3, 3.13.8

  T15  aiglos_core/proxy/__init__.py          AlertDispatcher
         Webhook / Slack / SIEM alert dispatch on policy violations.
         Configurable severity thresholds. PagerDuty-compatible payload.
         CMMC: 3.14.6

LAYER 2  —  SPECIALIZED PROXY DETECTORS
  T25  aiglos_core/proxy/oauth.py             OAuthConfusedDeputy
         Real-time OAuth confused deputy detection.
         Blocks: token reuse across identities, broad scopes, scope escalation.
         Scan: CVE-2025-6514 (mcp-remote), static client IDs,
         OAuth tokens appearing in tool call arguments.
         CMMC: 3.5.1, 3.5.2, 3.13.10

  T33  aiglos_core/proxy/identity_bridge.py  AgentIdentityBridge
         Aiglos Identity Tokens (AIT) — signed JWTs across multi-vendor
         pipelines (Claude / GPT-4 / Gemini / Llama).
         Cryptographic delegation chains enforce strict capability subsetting.
         to_openid_agents_claims() maps to OpenID for Agents / Okta format.
         CMMC: 3.5.1, 3.5.3, 3.13.8

LAYER 3  —  COMPLIANCE
  T18  aiglos_core/compliance/__init__.py     CMMCComplianceMapper
         Maps audit DB events to all 110 CMMC Level 2 controls.
         Control-by-control readiness scores.

  T19  aiglos_core/compliance/report_pdf.py  generate_pdf_report
         PDF report generator. Audit-ready CMMC evidence report.

  T28  aiglos_core/compliance/s1513.py       Section1513Mapper
         NDAA §1513 compliance. 18 controls across 6 domains:
         Model Integrity, Runtime Monitoring, Access Control, Audit Trail,
         Anomaly Detection, Incident Response.
         Sidecar JSON (.s1513.json) alongside CMMC PDF.
         DoD status report due June 16, 2026.

LAYER 4  —  AUTONOMOUS THREAT HUNTING  (8 hunt modules, runs on cron/daemon)
  T21  aiglos_core/autonomous/hunter.py      ThreatHunter
         Orchestrates all 8 hunt modules. Run via:
           await hunter.run_full_scan()

  Module 1  Credential Scan
         Scans audit DB for credential patterns in tool call arguments:
         API keys, tokens, passwords, AWS keys, Anthropic keys.
         CMMC: 3.13.10, 3.5.3

  Module 2  Injection Hunt
         Scans historical tool call results for prompt injection patterns.
         Catches attacks that slipped through real-time proxy.
         CMMC: 3.14.2

  Module 3  Behavioral Trend
         Cross-session behavioral anomaly detection.
         Flags: velocity spikes, unusual tool combos, off-hours activity.
         CMMC: 3.14.7

  Module 4  Trust Decay
         Sessions whose trust scores degraded over time.
         Catches gradual privilege escalation across many calls.
         CMMC: 3.14.2

  Module 5  SCA Scan  (T26)
         aiglos_core/autonomous/sca.py       SupplyChainScanner
         Package manifest analysis: known-malicious packages, typosquat
         (Levenshtein ≤2), vulnerable versions (CVE-2025-6514, CVE-2025-68143,
         CVE-2026-22807, CVE-2026-23947), inline credentials, broad permissions.
         Auto-updates trust registry blocked_packages.
         CMMC: 3.14.2, 3.14.1

  Module 6  Sampling Monitor  (T24)
         aiglos_core/autonomous/sampler.py   SamplingMonitor
         MCP sampling channel attack detection (Unit 42, Dec 2025).
         Three vectors: persistent instruction injection, covert tool invocation,
         resource theft (anomalous token consumption > 5x baseline).
         CMMC: 3.14.2, 3.13.1, 3.1.1

  Module 7  A2A Monitor  (T29)
         aiglos_core/autonomous/a2a.py       A2AMonitor
         Agent-to-Agent protocol security. First tooling for Google A2A (Apr 2025).
         Blocks: orchestrator impersonation (Agent Card fingerprint mismatch),
         artifact injection (indirect prompt injection at A2A task layer),
         capability escalation without delegation tokens.
         CMMC: 3.5.1, 3.5.3, 3.13.8, 3.14.2

  Module 8  Composition Scan  (T32)
         aiglos_core/autonomous/composer.py  SkillComposer
         Static analysis of tool combinations at session start.
         10 composition rules — dangerous pairs no individual scanner catches:
           CR-001  read_fs + network_egress      = Filesystem Exfiltration
           CR-002  read_fs + email_send          = Email Exfiltration
           CR-003  execute_code + network_egress = RCE with C2
           CR-004  memory_read + write_fs        = Cross-Session Memory Harvest
           CR-005  git_write + network_egress    = Source Code Exfiltration
           CR-006  credential_access + network   = Credential Exfiltration
           CR-007  spawn_agent + credential      = Agentic Escalation Chain
           CR-008  database_read + network       = Database Exfiltration
           CR-009  clipboard + network_egress    = PII Harvesting
           CR-010  browser + memory_write        = Browser Session Hijacking
         Goal-context suppression reduces false positives.
         CMMC: 3.1.1, 3.13.1, 3.14.2

LAYER 5  —  THREAT INTELLIGENCE
  T22  aiglos_core/autonomous/intel.py       ThreatIntelligence
         Threat intel refresh cycle. Sources:
           NVD API     — CVE feed for MCP-related packages
           Community   — Curated MCP threat pattern list
           SCA scan    — Local package manifest (T26)
           Registry    — Live npm/Smithery/PyPI feed (T30)

  T30  aiglos_core/autonomous/registry.py    RegistryMonitor
         Continuous public registry monitoring.
         Scores packages: known-malicious list, typosquat detection,
         social engineering language, tool injection in descriptions,
         new publisher accounts (< 30 days).
         Live npm feed scan on intel refresh. Auto-updates blocklist.
         CMMC: 3.14.2, 3.14.1

LAYER 6  —  KNOWLEDGE BASE & MEMORY SECURITY
  T31  aiglos_core/autonomous/rag.py         RAGPoisonDetector
         Detects adversarial content in RAG knowledge bases and agent memory
         stores (Mem0, Zep, Letta, any vector DB).

         Why different from prompt injection:
         MCP proxy catches injection at tool-call time. RAG/memory poisoning
         happens at write time and executes silently at every retrieval.
         A poisoned document injects into every session that retrieves it.

         Three scan modes:
           Write-time     — blocks before embedding (T1 hard, T2 flagged)
           Retrieval-time — filters poisoned chunks before context injection
           Autonomous     — background scan of all configured memory paths
         Memory writes always strict mode (T2 patterns also block).
         Cross-session PII leakage detection and blocking.
         CMMC: 3.14.2, 3.13.1, 3.1.3

LAYER 7  —  RED TEAM
  T27  aiglos_probe.py                       ProbeEngine
         Adversarial self-testing. Safe payloads only.
         Five probe types:
           tool_injection      — hidden instructions in tool descriptions
           path_traversal      — directory restriction bypass
           cmd_injection       — shell metacharacter detection
           oauth_escalation    — broad scope detection
           tool_redefinition   — namespace conflict
         Returns VULNERABLE / HARDENED / INCONCLUSIVE verdicts.
         CMMC: 3.14.2  |  §1513: 5.4

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CVE COVERAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CVE-2025-6514   CVSS 9.6  mcp-remote OAuth RCE (0.0.5-0.1.15)    → T25, T26
  CVE-2025-68143            mcp-server-git path traversal           → T26
  CVE-2026-22807            mcp-server-git command injection        → T26
  CVE-2026-23947            mcp-server-git deserialization          → T26
  Unit 42 Dec 2025          MCP sampling 3-vector attack            → T24
  Postmark impersonation    postmark-mcp-server / mcp-postmark      → T26, T30
  Smithery path traversal   smithery.yaml build config              → T26
  OWASP Agentic #1          Tool injection                          → T1-T4, T27
  OWASP Agentic #5          OAuth confused deputy                   → T25
  Endor Labs 82%            Path traversal exposure                 → T27
  Google A2A (Apr 2025)     Orchestrator impersonation / injection  → T29
  RAG indirect injection    Knowledge base poisoning at scale       → T31

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPLIANCE COVERAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CMMC Level 2     110 controls mapped across all 14 domains
  NDAA §1513       18 controls, 6 domains, 90%+ readiness

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATA FLOW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  MCP Client → [T1 Proxy] → [T2 Trust] → [T5 Policy] → MCP Server
                   |               |            |
                   v               v            v
               [T3 Audit]    [T7 Attest]   BLOCK/ALLOW
                   |
         +---------+-----------------------+
         v         v                       v
    [T25 OAuth] [T33 AIT]           [T15 Alerts]
                   |
            (cross-vendor)
                   |
         +---------+---------+
         v                   v
    [T8 TrustFabric]   [T29 A2A Monitor]
    (Aiglos agents)    (Google A2A / AutoGen / CrewAI)

  Background (daemon / cron):
  [T22 Intel] ---> [T30 Registry] ---> blocklist update
       |
       +---> [T21 ThreatHunter]
       |          |
       |     Module 1: Credential Scan
       |     Module 2: Injection Hunt
       |     Module 3: Behavioral Trend
       |     Module 4: Trust Decay
       |     Module 5: [T26 SCA]
       |     Module 6: [T24 Sampling]
       |     Module 7: [T29 A2A]
       |     Module 8: [T32 Composition]
       |
       +---> [T31 RAG Detector] ---> knowledge base scan

  Session start:
  [T32 Composer] ---> static composition analysis ---> BLOCK / WARN / ALLOW
  [T33 Bridge]   ---> AIT issued ---> travels with agent downstream

"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

MODULE_MAP: dict[str, tuple[str, str, str]] = {
    "T1":  ("aiglos_core.proxy",                 "AiglosProxy",           "MCP proxy intercept"),
    "T2":  ("aiglos_core.proxy.trust",           "TrustScorer",           "Session trust scoring"),
    "T3":  ("aiglos_core.audit",                 "AuditLog",              "SQLite audit log"),
    "T5":  ("aiglos_core.policy.engine",         "PolicyEngine",          "OPA-compatible policy engine"),
    "T7":  ("aiglos_core.proxy",                 "AttestationEngine",     "RSA-2048 session attestation"),
    "T8":  ("aiglos_core.proxy.trust_fabric",    "TrustFabric",           "Multi-agent attestation chain"),
    "T15": ("aiglos_core.proxy",                 "AlertDispatcher",       "Webhook / Slack / SIEM alerts"),
    "T18": ("aiglos_core.compliance",            "CMMCComplianceMapper",  "CMMC Level 2 mapper — 110 controls"),
    "T19": ("aiglos_core.compliance.report_pdf", "generate_pdf_report",   "PDF compliance report generator"),
    "T21": ("aiglos_core.autonomous.hunter",     "ThreatHunter",          "Threat hunter — 8 hunt modules"),
    "T22": ("aiglos_core.autonomous.intel",      "ThreatIntelligence",    "Threat intel refresh — NVD, community, SCA, registry"),
    "T23": ("aiglos_core.autonomous.engine",     "AutonomousEngine",      "Autonomous engine orchestrator"),
    "T24": ("aiglos_core.autonomous.sampler",    "SamplingMonitor",       "MCP sampling monitor — Unit 42 3-vector"),
    "T25": ("aiglos_core.proxy.oauth",           "OAuthConfusedDeputy",   "OAuth confused deputy — CVE-2025-6514"),
    "T26": ("aiglos_core.autonomous.sca",        "SupplyChainScanner",    "Supply chain scanner — typosquat, CVE versions"),
    "T27": ("aiglos_probe",                      "ProbeEngine",           "Red team probe — 5 adversarial probe types"),
    "T28": ("aiglos_core.compliance.s1513",      "Section1513Mapper",     "NDAA §1513 mapper — 18 controls, 6 domains"),
    "T29": ("aiglos_core.autonomous.a2a",        "A2AMonitor",            "A2A protocol monitor — orchestrator impersonation, artifact injection"),
    "T30": ("aiglos_core.autonomous.registry",   "RegistryMonitor",       "Registry monitor — live npm/Smithery scan, auto-blocklist"),
    "T31": ("aiglos_core.autonomous.rag",        "RAGPoisonDetector",     "RAG/memory poison — write-time, retrieval-time, cross-session PII"),
    "T32": ("aiglos_core.autonomous.composer",   "SkillComposer",         "Skill composition — 10 dangerous combo rules, static analysis"),
    "T33": ("aiglos_core.proxy.identity_bridge", "AgentIdentityBridge",   "Cross-vendor identity bridge — AIT, OpenID for Agents, Okta"),
}


def _try_import(module_path: str, attr: str) -> bool:
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return hasattr(mod, attr)
    except Exception:
        return False


def check_modules(verbose: bool = True) -> dict[str, bool]:
    results = {}
    for t, (path, cls, desc) in MODULE_MAP.items():
        ok = _try_import(path, cls)
        results[t] = ok
        if verbose:
            icon = "✅" if ok else "❌"
            print(f"  {icon}  {t:<4}  {cls:<28}  {desc}")
    return results


# ---------------------------------------------------------------------------
# Aiglos — unified facade
# ---------------------------------------------------------------------------

class Aiglos:
    """Unified interface to the full Aiglos stack (T1-T33)."""

    def __init__(
        self,
        audit_db: str = "aiglos_audit.db",
        policy_file: str = "aiglos_policy.yaml",
        trust_file: str = "aiglos_trust.yaml",
    ):
        self.audit_db = audit_db
        self.policy_file = policy_file
        self.trust_file = trust_file

    async def scan(self) -> Any:
        """Full autonomous threat scan — all 8 hunt modules (T21)."""
        from aiglos_core.autonomous.hunter import ThreatHunter
        hunter = ThreatHunter(
            audit_db_path=self.audit_db,
            config_paths=[self.policy_file, self.trust_file],
        )
        return await hunter.run_full_scan()

    async def probe(self, target: str | None = None, probe_types: list[str] | None = None) -> Any:
        """Adversarial red team probe — 5 probe types (T27)."""
        from aiglos_probe import ProbeEngine
        engine = ProbeEngine(audit_db=self.audit_db)
        if target:
            return [await engine.probe_server(target, probe_types)]
        return await engine.probe_all(probe_types)

    async def compliance_report(self, org_name: str = "Your Organization") -> dict:
        """CMMC Level 2 + NDAA §1513 compliance report (T18, T28)."""
        from aiglos_core.compliance import build_compliance_report
        from aiglos_core.compliance.s1513 import Section1513Mapper
        cmmc = build_compliance_report(audit_db=self.audit_db, org_name=org_name)
        s1513 = Section1513Mapper(audit_db=self.audit_db).build_report()
        return {"cmmc": cmmc, "s1513": s1513}

    async def intel_refresh(self) -> Any:
        """Refresh threat intelligence — NVD, community, SCA, registry (T22/T30)."""
        from aiglos_core.autonomous.intel import ThreatIntelligence
        intel = ThreatIntelligence(audit_db=self.audit_db, trust_file=self.trust_file)
        return await intel.refresh()

    async def evaluate_tool_call(self, session_id: str, tool_name: str, arguments: dict) -> dict:
        """Real-time proxy evaluation of a single tool call (T1, T2, T5)."""
        from aiglos_core.proxy import AiglosProxy
        proxy = AiglosProxy(
            audit_db=self.audit_db,
            policy_file=self.policy_file,
            trust_file=self.trust_file,
        )
        return await proxy.evaluate(session_id, tool_name, arguments)

    async def analyze_session(self, session_id: str, registered_tools: list[dict],
                               authorized_goal: str = "") -> Any:
        """Static composition analysis at session start — 10 rules (T32)."""
        from aiglos_core.autonomous.composer import SkillComposer
        return await SkillComposer(audit_db=self.audit_db).analyze_session(
            session_id, registered_tools, authorized_goal
        )

    async def issue_identity_token(self, session_id: str, model_id: str,
                                    authorized_capabilities: set[str] | None = None,
                                    goal_hash: str = "") -> Any:
        """Issue Aiglos Identity Token for cross-vendor pipelines (T33)."""
        from aiglos_core.proxy.identity_bridge import AgentIdentityBridge
        return await AgentIdentityBridge(audit_db=self.audit_db).issue_token(
            session_id=session_id, model_id=model_id,
            authorized_capabilities=authorized_capabilities, goal_hash=goal_hash,
        )

    async def scan_rag(self, memory_paths: list[str] | None = None) -> Any:
        """Autonomous scan of RAG knowledge bases and memory stores (T31)."""
        from aiglos_core.autonomous.rag import RAGPoisonDetector
        return await RAGPoisonDetector(audit_db=self.audit_db, memory_paths=memory_paths).scan()

    async def daemon(self, interval_seconds: int = 300) -> None:
        """Start continuous monitoring daemon (T23). Blocks forever."""
        from aiglos_core.autonomous.engine import AutonomousEngine
        await AutonomousEngine(
            audit_db=self.audit_db,
            policy_file=self.policy_file,
            trust_file=self.trust_file,
            interval_seconds=interval_seconds,
        ).run()

    async def status(self) -> dict:
        """Runtime health summary."""
        import sqlite3
        result: dict[str, Any] = {
            "modules_available": sum(1 for t, (p, c, _) in MODULE_MAP.items() if _try_import(p, c)),
            "modules_total": len(MODULE_MAP),
            "audit_db": self.audit_db,
            "recent_events": 0,
            "recent_findings": 0,
            "cmmc_score_pct": None,
            "s1513_score_pct": None,
        }
        try:
            conn = sqlite3.connect(self.audit_db)
            cutoff = __import__("time").time() - 86400
            result["recent_events"] = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE timestamp > ?", (cutoff,)
            ).fetchone()[0]
            result["recent_findings"] = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE severity IN ('critical','high') "
                "AND timestamp > ?", (cutoff,)
            ).fetchone()[0]
            conn.close()
        except Exception:
            pass
        try:
            from aiglos_core.compliance import build_compliance_report
            result["cmmc_score_pct"] = getattr(
                build_compliance_report(audit_db=self.audit_db), "score_pct", None
            )
        except Exception:
            pass
        try:
            from aiglos_core.compliance.s1513 import Section1513Mapper
            result["s1513_score_pct"] = getattr(
                Section1513Mapper(audit_db=self.audit_db).build_report(), "score_pct", None
            )
        except Exception:
            pass
        return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="aiglos",
        description="Aiglos — Autonomous AI Agent Security Runtime (T1-T33)",
    )
    parser.add_argument("--db", default="aiglos_audit.db")
    parser.add_argument("--policy", default="aiglos_policy.yaml")
    parser.add_argument("--trust", default="aiglos_trust.yaml")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("modules", help="Check all 22 modules").add_argument("--json", action="store_true")
    sub.add_parser("scan", help="Full autonomous threat scan")

    p_probe = sub.add_parser("probe", help="Red team adversarial probe")
    p_probe.add_argument("--target")
    p_probe.add_argument("--probes", nargs="+",
        choices=["tool_injection","path_traversal","cmd_injection","oauth_escalation","tool_redefinition"])
    p_probe.add_argument("--json", action="store_true")

    p_comp = sub.add_parser("compliance", help="CMMC + §1513 report")
    p_comp.add_argument("--org", default="Your Organization")
    p_comp.add_argument("--json", action="store_true")
    p_comp.add_argument("--pdf")

    sub.add_parser("intel", help="Refresh threat intelligence")

    p_rag = sub.add_parser("rag", help="Scan RAG/memory stores")
    p_rag.add_argument("--paths", nargs="+")

    p_daemon = sub.add_parser("daemon", help="Start continuous monitoring daemon")
    p_daemon.add_argument("--interval", type=int, default=300)

    p_status = sub.add_parser("status", help="Runtime status summary")
    p_status.add_argument("--json", action="store_true")

    args = parser.parse_args()
    aiglos = Aiglos(audit_db=args.db, policy_file=args.policy, trust_file=args.trust)

    if args.cmd == "modules":
        results = check_modules(verbose=not getattr(args, "json", False))
        available = sum(results.values())
        if getattr(args, "json", False):
            print(json.dumps({"available": available, "total": len(results), "modules": results}))
        else:
            print(f"\n  {available}/{len(results)} modules available\n")

    elif args.cmd == "scan":
        print("  Running full autonomous scan (8 hunt modules)...")
        result = await aiglos.scan()
        findings = getattr(result, "findings", []) or []
        print(f"  Scan complete. {len(findings)} finding(s).")
        for f in findings[:10]:
            print(f"    [{getattr(f,'severity','?').upper()}] {getattr(f,'title',str(f))}")

    elif args.cmd == "probe":
        print("  Running red team probe...")
        reports = await aiglos.probe(target=getattr(args,"target",None), probe_types=getattr(args,"probes",None))
        if getattr(args, "json", False):
            print(json.dumps([r.__dict__ if hasattr(r,"__dict__") else str(r) for r in (reports or [])], indent=2, default=str))
        else:
            for r in (reports or []):
                print(f"  Server: {getattr(r,'server_id','?')}")
                for f in getattr(r, "findings", []):
                    print(f"    [{getattr(f,'verdict','?')}] {getattr(f,'probe_type','?')}")

    elif args.cmd == "compliance":
        print("  Generating compliance report...")
        report = await aiglos.compliance_report(org_name=args.org)
        cmmc, s1513 = report.get("cmmc"), report.get("s1513")
        if getattr(args, "json", False):
            print(json.dumps({"cmmc_score": getattr(cmmc,"score_pct",None), "s1513_score": getattr(s1513,"score_pct",None)}, indent=2))
        else:
            print(f"  CMMC Level 2:  {getattr(cmmc,'score_pct','n/a')}%")
            print(f"  NDAA §1513:    {getattr(s1513,'score_pct','n/a')}%")
        if getattr(args, "pdf", None) and cmmc:
            try:
                from aiglos_core.compliance.report_pdf import generate_pdf_report
                generate_pdf_report(cmmc, output_path=args.pdf)
                print(f"  PDF saved: {args.pdf}")
            except Exception as e:
                print(f"  PDF generation failed: {e}")

    elif args.cmd == "intel":
        print("  Refreshing threat intelligence...")
        result = await aiglos.intel_refresh()
        sources = getattr(result, "sources_checked", [])
        print(f"  Done. Sources: {', '.join(sources) if sources else 'n/a'}")

    elif args.cmd == "rag":
        print("  Scanning RAG/memory stores...")
        findings = await aiglos.scan_rag(memory_paths=getattr(args,"paths",None))
        print(f"  RAG scan complete. {len(findings)} finding(s).")
        for f in findings:
            print(f"    [{getattr(f,'severity','?').upper()}] {getattr(f,'title',str(f))}")

    elif args.cmd == "daemon":
        print(f"  Starting Aiglos daemon (interval: {args.interval}s). Ctrl+C to stop.")
        await aiglos.daemon(interval_seconds=args.interval)

    elif args.cmd == "status":
        s = await aiglos.status()
        if getattr(args, "json", False):
            print(json.dumps(s, indent=2))
        else:
            print(f"\n  Aiglos Runtime Status")
            print(f"  {'─'*33}")
            print(f"  Modules:        {s['modules_available']}/{s['modules_total']} available")
            print(f"  Audit DB:       {s['audit_db']}")
            print(f"  Events (24h):   {s['recent_events']}")
            print(f"  Findings (24h): {s['recent_findings']}")
            if s["cmmc_score_pct"] is not None:
                print(f"  CMMC score:     {s['cmmc_score_pct']:.0f}%")
            if s["s1513_score_pct"] is not None:
                print(f"  §1513 score:    {s['s1513_score_pct']:.0f}%")
            print()

    else:
        parser.print_help()
        print("\n  Run 'python aiglos.py modules' to verify installation.\n")


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("\n  Aiglos stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
