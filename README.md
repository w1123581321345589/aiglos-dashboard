# Aiglos

**Autonomous AI Agent Security Runtime — T1 through T33**

Aiglos is a full-stack security runtime for AI agents and multi-agent systems. It sits between any AI agent and the MCP servers it connects to, enforcing security policy at every tool call while running a continuous autonomous threat hunting engine in the background. It covers the complete attack surface: real-time proxy interception, semantic goal integrity, behavioral baseline fingerprinting, OPA policy enforcement, autonomous threat hunting across 8 modules, CMMC/§1513 compliance reporting, public registry monitoring, RAG/memory poison detection, skill composition analysis, and cryptographic cross-vendor agent identity.

**528 tests passing across 14 test files. Zero external runtime dependencies for core detection.**

-----

## The Problem

AI agents have no security layer. They accept tool calls from any server, execute instructions from any document they read, and have no mechanism to verify they are still pursuing their authorized objective. Traditional security tools operate at the network or identity layer — they are blind to what an agent actually does.

**Five classes of attack no existing tool catches:**

1. **Goal hijacking** — An adversary embeds instructions in a document the agent reads. The agent’s subsequent tool calls are syntactically valid but semantically wrong. Standard tools see nothing. Aiglos detects the semantic drift.
1. **MCP server compromise** — An attacker modifies a legitimate MCP server’s tool definitions to include malicious implementations behind familiar names. The agent’s calls look normal; the execution is not.
1. **Credential exfiltration via agent** — An agent with filesystem access reads a `.env` or `.ssh/id_rsa` and passes the contents as arguments to an outbound HTTP call. Standard DLP tools never see it because it is application-layer JSON, not a file transfer.
1. **A2A orchestrator impersonation** — In multi-agent pipelines using Google A2A, AutoGen, CrewAI, or LangGraph, a malicious agent forges an Agent Card and issues instructions to subagents that bypass the MCP proxy entirely. No existing tool covers this attack surface.
1. **RAG/memory poisoning** — A malicious document sits in a shared knowledge base and injects instructions into every agent session that retrieves it, invisibly, permanently, across all users. The attack happens at write time and fires at every retrieval. No prompt injection scanner catches it.

-----

## Architecture: Eight Security Layers

```
LAYER 0  Core Types & Audit      T3
LAYER 1  Real-Time Proxy         T1  T2  T4  T5  T7  T8  T11  T15  T25  T33
LAYER 2  Semantic Intelligence   T6  T9
LAYER 3  Compliance              T18  T19  T28
LAYER 4  Autonomous Hunt         T21  T22  T23  T24  T26  T29  T32
LAYER 5  Registry Intelligence   T30
LAYER 6  Memory Security         T31
LAYER 7  Red Team                T27
```

### Data Flow

```
MCP Client
    |
    v
[T1 Proxy] ──> [T2 Trust Scorer]
    |               |
    |           [T6 Goal Integrity]  ─── fast path (rule, <1ms)
    |           [T9 Behavioral]      ─── statistical baseline
    |               |
    |           [T5 Policy Engine]  ─── YAML rules
    |           [T11 OPA Engine]    ─── Rego stateful rules
    |               |
    |           BLOCK / ALLOW / REQUIRE_APPROVAL
    |
    |──> [T4 Config Scanner]    misconfig at session start
    |──> [T7 Attestation]       RSA-2048 signed session record
    |──> [T15 Alert Dispatch]   Slack / Splunk / Syslog / webhook
    |──> [T25 OAuth Guard]      confused deputy, scope escalation
    |──> [T33 Identity Bridge]  cross-vendor AIT token
    |
    v
[T3 Audit DB]  ←──────────────────────────────────────────────┐
    |                                                           |
    v                                                           |
[T23 Autonomous Engine]                                         |
    |                                                           |
    |──> [T22 Threat Intel] ──> [T26 SCA] ──> [T30 Registry]  |
    |                                                           |
    └──> [T21 ThreatHunter]  ── 8 modules, every 5 min ───────┘
             |
             ├── (1) exposure          config exposure via T4
             ├── (2) credential_scan   secrets in tool call history
             ├── (3) injection_hunt    injection in tool results
             ├── (4) behavioral_trend  baseline deviation via T6/T9
             ├── (5) policy_trend      repeated rule violations
             ├── (6) sampling_monitor  T24 MCP sampling 3-vector
             ├── (7) a2a_monitor       T29 Google A2A / AutoGen
             └── (8) composition_scan  T32 dangerous tool combos

Multi-agent / cross-vendor:
[T8 Trust Fabric]   ──  Aiglos-to-Aiglos attestation chain
[T29 A2A Monitor]   ──  Google A2A / AutoGen / CrewAI / LangGraph
[T33 Identity]      ──  AIT tokens across Claude / GPT-4 / Gemini / Llama

Session start (static):
[T32 Composer]  ──  composition analysis  ──  BLOCK / WARN / ALLOW

Memory:
[T31 RAG Detector]  ──  write-time / retrieval-time / background scan
```

-----

## Installation

```bash
pip install -e .
```

Requires Python 3.11+. The primary CLI (`aiglos proxy`, `aiglos report`, etc.) installs as `aiglos` via the entry point in `pyproject.toml`. The drop-in manifest (`aiglos.py`) works standalone without installation.

-----

## Quickstart

### CLI (installed)

```bash
aiglos proxy                        # Start the MCP security proxy
aiglos scan                         # Scan config for misconfigurations
aiglos sessions                     # List agent sessions with integrity scores
aiglos logs                         # View recent audit events
aiglos tail                         # Live tail security events
aiglos report --level 2             # CMMC Level 2 compliance report
aiglos report-pdf --org "Acme"      # PDF report for C3PAO submission
aiglos attest --session SESSION_ID  # Produce signed attestation document
aiglos verify SESSION_ID.json       # Verify an attestation document
aiglos trust list                   # List trust registry entries
aiglos trust allow HOST:PORT        # Allow an MCP server
aiglos trust block HOST:PORT        # Block an MCP server
aiglos probe                        # Red team adversarial self-test
aiglos s1513                        # NDAA §1513 readiness report
aiglos daemon start                 # Start continuous monitoring daemon
aiglos daemon status                # Show daemon state
aiglos daemon scan                  # Force immediate hunt cycle
aiglos daemon intel                 # Force immediate intel refresh
```

### Drop-in manifest (no install required)

```bash
python aiglos.py modules       # Check all modules (✅/❌)
python aiglos.py scan          # Full autonomous hunt
python aiglos.py probe         # Red team probe
python aiglos.py compliance    # CMMC + §1513 report
python aiglos.py intel         # Refresh threat intelligence
python aiglos.py rag           # Scan RAG/memory paths
python aiglos.py daemon        # Continuous monitoring
python aiglos.py status        # Runtime status
```

### Programmatic

```python
from aiglos import Aiglos

aiglos = Aiglos()

# Full threat hunt
result = await aiglos.scan()

# Pre-session composition check
result = await aiglos.analyze_session(
    session_id="sess-abc",
    registered_tools=my_tools,
    authorized_goal="Summarize the weekly sales report",
)
if result.risk_level == "critical":
    raise SecurityError(result.summary())

# Issue cross-vendor identity token
token = await aiglos.issue_identity_token(
    session_id="sess-abc",
    model_id="claude-opus-4-6",
    authorized_capabilities={"read_fs", "web_search"},
)

# Map to OpenID for Agents / Okta machine identity
from aiglos_core.proxy.identity_bridge import AgentIdentityBridge
claims = AgentIdentityBridge().to_openid_agents_claims(token)

# RAG write-time check
from aiglos_core.autonomous.rag import RAGPoisonDetector
verdict = await RAGPoisonDetector().scan_document(content=doc, source="uploads/brief.pdf")
```

-----

## Module Reference

### Layer 0 — Core

**T3 — Audit Log** `aiglos_core/audit/__init__.py`
SQLite audit log in WAL mode. Schema: `security_events`, `tool_calls`, `attestations`, `trust_scores`. Shared read/write substrate for all other modules. Also `aiglos_core/types.py` — shared dataclasses: `SecurityEvent`, `EventType`, `Severity`, `ToolCall`.
CMMC: 3.3.1, 3.3.2

-----

### Layer 1 — Real-Time Proxy

Every tool call passes through this pipeline before it reaches the MCP server.

**T1 — MCP Proxy** `aiglos_core/proxy/__init__.py`
WebSocket proxy. Intercepts all MCP tool calls before execution. Pipeline per call: trust scoring (T2), goal integrity (T6), behavioral check (T9), policy evaluation (T5/T11), attestation (T7), alert dispatch (T15). Inline credential scanner catches 20+ secret patterns (AWS keys, Anthropic keys, GitHub tokens, JWTs, high-entropy strings) in tool arguments before they reach the server. Blocks or allows within the same request/response cycle.
CMMC: 3.14.2, 3.13.1, 3.1.1

**T2 — Trust Scorer** `aiglos_core/proxy/trust.py`
Per-session behavioral trust scoring (0.0–1.0). Signals: call velocity, scope creep, anomaly delta, known-bad patterns. Score drives DENY/REQUIRE_APPROVAL thresholds in T5/T11 and feeds behavioral trend detection in T21.
CMMC: 3.14.2

**T4 — Config Scanner** `aiglos_core/scanner/config_scanner.py`
The original Aiglos scanner. Audits MCP server and agent config files for security misconfigurations: gateway binding to 0.0.0.0, missing authentication, plaintext credentials, file permission exposure, missing TLS, overly permissive tool grants, missing rate limiting, exposed logs, default port usage. Runs at session start and as Hunt Module 1 in T21.

**T5 — YAML Policy Engine** `aiglos_core/policy/__init__.py`
Human-readable YAML policy engine evaluated at proxy intercept. ALLOW/DENY/REQUIRE_APPROVAL/LOG rules match on tool name, argument patterns (glob), session ID, trust score range, and time of day. Hot-reload without restart. Shipped with a defense profile default.
CMMC: 3.1.1, 3.1.2

**T7 — Agent Identity Attestation** `aiglos_core/intelligence/attestation.py`
RSA-2048 session attestation. Keypair generated on first run (`~/.aiglos/keys/`). Each session produces a signed, tamper-evident JSON document: model identity, system prompt hash, tool permission grant, session initiator, timeline, security posture at close (integrity score, anomaly score, blocked call counts), per-event SHA-256 manifest. Verifiable offline with `aiglos verify`.
CMMC: 3.5.1, 3.13.8

**T8 — Multi-Agent Trust Fabric** `aiglos_core/proxy/trust_fabric.py`
Cryptographic attestation chain for orchestrator/subagent architectures. Token-based delegation: the orchestrator’s session token authorizes subagent sessions with explicit scope. Subagents cannot self-escalate. Integrity propagates — if a subagent is compromised, the chain reflects it.
CMMC: 3.5.1, 3.5.3, 3.13.8

**T11 — OPA Policy Engine** `aiglos_core/policy/opa.py`
Open Policy Agent integration for stateful, context-aware policies the YAML engine cannot express. Rego policies reason across the full session call history: e.g., “block bash if the session has already called read_file on a `.env` path and the current goal does not include ‘network’.” Two modes: OPA server (production) and embedded in-process fallback. Falls back to T5 YAML engine if OPA is unavailable.
CMMC: 3.1.1, 3.1.2, 3.13.1

**T15 — Alert Dispatcher** `aiglos_core/integrations/__init__.py`
Fan-out to Splunk HEC, Syslog CEF (QRadar/ArcSight/Sentinel), Slack webhook, generic webhook (PagerDuty/Opsgenie), Microsoft Teams, and file JSONL sink. Per-destination severity threshold and rate limiting. Fires on CRITICAL and HIGH events by default.
CMMC: 3.14.6

**T25 — OAuth Confused Deputy Detector** `aiglos_core/proxy/oauth.py`
Real-time hook blocks: token reuse across identities, broad OAuth scopes (`files:*`, `db:*`, `admin:*`), scope escalation attempts, OAuth tokens appearing in tool call arguments. Autonomous scan detects: CVE-2025-6514 (mcp-remote 0.0.5–0.1.15), static client IDs shared across sessions, authorization code reuse. Maps automatically to CMMC 3.5.x controls.
CMMC: 3.5.1, 3.5.2, 3.13.10

**T33 — Cross-Vendor Agent Identity Bridge** `aiglos_core/proxy/identity_bridge.py`
Issues signed Aiglos Identity Tokens (AIT) that travel with agents across multi-vendor pipelines (Claude / GPT-4 / Gemini / Llama / Mistral). Vendor auto-detected from model ID. Cryptographic delegation chains enforce strict capability subsetting — child agents can never exceed parent scope. `to_openid_agents_claims()` maps AIT fields directly to the OpenID for Agents / OAuth 2.0 spec — the integration surface for Okta machine identity. `from_openid_agents_claims()` parses inbound tokens from external issuers.

```python
bridge = AgentIdentityBridge()

# Issue at session start
token = await bridge.issue_token("sess-abc", "claude-opus-4-6", {"read_fs", "web_search"})

# Delegate to subagent — strict capability subset
child = await bridge.delegate(token, "gpt-4o-sub", {"web_search"})

# Verify inbound token
verdict = await bridge.verify_token(token_str=incoming_ait)
# verdict.trust_level: "aiglos-signed" | "unattested" | "invalid"

# Okta / OpenID for Agents format
claims = bridge.to_openid_agents_claims(token)
ait = bridge.from_openid_agents_claims(claims)

# Compact transport (base64url for HTTP headers)
compact = bridge.to_compact(token)
token = bridge.from_compact(compact)
```

CMMC: 3.5.1, 3.5.3, 3.13.8

-----

### Layer 2 — Semantic Intelligence

These two modules are the deepest defensible IP in the stack. They operate at the semantic and behavioral layers, catching attacks that look syntactically valid to every other module.

**T6 — Goal Integrity Engine** `aiglos_core/intelligence/__init__.py`
The single most defensible piece of IP in the platform. At session start, the authorized goal is registered and hashed. On every tool call, two evaluation paths run in parallel:

**Fast path** (rule-based, zero latency):

- Tool call sequence pattern matching against known hijack signatures
- Goal keyword drift detection — are goal-relevant terms disappearing from arguments?
- Sudden domain shift — agent was editing Python, now calling curl
- Suspicious tool chains — `read_file` → `write_file` → `http_request` in under 3 steps

**Semantic path** (LLM-evaluated, async, triggered on anomaly signal):

- Full tool call history summarized and scored 0.0 (fully drifted) to 1.0 (fully aligned)
- Only triggered when fast path raises a flag, keeping latency impact minimal

When the composite score drops below threshold (default 0.35), a `GOAL_DRIFT` event fires and the proxy halts, alerts, or requires approval. Direct counter to OWASP Agentic Top 10 2026 #1. An adversary’s embedded instructions produce syntactically valid tool calls — only semantic evaluation catches them.
CMMC: 3.14.2, 3.14.7

**T9 — Behavioral Baseline Engine** `aiglos_core/intelligence/baseline.py`
Two-tier behavioral fingerprinting that catches compromised agents without semantic evaluation — faster than T6 because it does not need to understand what the agent is doing, only that it is behaving differently than it usually does.

**Tier 1 — Global baseline:** aggregates across all sessions for a given `(model, goal_hash)` pair. Captures statistical distribution of tool usage, call rates, and sequence patterns across many runs of similar agents. Persists in SQLite and accumulates over time — effective from session 1 once a few baseline sessions exist.

**Tier 2 — Session baseline:** tracks current session behavior in real time against the global baseline and against the session’s own early behavior. Detects sudden mid-session shifts.

Five anomaly signal components (each 0.0–1.0), combined as weighted composite:

|Signal                   |Method                     |Weight|
|-------------------------|---------------------------|------|
|Tool distribution anomaly|Jensen-Shannon divergence  |0.25  |
|Call rate anomaly        |Welford’s online algorithm |0.20  |
|Sequence pattern anomaly |Bigram transition deviation|0.30  |
|Novel tool introduction  |Unknown tool penalty       |0.15  |
|Argument volume anomaly  |Running mean/variance      |0.10  |

CMMC: 3.14.2, 3.14.7

-----

### Layer 3 — Compliance

**T18 — CMMC Compliance Mapper** `aiglos_core/compliance/__init__.py`
Maps every audit DB event to NIST SP 800-171 Rev 2 controls across all 14 CMMC Level 2 families. Control-by-control readiness scores, evidence citations, and remediation priorities. Produces `ComplianceReport` objects consumed by T19.
CMMC: all 110 controls

**T19 — PDF Report Generator** `aiglos_core/compliance/report_pdf.py` + `pdf_report.py`
Produces multi-page, C3PAO-ready compliance reports in PDF format. Cover page (org, date, CMMC level, overall score), per-domain control coverage tables, evidence citations, remediation roadmap. One command from CLI: `aiglos report-pdf --org "Org Name"`.

**T28 — NDAA §1513 Compliance Mapper** `aiglos_core/compliance/s1513.py`
18 controls across 6 domains mapped to DoD’s FY2026 AI/ML cybersecurity framework mandate. Domains: Model Integrity, Runtime Monitoring, Access Control, Audit Trail, Anomaly Detection, Incident Response. Generates a sidecar JSON artifact alongside the CMMC PDF. DoD status report due June 16, 2026.

```bash
aiglos s1513 --pdf s1513_report.pdf
python aiglos.py compliance --org "Org Name" --pdf report.pdf --json
```

-----

### Layer 4 — Autonomous Threat Hunting

**T23 — Autonomous Engine** `aiglos_core/autonomous/engine.py`
Command Center orchestrator. Priority task queue: CRITICAL (0) > HIGH (1) > NORMAL (2) > LOW (3). Per-task retry (2 attempts) and configurable timeout. State persistence to `aiglos_engine_state.json`. Schedules: hunt every 5 min, intel refresh every 1 hour, compliance report every 24 hours. Watchdog loop detects engine interference and escalates to CRITICAL.

**T21 — ThreatHunter** `aiglos_core/autonomous/hunter.py`
Orchestrates 8 hunt modules against the audit DB. Runs on the T23 schedule or on-demand. Results persisted back to the audit DB as `ANOMALY_DETECTED` events, which feed T15 alerts and compliance scoring.

```python
result = await ThreatHunter(audit_db_path="aiglos_audit.db").run_full_scan()
print(result.critical_count, result.findings)
```

|#|Module            |What it hunts                                                                    |Source  |
|-|------------------|---------------------------------------------------------------------------------|--------|
|1|`exposure`        |Config files: 0.0.0.0 binding, missing auth, inline creds, permissive tool grants|T4      |
|2|`credential_scan` |API keys, tokens, AWS keys in historical tool call arguments                     |built-in|
|3|`injection_hunt`  |Prompt injection patterns in historical tool call results                        |built-in|
|4|`behavioral_trend`|Sessions with goal_integrity_score < 0.4; escalating drift                       |T6/T9   |
|5|`policy_trend`    |Repeated violations of the same rule across sessions (probing pattern)           |built-in|
|6|`sampling_monitor`|MCP sampling 3-vector: injection, covert invocation, resource theft              |T24     |
|7|`a2a_monitor`     |A2A orchestrator impersonation, artifact injection, capability escalation        |T29     |
|8|`composition_scan`|Dangerous tool combinations before session runs                                  |T32     |

**T22 — Threat Intelligence** `aiglos_core/autonomous/intel.py`
Refresh cycle pulls from NVD API, curated community MCP threat patterns (known malicious server fingerprints), local SCA scan (T26), and live registry scan (T30). Auto-updates `aiglos_policy.yaml` with new block/alert rules and `aiglos_trust.yaml` with new blocked server hashes.

**T24 — MCP Sampling Monitor** `aiglos_core/autonomous/sampler.py`
Detects the three-vector MCP sampling channel attack documented by Unit 42 (December 2025):

- **Persistent instruction injection** — malicious instructions embedded in sampling responses
- **Covert tool invocation** — subprocess/file/network patterns in sampling-initiated calls
- **Resource theft** — anomalous token consumption exceeding 5x session baseline

CMMC: 3.14.2, 3.13.1, 3.1.1

**T26 — Supply Chain Scanner** `aiglos_core/autonomous/sca.py`
Scans package manifests (`package.json`, `smithery.yaml`, `pyproject.toml`) for: known-malicious packages (`postmark-mcp-server`, `mcp-postmark`), typosquatting (Levenshtein distance ≤2 from known-good packages), vulnerable versions (CVE-2025-6514, CVE-2025-68143, CVE-2026-22807, CVE-2026-23947), inline credentials, overly broad tool permission grants. Wired into T22 intel refresh cycle — runs on every intel update and auto-updates `aiglos_trust.yaml` blocked_packages list.
CMMC: 3.14.2, 3.14.1

**T29 — A2A Protocol Monitor** `aiglos_core/autonomous/a2a.py`
First security tooling purpose-built for Google’s Agent-to-Agent (A2A) protocol (published April 2025). Covers multi-agent frameworks: AutoGen, CrewAI, LangGraph, OpenAI Swarm. Three detection vectors:

**Orchestrator impersonation** — Agent Card fingerprint registry. If an orchestrator’s Card changes between calls, the session is blocked as a probable impersonation.

**Artifact injection** — Scans all A2A task payloads and Part objects for indirect prompt injection patterns before forwarding to subagents. Catches the A2A-layer equivalent of MCP tool description injection.

**Capability escalation** — Blocks subagent task dispatches requesting high-risk capabilities (`file_system_write`, `shell_execution`, `code_execution`, `network_egress`, `credential_access`) without an explicit Aiglos delegation token from T33.

```python
monitor = A2AMonitor(audit_db="aiglos_audit.db")
monitor.register_agent("orch-001", trusted_card, allowed_capabilities={"read_fs"})

verdict = await monitor.evaluate(A2AEvent(
    orchestrator_id="orch-001",
    target_agent_id="sub-001",
    task_type="research",
    payload=task_dict,
    agent_card=card_dict,
))
# verdict.blocked == True → event persisted to audit DB, alert dispatched
```

CMMC: 3.5.1, 3.5.3, 3.13.8, 3.14.2

**T32 — Skill Composition Analyzer** `aiglos_core/autonomous/composer.py`
Static analysis of all registered tool combinations at session start — before any tool executes. Individual tools can each be benign while their combination creates a dangerous capability. Goal-context suppression reduces false positives: if the authorized goal explicitly mentions the combination (e.g., “email the report”), the matching rule is suppressed.

10 composition rules:

|Rule  |Capabilities                          |Threat                          |
|------|--------------------------------------|--------------------------------|
|CR-001|`read_fs` + `network_egress`          |Filesystem Exfiltration Pipeline|
|CR-002|`read_fs` + `email_send`              |Email Exfiltration Pipeline     |
|CR-003|`execute_code` + `network_egress`     |RCE with Command-and-Control    |
|CR-004|`memory_read` + `write_fs`            |Cross-Session Memory Harvesting |
|CR-005|`git_write` + `network_egress`        |Source Code Exfiltration        |
|CR-006|`credential_access` + `network_egress`|Credential Exfiltration         |
|CR-007|`spawn_agent` + `credential_access`   |Agentic Escalation Chain        |
|CR-008|`database_read` + `network_egress`    |Database Exfiltration Pipeline  |
|CR-009|`clipboard` + `network_egress`        |PII Harvesting Pipeline         |
|CR-010|`browser` + `memory_write`            |Browser Session Hijacking       |

```python
result = await SkillComposer().analyze_session(
    session_id="sess-123",
    registered_tools=tool_list,
    authorized_goal="Email the quarterly report to the finance team",
)
# CR-002 suppressed because goal explicitly mentions email
# result.risk_level: "critical" | "high" | "medium" | "clean"
```

CMMC: 3.1.1, 3.13.1, 3.14.2

-----

### Layer 5 — Registry Intelligence

**T30 — Registry Monitor** `aiglos_core/autonomous/registry.py`
Continuous monitoring of npm, Smithery, mcp.so, and PyPI for newly published malicious MCP packages — proactive detection before installation. Scores each package on 8 signals:

- Name match against known-malicious list
- Typosquatting (Levenshtein distance ≤2 from known-good packages)
- Social engineering language in README/description
- Tool injection patterns in package metadata
- High-risk permissions declared in `smithery.yaml` or `package.json`
- Publisher account age < 30 days
- Abnormal download spike vs historical baseline
- Known-malicious transitive dependencies

Live npm feed scan runs on every T22 intel refresh. Critical findings automatically update the `aiglos_trust.yaml` blocked_packages list before any human intervenes.

```python
score = await RegistryMonitor().score_package("postmark-mcp-server")
# score.risk_level == "critical"
# score.signals == ["Known-malicious package name: postmark-mcp-server"]
```

CMMC: 3.14.2, 3.14.1

-----

### Layer 6 — Memory Security

**T31 — RAG / Memory Poison Detector** `aiglos_core/autonomous/rag.py`
Why this is architecturally distinct from prompt injection detection: the MCP proxy catches injection at tool-call time. RAG/memory poisoning happens at write time and executes silently at every subsequent retrieval. A single poisoned document in a shared vector store injects its instructions into every agent session that retrieves it — across all users, indefinitely, without triggering any runtime scanner.

Four scan modes:

**Write-time** — scans documents before embedding into the knowledge base:

```python
verdict = await detector.scan_document(content=doc_text, source="uploads/brief.pdf")
if not verdict.safe:
    raise SecurityError(verdict.reason)
```

**Memory write** — scans before persisting to Mem0/Zep/Letta. Always uses strict mode because poisoned memories persist across all future sessions:

```python
verdict = await detector.scan_memory_write(
    content=memory_text, memory_key="pref_001", session_id="sess-abc"
)
```

**Retrieval-time** — filters poisoned chunks before injecting into the context window:

```python
safe_chunks = await detector.filter_chunks(chunks=retrieved_chunks, session_id="sess-abc")
```

**Cross-session PII leakage** — blocks one user’s personal data from leaking into another’s context via over-broad semantic search:

```python
clean = await detector.check_cross_session_leakage(chunks, current_session, owner_session)
```

**Autonomous background scan** — scans all configured memory paths (`./memory/`, `./knowledge_base/`, `./rag_data/`, `./embeddings/`, `./vector_store/`, `./mem0/`, `./zep/`).

Two detection tiers: T1 patterns (hard injection — `ignore all previous instructions`, system tags, zero-width steganography) block immediately. T2 patterns (suspicious — `please disregard`, base64_decode, eval/exec, exfil patterns) flag in standard mode, block in strict mode. Memory writes always use strict mode.

CMMC: 3.14.2, 3.13.1, 3.1.3

-----

### Layer 7 — Red Team

**T27 — ProbeEngine** `aiglos_probe.py`
Adversarial self-testing with safe payloads only — no live exploits, safe to run in CI/CD. Five probe types:

|Probe              |What it tests                                     |
|-------------------|--------------------------------------------------|
|`tool_injection`   |Prompt injection via tool description manipulation|
|`path_traversal`   |Directory traversal in file tool arguments        |
|`cmd_injection`    |Command injection in shell tool arguments         |
|`oauth_escalation` |OAuth scope escalation via confused deputy        |
|`tool_redefinition`|Tool schema change detection (supply chain signal)|

Returns `VULNERABLE` / `HARDENED` / `INCONCLUSIVE` per probe. `VULNERABLE` findings are persisted to the audit DB and fire T15 alerts. Integrates with CI/CD via exit code.

```bash
aiglos probe
aiglos probe --target localhost:18789 --probes tool_injection path_traversal
aiglos probe --json
```

CMMC: 3.14.2 | §1513: Domain 5.4

-----

## CVE & Threat Coverage

|CVE / Threat           |CVSS|Description                                    |Module  |
|-----------------------|----|-----------------------------------------------|--------|
|CVE-2025-6514          |9.6 |mcp-remote OAuth RCE (0.0.5–0.1.15)            |T25, T26|
|CVE-2025-68143         |—   |mcp-server-git path traversal                  |T26     |
|CVE-2026-22807         |—   |mcp-server-git XSS / command injection         |T26     |
|CVE-2026-23947         |—   |mcp-server-git XSS / deserialization           |T26     |
|Unit 42 (Dec 2025)     |—   |MCP sampling 3-vector attack                   |T24     |
|Postmark impersonation |—   |postmark-mcp-server npm exfil package          |T26, T30|
|Smithery path traversal|—   |smithery.yaml build config arbitrary read      |T26     |
|OWASP Agentic #1       |—   |Goal hijacking / tool description injection    |T6, T27 |
|OWASP Agentic #2       |—   |Tool poisoning via server compromise           |T2, T21 |
|OWASP Agentic #5       |—   |OAuth confused deputy                          |T25     |
|Endor Labs 82%         |—   |Path traversal in MCP implementations          |T27     |
|Google A2A (Apr 2025)  |—   |Orchestrator impersonation / artifact injection|T29     |
|RAG indirect injection |—   |Knowledge base poisoning at scale              |T31     |

-----

## Compliance Coverage

|Framework            |Controls                 |Aiglos Coverage                          |
|---------------------|-------------------------|-----------------------------------------|
|CMMC Level 2         |110 controls, 14 families|Active coverage across all 14 families   |
|NIST SP 800-171 Rev 2|110 controls             |Mapped per audit event                   |
|NDAA FY2026 §1513    |18 controls, 6 domains   |90%+ readiness; report artifact generated|

Report commands:

```bash
aiglos report --level 2 --output cmmc.json
aiglos report-pdf --org "Your Org" --level 2 --output cmmc.pdf
aiglos s1513 --pdf s1513.pdf
```

-----

## Configuration

`aiglos.yaml` (generated by `aiglos init`):

```yaml
proxy:
  listen_port: 8765
  upstream_host: localhost
  upstream_port: 18789
  deployment_tier: cloud         # cloud | on_prem | gov

features:
  goal_integrity: true           # T6 semantic evaluation
  behavioral_baseline: true      # T9 fingerprinting
  credential_scanning: true      # inline in T1
  policy_engine: true            # T5 YAML
  opa_engine: false              # T11 OPA (requires OPA server or embedded)
  trust_registry: true           # T8
  attestation: true              # T7
  oauth_guard: true              # T25
  a2a_monitor: true              # T29
  rag_detector: true             # T31
  registry_monitor: true         # T30
  composition_analyzer: true     # T32

goal_integrity:
  drift_threshold: 0.35          # GOAL_DRIFT fires below this

trust:
  mode: audit                    # strict | audit | permissive
  file: aiglos_trust.yaml

alerts:
  slack:
    webhook_url: https://hooks.slack.com/...
    min_severity: high
  splunk:
    hec_url: https://splunk.example.com:8088/services/collector
    hec_token: YOUR_HEC_TOKEN
    min_severity: info
  file_sink:
    path: aiglos_events.jsonl

opa:
  server_url: http://localhost:8181
  timeout_ms: 50
  fallback_to_yaml: true

a2a:
  registered_agents_file: aiglos_agents.yaml

rag:
  memory_paths:
    - ./memory/
    - ./knowledge_base/
    - ./rag_data/
  strict_mode: false             # true blocks T2 patterns at write time

autonomous:
  scan_interval_seconds: 300
  intel_interval_seconds: 3600
  report_interval_seconds: 86400
```

Trust registry (`aiglos_trust.yaml`):

```yaml
allowed_servers:
  - address: localhost:18789
    alias: dev-server
    fingerprint: sha256:abc123...

blocked_packages:
  - postmark-mcp-server
  - mcp-postmark

blocked_servers: []
```

-----

## Deployment

**Standard (pip installed)**

```bash
pip install -e .
aiglos init
aiglos proxy
# Point your MCP client to localhost:8765 instead of :18789
```

**Drop-in (no install)**

```bash
# Copy aiglos.py into your project root
python aiglos.py modules    # verify all modules load
python aiglos.py daemon     # start monitoring
```

**Docker**

```bash
docker run -p 8765:8765 \
  -e UPSTREAM_HOST=your-mcp-server \
  -e UPSTREAM_PORT=18789 \
  aiglos/aiglos:latest
```

**Air-gapped / gov**

```bash
export AIGLOS_SIGNING_KEY="$(cat /path/to/private_key.pem)"
aiglos proxy --tier gov
```

Deployment tiers:

|Tier     |Target                     |CMMC Level|
|---------|---------------------------|----------|
|`cloud`  |SaaS, commercial           |L1/L2     |
|`on_prem`|Enterprise, air-gap capable|L3        |
|`gov`    |FedRAMP, IL4/IL5           |L3+ STIG  |

-----

## Repository Structure

```
aiglos/
│
├── aiglos.py                          Drop-in manifest — module map, CLI, Aiglos facade
├── aiglos_autonomous.py               Standalone autonomous engine entry point
├── aiglos_probe.py                    Red team probe entry point (T27)
├── pyproject.toml                     PyPI packaging + entry points
├── Dockerfile                         Multi-stage production image
├── docker-compose.yml
│
├── aiglos_cli/
│   └── main.py                        Installed CLI (proxy, scan, logs, tail, sessions,
│                                      report, report-pdf, attest, verify, trust, alerts,
│                                      probe, s1513, daemon, init)
│
├── aiglos_core/
│   ├── types.py                       Shared dataclasses: SecurityEvent, EventType, Severity
│   │
│   ├── audit/
│   │   └── __init__.py                SQLite audit log — WAL mode (T3)
│   │
│   ├── scanner/
│   │   └── config_scanner.py          Config file security scanner (T4)
│   │
│   ├── proxy/
│   │   ├── __init__.py                MCP WebSocket proxy + credential scan (T1)
│   │   ├── trust.py                   Per-session trust scorer (T2)
│   │   ├── trust_fabric.py            Multi-agent trust chain (T8)
│   │   ├── oauth.py                   OAuth confused deputy detector (T25)
│   │   └── identity_bridge.py         Cross-vendor AIT tokens / OpenID for Agents (T33)
│   │
│   ├── intelligence/
│   │   ├── __init__.py                Goal Integrity Engine — semantic drift (T6)
│   │   ├── attestation.py             RSA-2048 session attestation (T7)
│   │   └── baseline.py                Behavioral Baseline Engine (T9)
│   │
│   ├── policy/
│   │   ├── __init__.py                YAML policy engine (T5)
│   │   └── opa.py                     OPA / Rego stateful policy engine (T11)
│   │
│   ├── integrations/
│   │   └── __init__.py                SIEM + alert dispatcher (T15)
│   │
│   ├── compliance/
│   │   ├── __init__.py                CMMC Level 2 mapper (T18)
│   │   ├── report_pdf.py              PDF report generator (T19)
│   │   ├── pdf_report.py              PDF report generator v1 (T19)
│   │   └── s1513.py                   NDAA §1513 mapper (T28)
│   │
│   └── autonomous/
│       ├── engine.py                  Autonomous engine orchestrator (T23)
│       ├── hunter.py                  ThreatHunter — 8 hunt modules (T21)
│       ├── intel.py                   Threat intelligence refresh (T22)
│       ├── sampler.py                 MCP sampling channel monitor (T24)
│       ├── sca.py                     Supply chain scanner (T26)
│       ├── a2a.py                     A2A protocol monitor (T29)
│       ├── registry.py                Public registry monitor (T30)
│       ├── rag.py                     RAG / memory poison detector (T31)
│       └── composer.py                Skill composition analyzer (T32)
│
└── tests/
    └── unit/                          528 tests across 14 files
        ├── test_core.py               T3 audit log, shared types
        ├── test_trust.py              T2 trust scorer
        ├── test_trust_fabric.py       T8 multi-agent trust chain
        ├── test_attestation.py        T7 session attestation
        ├── test_goal_integrity.py     T6 goal integrity engine
        ├── test_baseline.py           T9 behavioral baseline engine
        ├── test_opa.py                T11 OPA policy engine
        ├── test_integrations.py       T15 alert dispatcher
        ├── test_compliance.py         T18 CMMC mapper
        ├── test_report_pdf.py         T19 PDF generator
        ├── test_autonomous.py         T21/T22/T23 autonomous stack
        ├── test_augmentation.py       T24/T25/T26/T27/T28 (round 1)
        ├── test_t24_t28.py            T24–T28 extended coverage
        └── test_t29_t33.py            T29–T33 agent/skills proliferation
```

-----

## License

Proprietary. Contact [will@aiglos.io](mailto:will@aiglos.io) for licensing.