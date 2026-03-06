# Aiglos

**Autonomous AI Agent Security Runtime**

Aiglos is a full-stack security runtime for AI agents. It sits between any AI agent and the MCP servers it connects to, intercepting every tool call through a layered security pipeline while running a continuous autonomous threat hunting engine in the background. It covers the complete modern agent attack surface: real-time proxy enforcement, semantic goal integrity, behavioral baseline fingerprinting, stateful OPA policy, supply chain scanning, registry monitoring, RAG/memory poison detection, skill composition analysis, and cryptographic identity across multi-vendor agent pipelines.

**528 tests passing. 14 test files. Python 3.11+.**

-----

## The Problem

AI agents have no security layer. They accept tool calls from any server, execute instructions from any document they read, and have no way to verify they are still pursuing their authorized objective. Traditional security tools operate at the network or identity layer and are blind to what an agent actually does.

Five classes of attack no existing tool catches:

**Goal hijacking.** An adversary embeds instructions in a file the agent reads. The agent’s subsequent tool calls are syntactically valid but semantically wrong. Standard tools see nothing suspicious. Aiglos detects the semantic drift in real time.

**MCP server compromise.** An attacker modifies a legitimate MCP server’s tool definitions to hide malicious logic behind familiar names. The agent’s calls look normal. The execution is not.

**Credential exfiltration via agent.** An agent with filesystem access reads a `.env` or `.ssh/id_rsa` and passes the contents as arguments to an outbound HTTP call. Standard DLP tools never see it because it is application-layer JSON, not a file transfer.

**A2A orchestrator impersonation.** In multi-agent pipelines using Google A2A, AutoGen, CrewAI, or LangGraph, a malicious agent forges an Agent Card and issues instructions to subagents that bypass the MCP proxy entirely. No existing tool covers this attack surface.

**RAG and memory poisoning.** A malicious document sits in a shared knowledge base and injects instructions into every agent session that retrieves it — invisibly, permanently, across all users. The attack happens at write time and executes at every retrieval. No prompt injection scanner catches it.

-----

## Architecture

```
LAYER 0   Core                   T3  (audit log, shared types)
LAYER 1   Real-Time Proxy        T1  T2  T4  T5  T6  T7  T8  T9  T11  T15  T25  T33
LAYER 2   Compliance             T18  T19  T28
LAYER 3   Autonomous Hunt        T21  T22  T23  T24  T26  T29  T32
LAYER 4   Registry Intelligence  T30
LAYER 5   Memory Security        T31
LAYER 6   Red Team               T27
```

### Data Flow

```
MCP Client
    |
    v
[T1 Proxy] ─── credential scan (inline, 20+ patterns)
    |           injection detection (inline)
    |           config scan via T4
    |           trust scoring via T2
    |           behavioral baseline via T9
    |           goal integrity via T6
    |           YAML policy via T5
    |           OPA stateful policy via T11
    |           attestation via T7
    |           alert dispatch via T15
    |           OAuth guard via T25
    |
    ├── BLOCK / REQUIRE_APPROVAL / ALLOW
    |
    v
[T3 Audit DB] ←──────────────────────────────────────────┐
    |                                                      |
    v                                                      |
[T23 Autonomous Engine]                                    |
    |                                                      |
    ├── [T22 Threat Intel] ── [T26 SCA] ── [T30 Registry] |
    |                                                      |
    └── [T21 ThreatHunter] (8 modules, every 5 min) ──────┘
            ├── exposure          config misconfigurations via T4
            ├── credential_scan   secrets in tool call history
            ├── injection_hunt    injection patterns in tool results
            ├── behavioral_trend  goal drift and baseline deviation
            ├── policy_trend      repeated rule violations (probing)
            ├── sampling_monitor  MCP sampling 3-vector attack via T24
            ├── a2a_monitor       A2A impersonation/injection via T29
            └── composition_scan  dangerous tool combinations via T32

Multi-agent:
[T8 Trust Fabric]  ── Aiglos-to-Aiglos cryptographic chain
[T29 A2A Monitor]  ── Google A2A / AutoGen / CrewAI / LangGraph
[T33 Identity]     ── AIT tokens across Claude / GPT-4 / Gemini / Llama

Session start (static analysis):
[T32 Composer] ── BLOCK / WARN / ALLOW before any tool executes

Memory writes and retrieval:
[T31 RAG Detector] ── write-time / retrieval-time / background scan
```

> **On T-number sequencing:** The original 22-task build plan used a different numbering scheme. As the architecture evolved, numbers were consolidated and reassigned. The current canonical set is T1–T9, T11, T15, T18–T19, T21–T33. There are no gaps in shipped code — the missing numbers reflect tasks that were merged into larger modules (e.g., the credential scanner and injection detector are inline in T1 rather than separate modules) or renumbered as the design matured.

-----

## Installation

```bash
pip install -e .            # installs the aiglos CLI entry point
```

Or drop `aiglos.py` into any project root for zero-install use:

```bash
python aiglos.py modules    # verify all modules load (✅/❌ per module)
```

Requires Python 3.11+.

-----

## Quickstart

### Installed CLI

```bash
# Core proxy
aiglos proxy                         # start MCP security proxy (default: :8765 → :18789)
aiglos proxy --tier gov              # gov tier: stricter defaults, STIG-aligned
aiglos proxy --no-goal-check         # disable T6 semantic evaluation

# Observability
aiglos sessions                      # list sessions with integrity scores
aiglos logs                          # recent audit events
aiglos tail                          # live tail
aiglos scan                          # config misconfig scan via T4

# Setup
aiglos init                          # generate aiglos.yaml, aiglos_policy.yaml

# Compliance
aiglos report --level 2              # CMMC Level 2 JSON report
aiglos report-pdf --org "Acme"       # C3PAO-ready PDF report
aiglos s1513                         # NDAA §1513 readiness report

# Attestation
aiglos attest --session SESSION_ID   # produce signed attestation document
aiglos verify SESSION_ID.json        # verify attestation offline

# Trust registry
aiglos trust list
aiglos trust allow HOST:PORT --alias dev
aiglos trust block HOST:PORT --reason "known bad"

# Red team
aiglos probe                         # adversarial self-test (all 5 probe types)
aiglos probe --probes tool_injection path_traversal

# Alerts
aiglos alerts                        # show alert destination config

# Daemon
aiglos daemon start                  # start continuous monitoring
aiglos daemon status
aiglos daemon scan                   # force immediate hunt cycle
aiglos daemon intel                  # force immediate intel refresh
```

### Drop-in manifest

```bash
python aiglos.py scan
python aiglos.py probe
python aiglos.py compliance
python aiglos.py intel
python aiglos.py rag --paths ./knowledge_base ./memory
python aiglos.py daemon
python aiglos.py status
python aiglos.py modules
```

### Programmatic

```python
from aiglos import Aiglos

aiglos = Aiglos()

# Full threat hunt
result = await aiglos.scan()

# Pre-session composition check — run before registering tools
result = await aiglos.analyze_session(
    session_id="sess-abc",
    registered_tools=my_tools,
    authorized_goal="Summarize the weekly sales report",
)
if result.risk_level == "critical":
    raise SecurityError(result.summary())

# Cross-vendor identity token
token = await aiglos.issue_identity_token(
    session_id="sess-abc",
    model_id="claude-opus-4-6",
    authorized_capabilities={"read_fs", "web_search"},
)

# RAG write-time poison check
result = await aiglos.scan_rag(paths=["./knowledge_base"])
```

-----

## Module Reference

### T3 — Audit Log and Core Types

**`aiglos_core/audit/__init__.py`** — SQLite audit log in WAL mode. Every tool call, security event, attestation record, and trust score is written here. Schema: `security_events`, `tool_calls`, `attestations`, `trust_scores`. The shared substrate all other modules read and write.

**`aiglos_core/types.py`** — Shared dataclasses used across the entire stack: `SecurityEvent`, `EventType`, `Severity`, `ToolCall`.

CMMC: 3.3.1, 3.3.2

-----

### T1 — MCP Security Proxy

**`aiglos_core/proxy/__init__.py`**

WebSocket proxy. Every message between the MCP client and MCP server passes through this pipeline before being forwarded. Per tool call, in order:

1. Credential scan — 20+ pattern library (AWS keys, Anthropic keys, GitHub tokens, JWTs, high-entropy strings) across all tool arguments
1. Injection detection — command injection, path traversal, prompt injection patterns
1. Config exposure check via T4
1. Trust scoring via T2
1. Behavioral baseline check via T9
1. Goal integrity evaluation via T6
1. YAML policy evaluation via T5
1. OPA stateful policy evaluation via T11
1. Attestation recording via T7
1. Alert dispatch via T15 on CRITICAL/HIGH events

If any step produces a BLOCK decision, the tool call is rejected and an error is returned to the client within the same request/response cycle. Nothing reaches the MCP server.

CMMC: 3.14.2, 3.13.1, 3.1.1

-----

### T2 — Trust Scorer

**`aiglos_core/proxy/trust.py`**

Per-session behavioral trust score from 0.0 to 1.0. Signals: call velocity anomaly, scope creep (tools called outside the session’s declared goal domain), anomaly delta from baseline, and known-bad tool sequence patterns. The score is attached to every audit event and drives DENY/REQUIRE_APPROVAL thresholds in T5 and T11. Also feeds the behavioral_trend hunt module in T21.

CMMC: 3.14.2

-----

### T4 — Config Scanner

**`aiglos_core/scanner/config_scanner.py`**

Audits MCP server and agent config files for security misconfigurations. Checks: gateway binding to 0.0.0.0, missing authentication, plaintext credentials in config, unsafe file permissions, missing TLS, overly permissive tool grants, missing rate limiting, exposed log paths, use of default ports. Runs at session start via `aiglos scan` and as hunt module 1 (exposure) inside T21.

-----

### T5 — YAML Policy Engine

**`aiglos_core/policy/__init__.py`**

Human-readable YAML policy engine evaluated at the proxy intercept point. Rule actions: ALLOW, DENY, REQUIRE_APPROVAL, LOG. Rules match on tool name (glob), argument patterns, session ID, trust score range, and time of day. Hot-reload without proxy restart. Ships with a defense profile default covering the most common dangerous patterns (`sudo`, `rm -rf`, path traversal, outbound HTTP to new domains, and others).

CMMC: 3.1.1, 3.1.2

-----

### T6 — Goal Integrity Engine

**`aiglos_core/intelligence/__init__.py`**

The single most defensible piece of IP in the platform. At session start, the authorized goal is registered and hashed. On every tool call, two evaluation paths run:

**Fast path** (rule-based, sub-millisecond):

- Tool sequence matching against known hijack signatures
- Goal keyword drift — are terms from the original goal disappearing from tool arguments?
- Domain shift — agent was editing Python, now it is calling curl
- Suspicious chains — `read_file` → `write_file` → `http_request` in under three steps

**Semantic path** (LLM-evaluated, async):

- Triggered only when the fast path flags an anomaly, keeping latency impact minimal
- Full tool call history scored 0.0 (fully drifted) to 1.0 (fully aligned) against the original goal

When the composite score drops below threshold (default 0.35), a `GOAL_DRIFT` event fires and the proxy halts, alerts, or requires approval depending on policy. This is the direct counter to OWASP Agentic Top 10 2026 #1. An adversary’s embedded instructions produce syntactically valid tool calls — only semantic evaluation catches them. Enable the semantic path by setting `ANTHROPIC_API_KEY` in the environment.

CMMC: 3.14.2, 3.14.7

-----

### T7 — Agent Identity Attestation

**`aiglos_core/intelligence/attestation.py`**

RSA-2048 session attestation. Keypair generated on first run and stored in `~/.aiglos/keys/`. Each session produces a signed, tamper-evident JSON document containing: model identity, system prompt SHA-256 hash, tool permissions granted, session initiator, start/end timestamps, security posture at close (integrity score, anomaly score, blocked call counts), and a SHA-256 manifest of every security event in order. Verifiable offline with `aiglos verify`. For air-gapped environments, inject the signing key via `AIGLOS_SIGNING_KEY`.

CMMC: 3.5.1, 3.13.8

-----

### T8 — Multi-Agent Trust Fabric

**`aiglos_core/proxy/trust_fabric.py`**

Cryptographic attestation chain for orchestrator/subagent architectures within Aiglos-managed pipelines. Token-based delegation: the orchestrator’s session token authorizes subagent sessions with explicit capability scope. Subagents cannot self-escalate. If a subagent is compromised, the chain reflects it. Extends T7 across multi-session workflows.

CMMC: 3.5.1, 3.5.3, 3.13.8

-----

### T9 — Behavioral Baseline Engine

**`aiglos_core/intelligence/baseline.py`**

Two-tier statistical fingerprinting that catches compromised agents without semantic evaluation — faster than T6 because it does not need to understand what the agent is doing, only that it is behaving differently than usual.

**Tier 1 — Global baseline:** aggregates across all sessions sharing a `(model, goal_hash)` pair. Captures the statistical distribution of tool usage, call rates, and sequence patterns. Persists in SQLite and accumulates over time.

**Tier 2 — Session baseline:** tracks the current session against the global baseline and the session’s own early behavior, catching sudden mid-session shifts.

Five anomaly signals combined as a weighted composite:

|Signal                   |Method                     |Weight|
|-------------------------|---------------------------|------|
|Tool distribution anomaly|Jensen-Shannon divergence  |0.25  |
|Call rate anomaly        |Welford’s online algorithm |0.20  |
|Sequence pattern anomaly |Bigram transition deviation|0.30  |
|Novel tool introduction  |Unknown tool penalty       |0.15  |
|Argument volume anomaly  |Running mean/variance      |0.10  |

CMMC: 3.14.2, 3.14.7

-----

### T11 — OPA Policy Engine

**`aiglos_core/policy/opa.py`**

Open Policy Agent integration for stateful, context-aware policies that the YAML engine cannot express. Rego policies reason across the full session call history. Example: “block bash if the session has already called read_file on a `.env` path and the current goal does not include ‘network’ in its scope.” That rule cannot be expressed as a glob pattern — it requires cross-event reasoning.

Two modes: OPA server (recommended for production — send tool calls to a running OPA instance at `http://localhost:8181`) and embedded in-process fallback. Falls back gracefully to T5 if OPA is unavailable.

CMMC: 3.1.1, 3.1.2, 3.13.1

-----

### T15 — Alert Dispatcher

**`aiglos_core/integrations/__init__.py`**

Fan-out alert routing to: Splunk HEC, Syslog CEF (QRadar/ArcSight/Sentinel), Slack, generic webhook (PagerDuty/Opsgenie/Tines), Microsoft Teams, and file JSONL sink. Per-destination severity threshold and independent token-bucket rate limiting — one failing destination never affects the others. Fires on CRITICAL and HIGH events by default. The file JSONL sink is the air-gap/IL4/IL5 deployment pattern: transfer the file to the classified network and ingest it there.

CMMC: 3.14.6

-----

### T18 — CMMC Compliance Mapper

**`aiglos_core/compliance/__init__.py`**

Maps every audit DB event to NIST SP 800-171 Rev 2 controls across all 14 CMMC Level 2 families. Produces control-by-control readiness scores with evidence citations and remediation priorities. Output consumed by T19 for PDF generation.

CMMC: all 110 controls

-----

### T19 — PDF Report Generator

**`aiglos_core/compliance/report_pdf.py`** and **`aiglos_core/compliance/pdf_report.py`**

Produces multi-page, C3PAO-ready compliance reports in PDF format. Cover page with org name, assessment date, CMMC level, and overall score. Per-domain control coverage tables with evidence citations and remediation roadmap. One command: `aiglos report-pdf --org "Org Name"`.

-----

### T21 — ThreatHunter

**`aiglos_core/autonomous/hunter.py`**

Orchestrates 8 hunt modules against the audit DB. Runs on the T23 schedule (every 5 minutes by default) or on demand. Results are persisted back to the audit DB as `ANOMALY_DETECTED` events, which feed T15 alerts and T18 compliance scoring.

```python
result = await ThreatHunter(audit_db_path="aiglos_audit.db").run_full_scan()
```

|Module            |What it hunts                                                              |Source  |
|------------------|---------------------------------------------------------------------------|--------|
|`exposure`        |Config misconfigurations: 0.0.0.0 binding, missing auth, inline credentials|T4      |
|`credential_scan` |API keys, tokens, AWS keys in historical tool call arguments               |built-in|
|`injection_hunt`  |Prompt injection patterns in historical tool call results                  |built-in|
|`behavioral_trend`|Sessions with goal_integrity_score < 0.4; escalating drift over time       |T6/T9   |
|`policy_trend`    |Repeated violations of the same rule across sessions (probing pattern)     |built-in|
|`sampling_monitor`|MCP sampling 3-vector: injection, covert invocation, resource theft        |T24     |
|`a2a_monitor`     |A2A orchestrator impersonation, artifact injection, capability escalation  |T29     |
|`composition_scan`|Dangerous tool combinations registered before sessions run                 |T32     |

-----

### T22 — Threat Intelligence

**`aiglos_core/autonomous/intel.py`**

Intel refresh cycle pulls from: NVD API (new MCP-related CVEs), curated community feed (known malicious server fingerprints), local SCA scan via T26, and live registry scan via T30. Auto-updates `aiglos_policy.yaml` with new block/alert rules and `aiglos_trust.yaml` with new blocked server hashes and packages. Runs every hour by default via T23.

-----

### T23 — Autonomous Engine

**`aiglos_core/autonomous/engine.py`**

Command Center orchestrator. Priority task queue: CRITICAL (0) > HIGH (1) > NORMAL (2) > LOW (3). Per-task retry (2 attempts) and configurable timeout. State persisted to `aiglos_engine_state.json` for CLI status display. Default schedule: hunt every 5 min, intel refresh every 1 hour, compliance report every 24 hours. Watchdog loop detects engine interference and escalates to CRITICAL. Also available as a standalone entry point via `aiglos_autonomous.py`.

-----

### T24 — MCP Sampling Monitor

**`aiglos_core/autonomous/sampler.py`**

Detects the three-vector MCP sampling channel attack documented by Unit 42 (December 2025):

- **Persistent instruction injection** — malicious instructions embedded in sampling responses that override agent behavior across future calls
- **Covert tool invocation** — subprocess/file/network patterns in sampling-initiated calls that circumvent the proxy pipeline
- **Resource theft** — anomalous token consumption exceeding 5x the session baseline

Runs as hunt module 6 in T21. Also wired into T22 intel refresh.

CMMC: 3.14.2, 3.13.1, 3.1.1

-----

### T25 — OAuth Confused Deputy Detector

**`aiglos_core/proxy/oauth.py`**

Real-time hook blocks: token reuse across identities, overly broad OAuth scopes (`files:*`, `db:*`, `admin:*`), scope escalation attempts, and OAuth tokens appearing as tool call arguments. Autonomous scan mode detects: CVE-2025-6514 (mcp-remote 0.0.5–0.1.15, CVSS 9.6), static client IDs shared across sessions, and authorization code reuse.

CMMC: 3.5.1, 3.5.2, 3.13.10

-----

### T26 — Supply Chain Scanner

**`aiglos_core/autonomous/sca.py`**

Scans `package.json`, `smithery.yaml`, and `pyproject.toml` for: known-malicious packages (`postmark-mcp-server`, `mcp-postmark`), typosquatting (Levenshtein distance ≤2 from known-good names), packages with vulnerable versions (CVE-2025-6514, CVE-2025-68143, CVE-2026-22807, CVE-2026-23947), inline credentials, and overly broad tool permission grants. Runs on every T22 intel refresh and auto-updates `aiglos_trust.yaml`.

CMMC: 3.14.2, 3.14.1

-----

### T27 — Red Team Probe Engine

**`aiglos_probe.py`**

Adversarial self-testing with safe payloads only — no live exploits, safe in CI/CD. Five probe types:

|Probe              |What it tests                                            |
|-------------------|---------------------------------------------------------|
|`tool_injection`   |Prompt injection via tool description manipulation       |
|`path_traversal`   |Directory traversal in file tool arguments               |
|`cmd_injection`    |Command injection in shell tool arguments                |
|`oauth_escalation` |OAuth scope escalation via confused deputy               |
|`tool_redefinition`|Tool schema change detection (supply chain attack signal)|

Returns VULNERABLE / HARDENED / INCONCLUSIVE per probe. VULNERABLE findings are persisted to the audit DB and fire T15 alerts. Exit code non-zero on VULNERABLE, making it a natural CI/CD gate.

```bash
aiglos probe
aiglos probe --probes tool_injection path_traversal --target localhost:18789
aiglos probe --json
```

CMMC: 3.14.2 | §1513: Domain 5

-----

### T28 — NDAA §1513 Compliance Mapper

**`aiglos_core/compliance/s1513.py`**

Maps Aiglos coverage to NDAA FY2026 Section 1513’s six control domains. DoD status report due June 16, 2026.

|Domain               |Coverage                                       |
|---------------------|-----------------------------------------------|
|1. Model Integrity   |T7 attestation, T26 SCA                        |
|2. Runtime Monitoring|T23 autonomous engine, T24 sampling monitor    |
|3. Access Control    |T5/T11 policy, T25 OAuth guard, T8 trust fabric|
|4. Audit Trail       |T3 audit log, T7 signed attestation            |
|5. Anomaly Detection |T6/T9 proxy pipeline, T21 hunter, T27 probe    |
|6. Incident Response |T15 alert dispatch, T23 engine suspend state   |

```bash
aiglos s1513
aiglos s1513 --pdf s1513_report.pdf
```

-----

### T29 — A2A Protocol Monitor

**`aiglos_core/autonomous/a2a.py`**

First security tooling purpose-built for Google’s Agent-to-Agent (A2A) protocol (published April 2025). Covers multi-agent frameworks: AutoGen, CrewAI, LangGraph, OpenAI Swarm. Three detection vectors:

**Orchestrator impersonation** — Agent Card fingerprint registry per registered agent. If an orchestrator’s Card changes between calls, the session is blocked as a probable impersonation.

**Artifact injection** — All A2A task payloads and Part objects are scanned for indirect prompt injection patterns before forwarding to subagents.

**Capability escalation** — Subagent task dispatches requesting high-risk capabilities (`file_system_write`, `shell_execution`, `code_execution`, `network_egress`, `credential_access`) without an explicit delegation token from T33 are blocked.

```python
monitor = A2AMonitor(audit_db="aiglos_audit.db")
monitor.register_agent("orch-001", trusted_card, allowed_capabilities={"read_fs"})
verdict = await monitor.evaluate(A2AEvent(...))
```

Runs as hunt module 7 in T21.

CMMC: 3.5.1, 3.5.3, 3.13.8, 3.14.2

-----

### T30 — Registry Monitor

**`aiglos_core/autonomous/registry.py`**

Continuous monitoring of npm, Smithery, mcp.so, and PyPI for newly published malicious MCP packages — proactive detection before installation. Scores each package against 8 signals: known-malicious name, typosquatting (Levenshtein ≤2), social engineering language in README, tool injection patterns in package metadata, high-risk permission declarations, publisher account age under 30 days, abnormal download spike, and known-malicious transitive dependencies. Runs on every T22 intel refresh. Critical findings automatically update `aiglos_trust.yaml`.

```python
score = await RegistryMonitor().score_package("postmark-mcp-server")
# score.risk_level == "critical"
```

CMMC: 3.14.2, 3.14.1

-----

### T31 — RAG and Memory Poison Detector

**`aiglos_core/autonomous/rag.py`**

Why this is architecturally distinct from prompt injection detection: T1 catches injection at tool-call time. RAG/memory poisoning happens at write time and executes silently at every subsequent retrieval. A single poisoned document in a shared vector store injects into every session that retrieves it — across all users, indefinitely, without triggering any runtime scanner.

Four scan modes:

**Write-time** — scans before embedding into the knowledge base. T1 patterns (hard injection: `ignore all previous instructions`, system tags, zero-width steganography) block immediately. T2 patterns (suspicious: `please disregard`, base64_decode, eval/exec, exfil patterns) flag in standard mode and block in strict mode.

**Memory write** — scans before persisting to Mem0/Zep/Letta. Always uses strict mode, because a poisoned memory persists across all future sessions.

**Retrieval-time** — filters poisoned chunks before injecting into the context window.

**Cross-session PII leakage** — blocks one user’s personal data (SSN, credit cards, API keys, emails, IPs) from leaking into another user’s context via over-broad semantic search.

**Autonomous background scan** — scans all configured memory paths (`./memory/`, `./knowledge_base/`, `./rag_data/`, `./embeddings/`, `./vector_store/`, `./mem0/`, `./zep/`).

```python
detector = RAGPoisonDetector()
verdict = await detector.scan_document(content=doc, source="uploads/brief.pdf")
safe_chunks = await detector.filter_chunks(chunks=retrieved, session_id="sess-abc")
```

CMMC: 3.14.2, 3.13.1, 3.1.3

-----

### T32 — Skill Composition Analyzer

**`aiglos_core/autonomous/composer.py`**

Static analysis of registered tool combinations at session start — before any tool executes. Individual tools can each be benign while their combination creates a dangerous capability. Goal-context suppression reduces false positives: if the authorized goal explicitly mentions a combination (e.g., “email the report”), the matching rule is suppressed.

10 composition rules:

|Rule  |Capabilities                          |Threat                         |
|------|--------------------------------------|-------------------------------|
|CR-001|`read_fs` + `network_egress`          |Filesystem exfiltration        |
|CR-002|`read_fs` + `email_send`              |Email exfiltration             |
|CR-003|`execute_code` + `network_egress`     |RCE with C2                    |
|CR-004|`memory_read` + `write_fs`            |Cross-session memory harvesting|
|CR-005|`git_write` + `network_egress`        |Source code exfiltration       |
|CR-006|`credential_access` + `network_egress`|Credential exfiltration        |
|CR-007|`spawn_agent` + `credential_access`   |Agentic escalation chain       |
|CR-008|`database_read` + `network_egress`    |Database exfiltration          |
|CR-009|`clipboard` + `network_egress`        |PII harvesting                 |
|CR-010|`browser` + `memory_write`            |Browser session hijacking      |

Runs as hunt module 8 in T21 and via `aiglos.analyze_session()` at session start.

CMMC: 3.1.1, 3.13.1, 3.14.2

-----

### T33 — Cross-Vendor Agent Identity Bridge

**`aiglos_core/proxy/identity_bridge.py`**

Issues signed Aiglos Identity Tokens (AIT) that travel with agents across multi-vendor pipelines (Claude, GPT-4, Gemini, Llama, Mistral). Vendor is auto-detected from the model ID. Cryptographic delegation chains enforce strict capability subsetting — child agents can never exceed parent scope.

`to_openid_agents_claims()` maps AIT fields directly to the OpenID for Agents / OAuth 2.0 spec — the direct integration surface for Okta machine identity. `from_openid_agents_claims()` parses inbound tokens from external issuers.

```python
bridge = AgentIdentityBridge()

# Issue at session start
token = await bridge.issue_token("sess-abc", "claude-opus-4-6", {"read_fs", "web_search"})

# Delegate to subagent — strict capability subset enforced
child = await bridge.delegate(token, "gpt-4o-sub", {"web_search"})

# Verify inbound token from external model
verdict = await bridge.verify_token(token_str=incoming_ait)
# verdict.trust_level: "aiglos-signed" | "unattested" | "invalid"

# Compact form for HTTP headers (base64url)
compact = bridge.to_compact(token)
token = bridge.from_compact(compact)

# Okta / OpenID for Agents format
claims = bridge.to_openid_agents_claims(token)
token = bridge.from_openid_agents_claims(claims)
```

CMMC: 3.5.1, 3.5.3, 3.13.8

-----

## CVE and Threat Coverage

|CVE / Threat           |CVSS|Description                                   |Module  |
|-----------------------|----|----------------------------------------------|--------|
|CVE-2025-6514          |9.6 |mcp-remote OAuth RCE (0.0.5–0.1.15)           |T25, T26|
|CVE-2025-68143         |—   |mcp-server-git path traversal                 |T26     |
|CVE-2026-22807         |—   |mcp-server-git XSS / command injection        |T26     |
|CVE-2026-23947         |—   |mcp-server-git XSS / deserialization          |T26     |
|Unit 42 (Dec 2025)     |—   |MCP sampling channel 3-vector attack          |T24     |
|Postmark impersonation |—   |postmark-mcp-server npm exfil package         |T26, T30|
|Smithery path traversal|—   |smithery.yaml arbitrary read                  |T26     |
|OWASP Agentic #1       |—   |Goal hijacking / tool description injection   |T6, T27 |
|OWASP Agentic #2       |—   |Tool poisoning via server compromise          |T2, T21 |
|OWASP Agentic #5       |—   |OAuth confused deputy                         |T25     |
|Endor Labs 82%         |—   |Path traversal in MCP implementations         |T27     |
|Google A2A (Apr 2025)  |—   |Orchestrator impersonation, artifact injection|T29     |
|RAG indirect injection |—   |Knowledge base poisoning at scale             |T31     |

-----

## Compliance

|Framework        |Coverage                                                             |
|-----------------|---------------------------------------------------------------------|
|CMMC Level 2     |110 controls across all 14 NIST SP 800-171 Rev 2 families            |
|NDAA FY2026 §1513|18 controls across 6 domains; report artifact generated automatically|

```bash
aiglos report --level 2 --output cmmc.json
aiglos report-pdf --org "Your Org" --output cmmc.pdf
aiglos s1513 --pdf s1513.pdf
```

-----

## Configuration

`aiglos init` generates `aiglos.yaml` and `aiglos_policy.yaml`. Key options:

```yaml
proxy:
  listen_port: 8765
  upstream_host: localhost
  upstream_port: 18789
  deployment_tier: cloud         # cloud | on_prem | gov

features:
  credential_scanning: true      # inline in T1
  goal_integrity: true           # T6 — set ANTHROPIC_API_KEY for semantic path
  behavioral_baseline: true      # T9
  policy_engine: true            # T5 YAML
  opa_engine: false              # T11 — requires OPA server or embedded mode
  attestation: true              # T7
  trust_registry: true           # T8
  oauth_guard: true              # T25
  a2a_monitor: true              # T29
  rag_detector: true             # T31
  registry_monitor: true         # T30
  composition_analyzer: true     # T32

goal_integrity:
  drift_threshold: 0.35          # GOAL_DRIFT fires when score drops below this

trust:
  mode: audit                    # strict | audit | permissive
  file: aiglos_trust.yaml

alerts:
  slack:
    webhook_url: https://hooks.slack.com/...
    min_severity: high
  splunk:
    hec_url: https://splunk.example.com:8088/services/collector
    hec_token: YOUR_TOKEN
    min_severity: info
  file_sink:
    path: aiglos_events.jsonl    # air-gap / IL4/IL5 SIEM handoff

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

`aiglos_trust.yaml` — ships pre-populated with known-malicious packages. T26 and T30 append to this file automatically during intel refresh:

```yaml
blocked_packages:
  - postmark-mcp-server       # active npm exfiltration package
  - modelcontextprotocol-sdk  # impersonation package

allowed_servers: []
blocked_servers: []
```

-----

## Deployment

**Standard**

```bash
pip install -e .
aiglos init
aiglos proxy
# Point your MCP client to localhost:8765
```

**Docker**

```bash
docker run -p 8765:8765 \
  -e UPSTREAM_HOST=your-mcp-server \
  -e UPSTREAM_PORT=18789 \
  aiglos/aiglos:latest
```

**Docker Compose**

```bash
UPSTREAM_HOST=your-mcp-server docker compose up
```

The compose file mounts `aiglos.yaml`, `aiglos_policy.yaml`, and `aiglos_trust.yaml` as read-only volumes and persists the audit DB and signing keys to a named volume (`aiglos_data`). Key environment variables:

|Variable            |Default    |Purpose                                           |
|--------------------|-----------|--------------------------------------------------|
|`UPSTREAM_HOST`     |`localhost`|MCP server hostname                               |
|`UPSTREAM_PORT`     |`18789`    |MCP server port                                   |
|`DEPLOYMENT_TIER`   |`cloud`    |cloud / on_prem / gov                             |
|`TRUST_MODE`        |`audit`    |strict / audit / permissive                       |
|`ANTHROPIC_API_KEY` |—          |Enables T6 LLM-based semantic evaluation          |
|`AIGLOS_SIGNING_KEY`|—          |Injects RSA private key for air-gapped deployments|

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

## CI/CD

GitHub Actions pipeline at `.github/workflows/ci.yml`. Three jobs run on every push to `main`/`develop` and every pull request:

**`test`** — matrix across Python 3.11 and 3.12:

- `ruff check aiglos_core aiglos_cli`
- `mypy aiglos_core aiglos_cli --ignore-missing-imports`
- `pytest tests/ -v --cov=aiglos_core --cov-report=xml`
- `aiglos --version` entry point smoke test

**`security-scan`** — Bandit static security analysis on `aiglos_core` and `aiglos_cli`

**`build`** — `python -m build` wheel build, uploads dist artifacts

T27 (ProbeEngine) integrates with any CI/CD pipeline via exit code. Add `aiglos probe` as a pipeline step to gate deployments on adversarial self-test results.

-----

## Repository Structure

```
aiglos/
│
├── aiglos.py                      Drop-in manifest: module map, CLI, Aiglos facade class
├── aiglos_autonomous.py           Standalone autonomous engine entry point
├── aiglos_probe.py                Red team probe entry point (T27)
├── pyproject.toml                 Package config, entry points, dev dependencies (v0.1.0)
├── Dockerfile                     Multi-stage production image (python:3.12-slim)
├── docker-compose.yml             Full stack compose with volume mounts and env vars
├── aiglos_trust.yaml              Trust registry — ships with known-malicious blocklist
│
├── .github/
│   └── workflows/
│       └── ci.yml                 test / security-scan / build pipeline
│
├── aiglos_dashboard/              React dashboard scaffold (T16/T17 from original build plan)
│   └── src/                       Directory structure in place (components, hooks, lib, pages)
│                                  Interactive pitch demo delivered as standalone HTML artifact
│
├── aiglos_cli/
│   └── main.py                    Installed CLI — proxy, logs, tail, sessions, scan, init,
│                                  report, report-pdf, attest, verify, trust, alerts,
│                                  probe, s1513, daemon (start/stop/status/scan/intel)
│
├── aiglos_core/
│   ├── types.py                   Shared types: SecurityEvent, EventType, Severity, ToolCall
│   │
│   ├── audit/
│   │   └── __init__.py            SQLite audit log, WAL mode (T3)
│   │
│   ├── scanner/
│   │   └── config_scanner.py      Config file misconfig scanner (T4)
│   │
│   ├── proxy/
│   │   ├── __init__.py            MCP WebSocket proxy + inline detection pipeline (T1)
│   │   ├── trust.py               Per-session trust scorer (T2)
│   │   ├── trust_fabric.py        Multi-agent attestation chain (T8)
│   │   ├── oauth.py               OAuth confused deputy detector (T25)
│   │   └── identity_bridge.py     Cross-vendor AIT tokens, OpenID for Agents (T33)
│   │
│   ├── intelligence/
│   │   ├── __init__.py            Goal Integrity Engine — semantic drift detection (T6)
│   │   ├── attestation.py         RSA-2048 session attestation (T7)
│   │   └── baseline.py            Behavioral Baseline Engine — statistical fingerprinting (T9)
│   │
│   ├── policy/
│   │   ├── __init__.py            YAML policy engine (T5)
│   │   └── opa.py                 OPA / Rego stateful policy engine (T11)
│   │
│   ├── integrations/
│   │   └── __init__.py            SIEM and alert dispatcher (T15)
│   │
│   ├── compliance/
│   │   ├── __init__.py            CMMC Level 2 mapper (T18)
│   │   ├── report_pdf.py          PDF report generator (T19)
│   │   ├── pdf_report.py          PDF report generator, v1 (T19)
│   │   └── s1513.py               NDAA §1513 compliance mapper (T28)
│   │
│   └── autonomous/
│       ├── engine.py              Autonomous engine orchestrator (T23)
│       ├── hunter.py              ThreatHunter — 8 hunt modules (T21)
│       ├── intel.py               Threat intelligence refresh cycle (T22)
│       ├── sampler.py             MCP sampling monitor (T24)
│       ├── sca.py                 Supply chain scanner (T26)
│       ├── a2a.py                 A2A protocol monitor (T29)
│       ├── registry.py            Public registry monitor (T30)
│       ├── rag.py                 RAG and memory poison detector (T31)
│       └── composer.py            Skill composition analyzer (T32)
│
└── tests/
    └── unit/                      528 tests across 14 files
        ├── test_core.py           T3 audit log, shared types
        ├── test_trust.py          T2 trust scorer
        ├── test_trust_fabric.py   T8 multi-agent trust chain
        ├── test_attestation.py    T7 session attestation
        ├── test_goal_integrity.py T6 goal integrity engine
        ├── test_baseline.py       T9 behavioral baseline engine
        ├── test_opa.py            T11 OPA policy engine
        ├── test_integrations.py   T15 alert dispatcher
        ├── test_compliance.py     T18 CMMC mapper
        ├── test_report_pdf.py     T19 PDF generator
        ├── test_autonomous.py     T21 / T22 / T23 autonomous stack
        ├── test_augmentation.py   T24 / T25 / T26 / T27 / T28
        ├── test_t24_t28.py        T24–T28 extended coverage
        └── test_t29_t33.py        T29–T33 agent and skills proliferation
```

-----

## License

Proprietary. Contact [will@aiglos.io](mailto:will@aiglos.io) for licensing.