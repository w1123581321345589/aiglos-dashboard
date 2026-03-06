# Aiglos

**Autonomous AI Agent Security Runtime — T1 through T33**

Aiglos is a full-stack security runtime for AI agents and multi-agent systems. It covers every layer of the modern agent attack surface: real-time MCP proxy interception, autonomous threat hunting, compliance reporting, public registry monitoring, RAG/memory poison detection, skill composition analysis, and cryptographic identity across multi-vendor pipelines.

528 tests passing. Zero external runtime dependencies for core detection.

-----

## The Problem

AI agents have no security layer. They accept tool calls from any server, execute instructions from any document they read, and have no mechanism to verify they are still pursuing their authorized objective. Traditional security tools operate at the network or identity layer — they are blind to what an agent actually does.

**Five classes of attack no existing tool catches:**

1. **Goal hijacking** — An adversary embeds instructions in a document the agent reads. The agent’s subsequent tool calls are syntactically valid but semantically wrong. The agent is now doing the attacker’s work.
1. **MCP server compromise** — An attacker modifies a legitimate MCP server’s tool definitions to include malicious implementations behind familiar names. The agent’s calls look normal; the execution is not.
1. **Credential exfiltration via agent** — An agent with file system access reads a `.env` or `.ssh/id_rsa` and passes the contents as arguments to an outbound HTTP call. Standard DLP tools never see it because it’s application-layer JSON, not a file transfer.
1. **A2A orchestrator impersonation** — In multi-agent pipelines using Google A2A, AutoGen, CrewAI, or LangGraph, a malicious agent forges an Agent Card and issues instructions to subagents that bypass the MCP proxy entirely. No existing tool covers this.
1. **RAG/memory poisoning** — A malicious document sits in a shared knowledge base and injects instructions into every agent session that retrieves it, invisibly, permanently, across all users. The attack happens at write time; it executes at every retrieval. No prompt injection scanner catches it.

-----

## Architecture: Seven Security Layers

```
LAYER 1  Real-Time Proxy        T1, T2, T5, T7, T8, T15, T25, T33
LAYER 2  Compliance             T18, T19, T28
LAYER 3  Autonomous Hunt        T21  (8 modules: T24, T26, T29, T32 + 4 behavioral)
LAYER 4  Threat Intelligence    T22, T30
LAYER 5  Knowledge Base Guard   T31
LAYER 6  Red Team               T27
LAYER 7  Cross-Vendor Identity  T33
```

### Data Flow

```
MCP Client --> [T1 Proxy] --> [T2 Trust] --> [T5 Policy] --> MCP Server
                  |               |               |
                  v               v               v
              [T3 Audit]    [T7 Attest]      BLOCK/ALLOW
                  |
        +---------+------------------------+
        v         v                        v
   [T25 OAuth] [T33 AIT]            [T15 Alerts]
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

Session start (static analysis):
[T32 Composer] ---> composition analysis ---> BLOCK / WARN / ALLOW
[T33 Bridge]   ---> AIT issued ---> travels with agent downstream
```

-----

## Installation

```bash
pip install -e .
```

Requires Python 3.11+.

-----

## Quickstart

```bash
# Check all 22 modules
python aiglos.py modules

# Full autonomous scan (all 8 hunt modules)
python aiglos.py scan

# Red team adversarial probe
python aiglos.py probe

# CMMC Level 2 + NDAA §1513 compliance report
python aiglos.py compliance

# Refresh threat intelligence (NVD + registry)
python aiglos.py intel

# Scan RAG/memory stores for poison
python aiglos.py rag --paths ./knowledge_base ./memory

# Start continuous monitoring daemon
python aiglos.py daemon --interval 300

# Runtime status
python aiglos.py status
```

### Programmatic use

```python
from aiglos import Aiglos

aiglos = Aiglos()

# Full threat hunt
result = await aiglos.scan()

# Static composition analysis at session start
result = await aiglos.analyze_session(
    session_id="sess-abc",
    registered_tools=my_tool_list,
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

# Map to OpenID for Agents / Okta machine identity format
from aiglos_core.proxy.identity_bridge import AgentIdentityBridge
bridge = AgentIdentityBridge()
okta_claims = bridge.to_openid_agents_claims(token)
```

-----

## Module Reference

### Layer 1 — Real-Time Proxy

Every tool call passes through this pipeline before reaching the MCP server.

**T1 — MCP Proxy** `aiglos_core/proxy/__init__.py`
WebSocket proxy. Intercepts all tool calls before execution. Real-time hooks: trust scoring, policy check, attestation, alert dispatch. Blocks or allows each call within the same request/response cycle.
CMMC: 3.14.2, 3.13.1, 3.1.1

**T2 — Trust Scorer** `aiglos_core/proxy/trust.py`
Per-session behavioral trust scoring (0.0–1.0). Signals: velocity, scope creep, anomaly delta, known-bad patterns. Score drives policy thresholds in T5.
CMMC: 3.14.2

**T5 — Policy Engine** `aiglos_core/policy/engine.py`
OPA-compatible YAML policy engine. ALLOW/DENY/REQUIRE_APPROVAL rules match on tool name, session ID, trust score, time of day, capabilities. Hot-reload without restart.
CMMC: 3.1.1, 3.1.2

**T7 — Attestation Engine** `aiglos_core/proxy/__init__.py`
RSA-2048 session attestation. Signs each session at start. Produces audit log entries verifiable offline: model identity, system prompt hash, tool permissions, per-event SHA-256 manifest.
CMMC: 3.5.1, 3.13.8

**T8 — Trust Fabric** `aiglos_core/proxy/trust_fabric.py`
Multi-agent attestation chain. Extends T7 across orchestrator and subagent sessions within Aiglos-managed pipelines.
CMMC: 3.5.1, 3.5.3, 3.13.8

**T15 — Alert Dispatcher** `aiglos_core/proxy/__init__.py`
Fan-out to Slack, Splunk HEC, Syslog CEF (QRadar/ArcSight/Sentinel), webhook (PagerDuty/Opsgenie), Microsoft Teams, and file JSONL sink. Rate-limited per destination.
CMMC: 3.14.6

**T25 — OAuth Confused Deputy Detector** `aiglos_core/proxy/oauth.py`
Real-time hook blocks: token reuse across identities, broad scopes (`files:*`, `db:*`, `admin:*`), scope escalation. Autonomous scan detects CVE-2025-6514 (mcp-remote 0.0.5–0.1.15), static client IDs, OAuth tokens appearing in tool call arguments.
CMMC: 3.5.1, 3.5.2, 3.13.10

**T33 — Cross-Vendor Agent Identity Bridge** `aiglos_core/proxy/identity_bridge.py`
Issues signed Aiglos Identity Tokens (AIT) that travel with agents across multi-vendor pipelines (Claude / GPT-4 / Gemini / Llama). Cryptographic delegation chains enforce strict capability subsetting — child agents can never exceed parent scope. `to_openid_agents_claims()` maps AIT fields to the OpenID for Agents / OAuth 2.0 spec, the direct integration surface for Okta machine identity.

```python
# Issue at session start
token = await bridge.issue_token("sess-abc", "claude-opus-4-6", {"read_fs", "web_search"})

# Delegate to subagent (strict subsetting — cannot escalate)
child = await bridge.delegate(token, "gpt-4o-sub", {"web_search"})

# Verify incoming token from external model
verdict = await bridge.verify_token(token_str=incoming_ait)
# trust_level: "aiglos-signed" | "unattested" | "invalid"

# Map to OpenID for Agents / Okta format
claims = bridge.to_openid_agents_claims(token)
```

CMMC: 3.5.1, 3.5.3, 3.13.8

-----

### Layer 2 — Compliance

**T18 — CMMC Compliance Mapper** `aiglos_core/compliance/__init__.py`
Maps audit DB events to all 110 CMMC Level 2 controls. Control-by-control readiness scores.

**T19 — PDF Report Generator** `aiglos_core/compliance/report_pdf.py`
Produces audit-ready CMMC compliance report with evidence table, control scores, and remediation roadmap.

**T28 — NDAA §1513 Compliance Mapper** `aiglos_core/compliance/s1513.py`
18 controls across 6 domains: Model Integrity, Runtime Monitoring, Access Control, Audit Trail, Anomaly Detection, Incident Response. Generates sidecar JSON (`.s1513.json`) alongside the CMMC PDF. DoD status report due June 16, 2026.

```bash
python aiglos.py compliance --org "Acme Defense" --pdf report.pdf --json
```

-----

### Layer 3 — Autonomous Threat Hunting

**T21 — ThreatHunter** `aiglos_core/autonomous/hunter.py`
Orchestrates all 8 hunt modules. Runs on daemon cycle or on demand.

```python
result = await ThreatHunter(audit_db_path="aiglos_audit.db").run_full_scan()
```

|Module|Description                                                                        |T-Number|
|------|-----------------------------------------------------------------------------------|--------|
|1     |Credential patterns in tool call arguments (API keys, tokens, AWS keys)            |built-in|
|2     |Prompt injection patterns in historical tool call results                          |built-in|
|3     |Cross-session behavioral anomaly detection                                         |built-in|
|4     |Sessions with gradual trust score decay (privilege creep)                          |built-in|
|5     |Supply chain: typosquat, malicious packages, vulnerable CVE versions               |T26     |
|6     |MCP sampling channel: instruction injection, covert tool invocation, resource theft|T24     |
|7     |A2A protocol: orchestrator impersonation, artifact injection, capability escalation|T29     |
|8     |Skill composition: dangerous tool combinations before session runs                 |T32     |

**T24 — Sampling Monitor** `aiglos_core/autonomous/sampler.py`
Detects the three-vector MCP sampling channel attack documented by Unit 42 (December 2025): persistent instruction injection, covert tool invocation (subprocess/file/network patterns), resource theft (anomalous token consumption >5x baseline).
CMMC: 3.14.2, 3.13.1, 3.1.1

**T26 — Supply Chain Scanner** `aiglos_core/autonomous/sca.py`
Package manifest analysis: known-malicious packages (postmark-mcp-server, mcp-postmark), typosquat detection (Levenshtein ≤2), vulnerable versions (CVE-2025-6514, CVE-2025-68143, CVE-2026-22807, CVE-2026-23947), inline credentials, broad tool permissions. Auto-updates `aiglos_trust.yaml` blocked_packages.
CMMC: 3.14.2, 3.14.1

**T29 — A2A Protocol Monitor** `aiglos_core/autonomous/a2a.py`
First security tooling for Google’s A2A protocol (published April 2025). Three detection vectors:

- **Orchestrator impersonation** — Agent Card fingerprint registry. If an orchestrator’s Card changes between calls, the session is blocked as a possible impersonation.
- **Artifact injection** — Scans all A2A task payloads for indirect prompt injection patterns before forwarding to subagents.
- **Capability escalation** — Blocks subagent task dispatches that request high-risk capabilities without an explicit delegation token.

```python
monitor = A2AMonitor(audit_db="aiglos_audit.db")
monitor.register_agent("orch-001", trusted_agent_card, allowed_capabilities={"read_fs"})

verdict = await monitor.evaluate(A2AEvent(
    orchestrator_id="orch-001",
    target_agent_id="sub-001",
    task_type="research",
    payload=task_dict,
    agent_card=card_dict,
))
```

CMMC: 3.5.1, 3.5.3, 3.13.8, 3.14.2

**T32 — Skill Composition Analyzer** `aiglos_core/autonomous/composer.py`
Static analysis of registered tool combinations at session start — before any tool executes. Individual tools can each be benign while their combination creates a dangerous capability. The analyzer catches it pre-execution.

10 composition rules:

|Rule  |Combination                           |Threat                      |
|------|--------------------------------------|----------------------------|
|CR-001|`read_fs` + `network_egress`          |Filesystem Exfiltration     |
|CR-002|`read_fs` + `email_send`              |Email Exfiltration          |
|CR-003|`execute_code` + `network_egress`     |RCE with C2                 |
|CR-004|`memory_read` + `write_fs`            |Cross-Session Memory Harvest|
|CR-005|`git_write` + `network_egress`        |Source Code Exfiltration    |
|CR-006|`credential_access` + `network_egress`|Credential Exfiltration     |
|CR-007|`spawn_agent` + `credential_access`   |Agentic Escalation Chain    |
|CR-008|`database_read` + `network_egress`    |Database Exfiltration       |
|CR-009|`clipboard` + `network_egress`        |PII Harvesting              |
|CR-010|`browser` + `memory_write`            |Browser Session Hijacking   |

Goal-context suppression reduces false positives for legitimate combinations.

```python
result = await SkillComposer().analyze_session(
    session_id="sess-123",
    registered_tools=tool_list,
    authorized_goal="Email the quarterly report to the finance team",
)
# CR-002 suppressed because goal explicitly mentions email
```

CMMC: 3.1.1, 3.13.1, 3.14.2

-----

### Layer 4 — Threat Intelligence

**T22 — Threat Intelligence** `aiglos_core/autonomous/intel.py`
Refresh cycle pulls from NVD API, curated community MCP threat patterns, local SCA scan (T26), and live registry scan (T30). Updates the pattern DB used by all detection layers.

**T30 — Registry Monitor** `aiglos_core/autonomous/registry.py`
Continuous monitoring of npm, Smithery, mcp.so, and PyPI for newly published malicious MCP packages. Scores each package against: known-malicious name list, typosquat detection (Levenshtein), social engineering language in descriptions, tool injection patterns in package metadata, new publisher accounts (<30 days). Live npm feed scan on every intel refresh. Automatically updates `aiglos_trust.yaml` blocklist on critical findings.

```python
# Pre-install check
score = await RegistryMonitor().score_package("postmark-mcp-server")
# score.risk_level == "critical"
# score.signals == ["Known-malicious package name: postmark-mcp-server"]
```

CMMC: 3.14.2, 3.14.1

-----

### Layer 5 — Knowledge Base & Memory Security

**T31 — RAG / Memory Poison Detector** `aiglos_core/autonomous/rag.py`

Why this is architecturally different from prompt injection detection: the MCP proxy catches injection at tool-call time. RAG/memory poisoning happens at write time and executes silently at every retrieval. A poisoned document sitting in a shared vector store injects instructions into every agent session that retrieves it — across all users, indefinitely.

Three scan modes:

**Write-time** — scans documents before embedding:

```python
verdict = await detector.scan_document(content=doc_text, source="uploads/brief.pdf")
if not verdict.safe:
    raise SecurityError(verdict.reason)
```

**Memory write** — scans before persisting to Mem0/Zep/Letta (always strict mode):

```python
verdict = await detector.scan_memory_write(
    content=memory_text, memory_key="pref_001", session_id="sess-abc"
)
```

**Retrieval-time** — filters poisoned chunks before context injection:

```python
safe_chunks = await detector.filter_chunks(chunks=retrieved_chunks, session_id="sess-abc")
```

**Cross-session PII leakage** — blocks one user’s data from leaking into another’s context via over-broad semantic search:

```python
safe = await detector.check_cross_session_leakage(chunks, current_session_id, owner_session_id)
```

**Autonomous scan** — background scan of all configured memory paths:

```python
findings = await detector.scan()  # scans ./memory/, ./knowledge_base/, ./rag_data/, etc.
```

Two pattern tiers: T1 (hard injection — blocked immediately) and T2 (suspicious — flagged in standard mode, blocked in strict mode). Memory writes always use strict mode.

CMMC: 3.14.2, 3.13.1, 3.1.3

-----

### Layer 6 — Red Team

**T27 — ProbeEngine** `aiglos_probe.py`
Adversarial self-testing with safe payloads only (no live exploits). Five probe types: `tool_injection`, `path_traversal`, `cmd_injection`, `oauth_escalation`, `tool_redefinition`. Returns VULNERABLE / HARDENED / INCONCLUSIVE verdicts. Persists findings to audit DB.

```bash
python aiglos.py probe --target filesystem --probes tool_injection path_traversal
python aiglos.py probe --json
```

CMMC: 3.14.2 | §1513: 5.4

-----

## CVE Coverage

|CVE / Threat           |CVSS|Description                                    |Covered by|
|-----------------------|----|-----------------------------------------------|----------|
|CVE-2025-6514          |9.6 |mcp-remote OAuth RCE (0.0.5–0.1.15)            |T25, T26  |
|CVE-2025-68143         |—   |mcp-server-git path traversal                  |T26       |
|CVE-2026-22807         |—   |mcp-server-git command injection               |T26       |
|CVE-2026-23947         |—   |mcp-server-git deserialization                 |T26       |
|Unit 42 Dec 2025       |—   |MCP sampling 3-vector attack                   |T24       |
|Postmark impersonation |—   |postmark-mcp-server / mcp-postmark             |T26, T30  |
|Smithery path traversal|—   |smithery.yaml build config                     |T26       |
|OWASP Agentic #1       |—   |Tool injection                                 |T1–T4, T27|
|OWASP Agentic #5       |—   |OAuth confused deputy                          |T25       |
|Endor Labs 82%         |—   |Path traversal exposure                        |T27       |
|Google A2A (Apr 2025)  |—   |Orchestrator impersonation / artifact injection|T29       |
|RAG indirect injection |—   |Knowledge base poisoning at scale              |T31       |

-----

## Compliance Coverage

|Framework   |Coverage                              |
|------------|--------------------------------------|
|CMMC Level 2|110 controls across all 14 domains    |
|NDAA §1513  |18 controls, 6 domains, 90%+ readiness|

```bash
python aiglos.py compliance --org "Your Organization" --pdf cmmc_report.pdf
```

-----

## Configuration

`aiglos.yaml`:

```yaml
proxy:
  listen_port: 8765
  upstream_host: localhost
  upstream_port: 18789
  deployment_tier: cloud   # cloud | on_prem | gov

features:
  goal_integrity: true
  credential_scanning: true
  policy_engine: true
  trust_registry: true
  attestation: true
  a2a_monitor: true
  rag_detector: true
  registry_monitor: true
  composition_analyzer: true

goal_integrity:
  drift_threshold: 0.35

trust:
  mode: audit   # strict | audit | permissive
  file: aiglos_trust.yaml

alerts:
  slack:
    webhook_url: https://hooks.slack.com/...
    min_severity: high
  splunk:
    hec_url: https://splunk.example.com:8088/services/collector
    hec_token: YOUR_HEC_TOKEN
    min_severity: info

a2a:
  registered_agents_file: aiglos_agents.yaml

rag:
  memory_paths:
    - ./memory/
    - ./knowledge_base/
    - ./rag_data/
  strict_mode: false
```

-----

## CLI Reference

```
python aiglos.py modules          Check all 22 modules (✅/❌)
python aiglos.py scan             Full autonomous threat scan (8 hunt modules)
python aiglos.py probe            Red team adversarial probe
  --target SERVER_ID              Probe a specific server
  --probes TYPE [TYPE ...]        tool_injection path_traversal cmd_injection
                                  oauth_escalation tool_redefinition
  --json                          JSON output
python aiglos.py compliance       CMMC Level 2 + NDAA §1513 report
  --org "Name"                    Organization name
  --pdf PATH                      Write PDF to path
  --json                          JSON output
python aiglos.py intel            Refresh threat intelligence
python aiglos.py rag              Scan RAG/memory stores for poison
  --paths PATH [PATH ...]         Paths to scan
python aiglos.py daemon           Start continuous monitoring daemon
  --interval SECONDS              Scan interval (default: 300)
python aiglos.py status           Runtime status summary
  --json                          JSON output
```

-----

## Deployment

**Standard**

```bash
pip install -e .
python aiglos.py proxy
# Point MCP client to localhost:8765
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
python aiglos.py proxy --tier gov
```

Deployment tiers:

|Tier     |Target             |CMMC    |
|---------|-------------------|--------|
|`cloud`  |SaaS, commercial   |L1/L2   |
|`on_prem`|Enterprise, air-gap|L3      |
|`gov`    |FedRAMP, IL4/IL5   |L3+ STIG|

-----

## Repository Structure

```
aiglos/
├── aiglos.py                      Drop-in manifest — module map, CLI, Aiglos class
├── aiglos_probe.py                Red team probe engine (T27)
├── aiglos_core/
│   ├── proxy/
│   │   ├── __init__.py            MCP proxy, attestation, alert dispatch (T1, T7, T15)
│   │   ├── trust.py               Trust scorer (T2)
│   │   ├── trust_fabric.py        Multi-agent trust chain (T8)
│   │   ├── oauth.py               OAuth confused deputy detector (T25)
│   │   └── identity_bridge.py     Cross-vendor identity bridge (T33)
│   ├── policy/
│   │   └── engine.py              OPA-compatible policy engine (T5)
│   ├── audit/
│   │   └── __init__.py            SQLite audit log (T3)
│   ├── compliance/
│   │   ├── __init__.py            CMMC mapper (T18)
│   │   ├── report_pdf.py          PDF generator (T19)
│   │   └── s1513.py               NDAA §1513 mapper (T28)
│   └── autonomous/
│       ├── hunter.py              ThreatHunter — 8 modules (T21)
│       ├── intel.py               Threat intelligence refresh (T22)
│       ├── engine.py              Autonomous engine orchestrator (T23)
│       ├── sampler.py             MCP sampling monitor (T24)
│       ├── sca.py                 Supply chain scanner (T26)
│       ├── a2a.py                 A2A protocol monitor (T29)
│       ├── registry.py            Public registry monitor (T30)
│       ├── rag.py                 RAG/memory poison detector (T31)
│       └── composer.py            Skill composition analyzer (T32)
└── tests/
    └── unit/
        ├── test_t1_t23.py         364 tests — proxy, compliance, hunting
        ├── test_t24_t28.py        51 tests  — sampling, OAuth, SCA, probe, §1513
        └── test_t29_t33.py        63 tests  — A2A, registry, RAG, composition, identity
```

**528 tests passing.**

-----

## License

Proprietary. Contact [will@aiglos.io](mailto:will@aiglos.io) for licensing.