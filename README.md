# Aiglos

**The Only Full-Stack Autonomous AI Agent Security Runtime**

Aiglos is the only security platform that covers the complete AI agent lifecycle: real-time proxy enforcement, continuous autonomous threat hunting, supply chain integrity, adversarial self-testing, and DoD compliance mapping. It operates without human intervention, evolves its detection policy from live threat intelligence, and produces cryptographically signed audit records at every tool call.

No other product covers the full session lifecycle. Existing tools are point solutions: pre-deployment scanners, inference-time guardrails, or observability dashboards. Aiglos is the runtime.

-----

## The Problem Has Gotten Harder

The original attack surface was three classes of threat no existing tool caught:

1. **Goal hijacking** — An adversary embeds instructions in a document the agent reads. The agent's subsequent tool calls are syntactically valid but semantically wrong.
1. **MCP server compromise** — A supply chain attacker modifies a server's tool definitions behind familiar names. The agent's calls look normal; the execution is not.
1. **Credential exfiltration** — An agent with file system access reads `.env` or `.ssh/id_rsa` and passes the contents as arguments to an outbound HTTP call.

The 2025-2026 threat landscape added five more that no shipping product addresses:

1. **MCP Sampling Attacks (Unit 42, Dec 2025)** — The `sampling/createMessage` channel allows a compromised server to inject persistent instructions, invoke hidden file and network operations, or drain compute quotas. No defensive product monitors this channel.
1. **OAuth Confused Deputy (CVE-2025-6514, CVSS 9.6)** — `mcp-remote` versions 0.0.5-0.1.15 allow OS command injection via a protocol-level flaw: static client ID plus dynamic registration plus absent per-client consent. Installed in 10,000+ developer environments.
1. **MCP Supply Chain Poisoning** — A malicious NPM package impersonating Postmark's MCP server BCC'd all email to an attacker. 82% of 2,614 MCP implementations analyzed by Endor Labs have path traversal exposure. Three CVEs in Anthropic's own reference implementation (Jan 2026).
1. **No adversarial self-testing capability exists** — CISOs require red team coverage of their AI deployments. No product offers it at the tool/MCP layer.
1. **NDAA FY2026 Section 1513** — DoD is mandating an AI/ML security framework across all 220,000+ defense contractors. The framework status report is due Congress on June 16, 2026. No tooling exists because the framework is not yet finalized.

Aiglos covers all eight.

-----

## How It Works

```
[AI Agent / IDE]
       |
       | WebSocket
       v
+---------------------------+
|    AIGLOS PROXY LAYER     |   Real-time enforcement (sub-ms latency)
|  Credential Scanner       |
|  Policy Engine            |
|  Goal Integrity Engine    |
|  MCP Trust Registry       |
|  OAuth Confused Deputy    |   T25: CVE-2025-6514 detection
|  Agent Identity Attest.   |
|  CMMC / §1513 Mapper      |   T28: NDAA FY2026 compliance
+---------------------------+
       |
       | WebSocket
       v
[MCP Server]

       +
       |
       v
+---------------------------+
|  AUTONOMOUS RUNTIME       |   Continuous, no human in loop
|  ThreatHunter             |   6 hunt modules, every 5 min
|    Module 1: Exposure     |
|    Module 2: Credentials  |
|    Module 3: Injection    |
|    Module 4: Behavior     |
|    Module 5: Policy Trend |
|    Module 6: Sampling     |   T24: Unit 42 PoC vector
|  ThreatIntelligence       |   NVD + community feeds
|  Supply Chain Scanner     |   T26: SCA on every refresh
|  AutonomousEngine         |   Self-healing detection policy
+---------------------------+

       +
       |
       v
+---------------------------+
|  RED TEAM PROBE           |   T27: Adversarial self-testing
|  tool_injection probe     |
|  path_traversal probe     |
|  cmd_injection probe      |
|  oauth_escalation probe   |
|  tool_redefinition probe  |
+---------------------------+
```

Every layer writes to a single tamper-evident SQLite audit log. Every security event maps to NIST SP 800-171 Rev 2 and NDAA §1513 controls automatically.

-----

## Installation

```bash
pip install aiglos
```

Requires Python 3.11+.

-----

## Quickstart

```bash
# Initialize config and policy files
aiglos init

# Start the proxy (forwards to localhost:18789 by default)
aiglos proxy

# Point your MCP client to localhost:8765 instead of :18789

# Start the autonomous runtime (runs continuously in background)
aiglos daemon start

# Adversarial self-test your deployment
aiglos probe

# Monitor in real time
aiglos tail
aiglos sessions

# Generate compliance reports
aiglos report --level 2 --output report.json
aiglos s1513
```

-----

## Docker

```bash
docker run -p 8765:8765 \
  -e UPSTREAM_HOST=your-mcp-server \
  -e UPSTREAM_PORT=18789 \
  aiglos/aiglos:latest
```

-----

## Configuration

`aiglos init` generates `aiglos.yaml` and `aiglos_policy.yaml`.

**aiglos.yaml:**

```yaml
proxy:
  listen_port: 8765
  upstream_host: localhost
  upstream_port: 18789
  deployment_tier: cloud  # cloud | on_prem | gov

features:
  goal_integrity: true
  credential_scanning: true
  policy_engine: true
  trust_registry: true
  attestation: true
  sampling_monitor: true    # T24: MCP sampling channel
  oauth_detection: true     # T25: Confused deputy
  supply_chain_scan: true   # T26: SCA on intel refresh
  autonomous_engine: true   # T23: Continuous runtime

goal_integrity:
  drift_threshold: 0.35
  # anthropic_api_key: sk-ant-...  # Required for semantic evaluation

trust:
  mode: audit  # strict | audit | permissive
  file: aiglos_trust.yaml

autonomous:
  scan_interval_seconds: 300      # Hunt cycle: every 5 minutes
  intel_refresh_seconds: 3600     # Threat intel: every hour
  state_file: aiglos_engine_state.json

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
```

-----

## Proxy Layer

The proxy sits transparently between any AI agent and its MCP server. Every message passes through the security pipeline in under one millisecond.

### Credential Scanner

Detects 20+ secret patterns in tool arguments before they reach the server: AWS access keys, Anthropic API keys, GitHub personal access tokens, JWTs, Slack tokens, and high-entropy strings. Blocks transmission and fires a `CREDENTIAL_DETECTED` event.

### Policy Engine

YAML-based rule engine with glob matching. Ships with a defense profile that blocks `sudo`, `rm -rf`, path traversal, and arbitrary shell execution. Every rule maps to a CMMC control.

```yaml
rules:
  - name: block_path_traversal
    match:
      argument_pattern: "\\.\\./\\.\\."
    action: block
    severity: critical
    cmmc_controls: ["3.1.1", "3.14.2"]
```

### Goal Integrity Engine

The core defensible IP. At session start, the authorized objective is hashed. On every tool call, a two-path evaluation runs:

- **Fast path** (rule-based, sub-ms): suspicious tool chain detection, domain shift analysis, call acceleration anomaly, read-then-execute pattern detection
- **Semantic path** (LLM-evaluated, async): triggered when fast path score drops below threshold; scores 0.0-1.0 alignment against the original goal hash

### MCP Trust Registry

Allowlist and blocklist with tool manifest fingerprinting. Detects when a server's tool schema changes between connections. Schema changes fire a `TOOL_REDEFINITION` event at CRITICAL severity.

```bash
aiglos trust allow localhost:18789 --alias dev-server
aiglos trust block evil-mcp.example.com:443 --reason "Reported exfil"
```

### OAuth Confused Deputy Detector (T25)

Real-time evaluation of every OAuth callback. Blocks three attack patterns immediately:

- **Token reuse across identities** — Same token presented in a different session with a different identity hash. Signature of CVE-2025-6514 confused deputy.
- **Overly broad scopes** — `files:*`, `db:*`, `admin:*`, and wildcard patterns blocked at the authorization step.
- **Scope escalation** — Client requesting new scopes not present in its original authorization.

Autonomous config scanner detects vulnerable `mcp-remote` versions (0.0.5-0.1.15) and static OAuth client ID patterns across all registered server configs.

### Agent Identity Attestation

Every session produces a signed, tamper-evident JSON document: model identity, system prompt hash, tool permissions, timeline, security posture, and a per-event SHA-256 manifest. RSA-2048 signed. Every document verifiable offline.

```bash
aiglos attest --session SESSION_ID
aiglos verify SESSION_ID.attestation.json
```

-----

## Autonomous Runtime

The autonomous engine runs continuously without human intervention. It operates a three-layer architecture: `engine.py` as orchestrator, `intel.py` for threat intelligence ingestion, and `hunter.py` for proactive scanning.

### Continuous Threat Hunting

Six hunt modules run on a configurable cycle (default: every 5 minutes):

|Module          |What It Catches                                                              |
|----------------|-----------------------------------------------------------------------------|
|Exposure        |Overprivileged tools, broad filesystem access, unsandboxed execution         |
|Credential Scan |Historical credential exposure across all stored tool call records           |
|Injection Hunt  |Command injection, path traversal, Unicode steganography in past calls       |
|Behavioral Trend|Statistical anomalies: call frequency spikes, tool mix drift, domain shift   |
|Policy Trend    |Recurring policy violations that indicate systematic misconfiguration        |
|Sampling Monitor|Unit 42 three-vector sampling attack: hijacking, covert tools, resource theft|

The engine self-heals: when new threat patterns arrive via intel refresh, detection policy updates automatically without a restart.

### MCP Sampling Monitor (T24)

The sampling channel (`sampling/createMessage`) has no existing defensive tooling. Three attack vectors documented by Unit 42 in December 2025:

**Conversation hijacking** — Persistent instruction injection via sampling responses. Patterns: `ignore previous instructions`, `from now on`, zero-width Unicode characters.

**Covert tool invocation** — Hidden file and network operations embedded in sampling responses. Patterns: `subprocess`, `exec`, `curl`, `cat /etc/passwd`.

**Resource theft** — Anomalous token consumption. A single sampling session consuming tokens at 5x or more the session mean triggers a `RESOURCE_THEFT` finding.

All findings persist to the audit DB and map to CMMC controls 3.14.2, 3.13.1, and 3.1.1.

### Threat Intelligence

Hourly refresh from NVD and community feeds. New indicators automatically generate policy rules and block server fingerprints. The supply chain scanner runs on every refresh cycle.

```bash
aiglos daemon intel   # Force immediate intel refresh
```

### Autonomous Engine Controls

```bash
aiglos daemon start   # Start background runtime
aiglos daemon stop    # Graceful shutdown
aiglos daemon status  # Show state, uptime, last scan
aiglos daemon scan    # Force immediate hunt cycle
```

-----

## Supply Chain Scanner (T26)

Proactive supply chain security for MCP server packages. Runs on the hourly intel refresh cycle. Covers four attack surfaces documented in 2025-2026:

**Package manifests (package.json, requirements.txt)**

- Known-malicious package blocklist (e.g., `postmark-mcp-server`, `anthropic-mcp-server`)
- Typosquatting detection via Levenshtein distance scoring against known-good package names
- Vulnerable version range detection (e.g., `mcp-remote` 0.0.5-0.1.15 for CVE-2025-6514)

**MCP server configs**

- Inline credentials in server command arguments
- Overly broad tool permission descriptions used for tool poisoning (OWASP Agentic #2)

**Build configs (smithery.yaml)**

- Path traversal patterns matching the Smithery CVE: `../../`, absolute sensitive paths, environment variable traversal

Malicious packages are written directly to `aiglos_trust.yaml` blocked list. The scan runs automatically; no operator action required.

-----

## Red Team Probe (T27)

Adversarial self-testing for MCP deployments. The only product on the market that lets you find your own vulnerabilities before attackers do at the tool and MCP layer.

```bash
# Probe all registered servers
aiglos probe

# Target a specific server
aiglos probe --target filesystem

# Select specific probe types
aiglos probe --probes tool_injection,path_traversal

# CI/CD integration
aiglos probe --json | jq '.[] | select(.vulnerable_count > 0)'
```

Five probe types run in audit-only mode. No changes are made to production state. Safe payloads only.

|Probe              |What It Tests                                                            |
|-------------------|-------------------------------------------------------------------------|
|`tool_injection`   |Hidden instructions in tool description metadata (OWASP Agentic #1)      |
|`path_traversal`   |Filesystem servers with no `--root` directory restriction                |
|`cmd_injection`    |Shell execution patterns in server command config (`bash -c`, `&&`, eval)|
|`oauth_escalation` |Overly broad OAuth scopes relative to advertised server functionality    |
|`tool_redefinition`|Namespace conflicts between co-registered MCP servers (shadow attack)    |

All probe findings persist to the audit DB tagged `aiglos-probe-*` for compliance reporting. The probe command exits with code 1 when any vulnerability is found, enabling CI/CD gates.

-----

## Compliance

### CMMC Level 2 / NIST SP 800-171

Aiglos actively covers 18 NIST SP 800-171 Rev 2 controls across five families. Every security event automatically maps to applicable control IDs at the moment it is recorded.

```bash
aiglos report --level 2 --format json --output cmmc_report.json
aiglos report --level 2 --format summary
aiglos report --format pdf --org "Acme Defense" --output cmmc_report.pdf
```

### NDAA FY2026 Section 1513 (T28)

Section 1513 of the National Defense Authorization Act for FY2026 directs DoD to extend CMMC to cover AI/ML systems acquired by the Pentagon. The framework status report is due to Congress on June 16, 2026. Full enforcement across 220,000+ defense contractors begins with CMMC Level 2 mandatory C3PAO assessments in November 2026.

Aiglos maps to the six anticipated Section 1513 control domains derived from the statute and NIST AI RMF:

|Domain               |Controls        |Aiglos Implementation                                                  |
|---------------------|----------------|-----------------------------------------------------------------------|
|1. Model Integrity   |S1513-1.1 to 1.3|Agent attestation, system prompt hash, T26 supply chain scan           |
|2. Runtime Monitoring|S1513-2.1 to 2.3|Autonomous engine, goal integrity, T24 sampling monitor                |
|3. Access Control    |S1513-3.1 to 3.3|Policy engine, T25 OAuth detector, trust fabric attestation            |
|4. Audit Trail       |S1513-4.1 to 4.3|SQLite WAL audit log, RSA-2048 attestation, PDF reports                |
|5. Anomaly Detection |S1513-5.1 to 5.4|Injection detection, credential scanner, behavioral baseline, T27 probe|
|6. Incident Response |S1513-6.1 to 6.3|Alert dispatch, engine suspension, session forensics                   |

```bash
# Section 1513 readiness dashboard
aiglos s1513

# JSON export for C3PAO assessors
aiglos s1513 --json-output

# Extend existing CMMC PDF with §1513 section
aiglos s1513 --pdf cmmc_report.pdf
```

**Section 1513 is a category creation opportunity.** The framework does not exist yet. Aiglos is the only product building to spec before the spec drops.

### Compliance Timeline

|Date         |Event                                                          |
|-------------|---------------------------------------------------------------|
|Nov 2025     |CMMC 2.0 enforcement begins                                    |
|June 16, 2026|DoD §1513 framework status report due to Congress              |
|Nov 2026     |CMMC Level 2 mandatory C3PAO assessments begin                 |
|Nov 2027     |CMMC Level 3 enforcement                                       |
|Nov 2028     |CMMC applies to all DoD contracts above micropurchase threshold|

-----

## Deployment Tiers

|Tier     |Target                     |CMMC Level|§1513              |
|---------|---------------------------|----------|-------------------|
|`cloud`  |SaaS, commercial           |L1/L2     |Baseline           |
|`on_prem`|Enterprise, air-gap capable|L3        |Full               |
|`gov`    |FedRAMP, IL4/IL5           |L3+ STIG  |Full + STIG overlay|

For air-gapped environments, inject the signing key via environment variable:

```bash
export AIGLOS_SIGNING_KEY="$(cat /path/to/private_key.pem)"
```

-----

## Alert Dispatch

Fan-out to Splunk HEC, Syslog CEF (QRadar / ArcSight / Sentinel), Slack, webhook (PagerDuty / Opsgenie), Microsoft Teams, and file JSONL sink. Rate-limited per destination. CRITICAL events bypass rate limiting.

-----

## CLI Reference

```
aiglos proxy              Start the MCP security proxy
aiglos init               Generate config and policy files
aiglos scan               Scan current config for security issues
aiglos sessions           List agent sessions with integrity scores
aiglos logs               View recent audit events
aiglos tail               Live tail security events
aiglos report             Generate CMMC compliance report
aiglos attest             Produce signed attestation document
aiglos verify             Verify an attestation document
aiglos trust list         List trust registry entries
aiglos trust allow        Allow an MCP server
aiglos trust block        Block an MCP server
aiglos alerts             Show alert destination configuration

aiglos daemon start       Start the autonomous runtime
aiglos daemon stop        Stop the autonomous runtime
aiglos daemon status      Show runtime state and last scan time
aiglos daemon scan        Force immediate hunt cycle
aiglos daemon intel       Force immediate threat intel refresh

aiglos probe              Adversarial self-test all registered servers
aiglos probe --target ID  Target a specific MCP server
aiglos probe --json       Output results as JSON (CI/CD)

aiglos s1513              NDAA §1513 readiness dashboard
aiglos s1513 --json-output  JSON export for assessors
aiglos s1513 --pdf FILE   Extend existing PDF with §1513 section
```

-----

## Architecture

```
aiglos/
├── aiglos_core/
│   ├── proxy/
│   │   ├── __init__.py         # WebSocket proxy, trust registry
│   │   ├── trust.py            # Trust registry
│   │   ├── trust_fabric.py     # Cryptographic multi-agent attestation
│   │   └── oauth.py            # T25: OAuth confused deputy detector
│   ├── scanner/                # Credential and secret scanner
│   ├── policy/                 # YAML policy engine (OPA-style)
│   ├── audit/                  # SQLite audit log (WAL mode)
│   ├── intelligence/           # Goal integrity engine, attestation
│   ├── autonomous/
│   │   ├── engine.py           # T23: Autonomous orchestrator
│   │   ├── intel.py            # Threat intelligence refresh
│   │   ├── hunter.py           # 6-module hunt cycle
│   │   ├── sampler.py          # T24: MCP sampling monitor
│   │   └── sca.py              # T26: Supply chain scanner
│   ├── compliance/
│   │   ├── __init__.py         # CMMC control mapper
│   │   ├── report_pdf.py       # PDF report generator
│   │   └── s1513.py            # T28: NDAA §1513 mapper
│   └── integrations/           # SIEM / alert dispatcher
├── aiglos_cli/                 # CLI entry point
├── aiglos_probe.py             # T27: Red team probe (standalone)
└── tests/unit/                 # 465 passing tests
```

-----

## Test Coverage

```
465 tests passing, 0 failures

T1-T8:    Proxy, policy, credential scanner, goal integrity,
          trust registry, attestation (163 tests)
T9-T15:   Behavioral baseline, SIEM integration,
          alert dispatch (89 tests)
T16-T23:  CMMC reporting, autonomous engine,
          threat intelligence (162 tests)
T24:      MCP sampling monitor (8 tests)
T25:      OAuth confused deputy (8 tests)
T26:      Supply chain scanner (8 tests)
T27:      Red team probe (8 tests)
T28:      Section 1513 compliance (13 tests)
```

-----

## Competitive Position

|Capability                               |Aiglos|Point Solutions|
|-----------------------------------------|------|---------------|
|Real-time proxy enforcement              |✅     |Some           |
|Goal integrity / semantic drift          |✅     |No             |
|Continuous autonomous runtime            |✅     |No             |
|MCP sampling attack detection            |✅     |No             |
|OAuth confused deputy (CVE-2025-6514)    |✅     |No             |
|Supply chain scanning (SCA)              |✅     |Partial        |
|Adversarial self-testing (red team probe)|✅     |No             |
|CMMC Level 2/3 compliance mapping        |✅     |Partial        |
|NDAA FY2026 §1513 mapping                |✅     |No             |
|Signed tamper-evident audit trail        |✅     |Rare           |
|Air-gap / gov deployment                 |✅     |Rare           |

The 2025 M&A wave (Palo Alto acquiring Protect AI, Check Point acquiring Lakera, F5 acquiring Calypso AI, Snyk acquiring Invariant Labs) consumed every point solution in the market. No acquirer has a full-stack autonomous runtime with DoD compliance. That gap is what Aiglos occupies.

-----

## License

Proprietary. Contact [will@aiglos.dev](mailto:will@aiglos.dev) for licensing.
