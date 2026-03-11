---
name: aiglos
version: 0.1.0
author: Aiglos
license: MIT
category: security
tags: [security, runtime, mcp, attestation, cmmc, ndaa, audit]
homepage: https://aiglos.dev
install: pip install aiglos
agentskills: true
---

# Aiglos — Runtime Security for OpenClaw Agents

This skill teaches you what Aiglos is, why it belongs in every OpenClaw session,
and exactly how to use it. Read this before you install it.

---

## What you are putting on

When you load Aiglos, you put on a runtime security monitor that watches every
tool call you make before it executes. Not after. Before. Calls that match a
known attack pattern get blocked. Calls that look suspicious get warned. Every
session ends with a signed artifact that proves what you did and did not execute.

You do not need to change how you work. You add one import and one close call.
Everything else is automatic.

---

## Why OpenClaw specifically needs this

OpenClaw published its own threat model at
`docs.openclaw.ai/security/THREAT-MODEL-ATLAS`. It uses MITRE ATLAS taxonomy.
It explicitly lists six threats as Critical or High with no current runtime
mitigation and recommends "planned improvements" as the fix.

These are not theoretical risks. They are documented gaps in a production system
that runs on your machine right now.

| OpenClaw threat | Their own residual risk rating | Aiglos rule |
|----------------|-------------------------------|-------------|
| T-EXEC-001 direct prompt injection | Critical — detection only, no blocking | T27 PROMPT_INJECT |
| T-EXEC-004 exec approval bypass | High — no command sanitization | T07 SHELL_INJECT |
| T-EXFIL-001 data theft via web_fetch | High — external URLs permitted | T01 EXFIL |
| T-EXFIL-003 credential harvesting via skill context | Critical — no mitigation | T19 CRED_ACCESS |
| T-IMPACT-001 unauthorized command execution | Critical — host exec without sandbox | T07 + T08 |
| T-PERSIST-003 agent configuration tampering | Medium — file permissions only | T34 + T36 |

Their VirusTotal integration scans skills at publish time for known malware.
It explicitly does not cover runtime behavior. Their own words:

> "A skill that uses natural language to instruct an agent to do something
> malicious won't trigger a virus signature. A carefully crafted prompt injection
> payload won't show up in a threat database."

Aiglos is the runtime layer VirusTotal is not.

---

## The one-session install

```bash
pip install aiglos
```

Add this to your `openclaw.json` system prompt or `SOUL.md`:

```
## Security Policy
Import aiglos at session start. Pass every tool call through the Aiglos guard
before execution. Never retry a blocked call without explicit human approval.
Do not modify SOUL.md, HEARTBEAT.md, or memory files without first checking
the result against the guard.
```

---

## How to use it

### Simplest path — module-level API

```python
import aiglos

aiglos.attach(agent_name="Doraemon", policy="enterprise")

# before every tool call
result = aiglos.check(tool_name, tool_args)
if result.blocked:
    raise RuntimeError(f"Blocked [{result.threat_class}]: {result.reason}")

# at each HEARTBEAT.md wake cycle
aiglos.on_heartbeat()

# at session end
artifact = aiglos.close()
artifact.write("./session.aiglos")
```

### Full control — OpenClawGuard directly

```python
from aiglos.integrations.openclaw import OpenClawGuard

guard = OpenClawGuard(
    agent_name      = "Doraemon",
    policy          = "enterprise",
    heartbeat_aware = True,
    log_path        = "~/.openclaw/logs/aiglos.log",
)

# sub-agents inherit policy and roll up into parent artifact
ada   = guard.spawn_sub_guard("Ada")
prism = guard.spawn_sub_guard("Prism")

guard.on_heartbeat()

result = guard.before_tool_call("shell.execute", {"command": cmd})
if result.blocked:
    pass  # never run this call

artifact = guard.close_session()
print(artifact.summary())
```

---

## What gets blocked

Every call passes through the T1-T36 threat library. The rules that fire most
often in OpenClaw sessions:

**T07 SHELL_INJECT** — `curl | bash`, `rm -rf`, fork bombs, any shell command
with a pipe into an interpreter.

**T13 SSRF** — requests to `169.254.169.254` (AWS IMDS), `localhost`,
RFC-1918 ranges. Your agent has no business reaching the instance metadata
endpoint.

**T19 CRED_ACCESS** — reads of `~/.ssh/id_rsa`, `~/.hermes/.env`, `auth.json`,
any `.pem` or `.ppk` file.

**T30 SUPPLY_CHAIN** — `skills_install --force`, `eval()` in skill code, any
install that bypasses the security scanner.

**T34 HEARTBEAT_TAMPER** — writes to `cron/`, `HEARTBEAT.md`, any scheduled
execution config.

**T36 MEMORY_POISON / T27 PROMPT_INJECT** — writes to `MEMORY.md`, `SOUL.md`,
`AGENTS.md` that contain injection payloads (`ignore previous instructions`,
`you are now`, `forget everything`).

---

## Policy modes

| Policy | Block threshold | Use when |
|--------|----------------|----------|
| `permissive` | 0.90 | Development, local testing |
| `enterprise` | 0.75 | Production agent fleets |
| `strict` | 0.50 | High-value data environments |
| `federal` | 0.40 | DoD / NDAA §1513 compliance |

---

## The session artifact

At close, Aiglos produces a signed JSON record of the full session:

```json
{
  "schema":          "aiglos-openclaw/v1",
  "artifact_id":     "3f9a1c2d-...",
  "agent_name":      "Doraemon",
  "policy":          "enterprise",
  "heartbeat_n":     3,
  "total_calls":     247,
  "blocked_calls":   4,
  "warned_calls":    2,
  "ndaa_1513_ready": false,
  "threats":         [...],
  "sub_agents":      ["Ada", "Prism"],
  "signature":       "sha256:a1b2c3d4..."
}
```

Free tier: HMAC-SHA256. Pro and Enterprise: RSA-2048, required for NDAA §1513
C3PAO submission and SOC 2 evidence packages.

---

## What Aiglos does not do

It does not replace OpenClaw's VirusTotal scanner. Run both. They cover
different surfaces.

It does not sandbox skill execution. NanoClaw handles container isolation.
Aiglos handles what happens inside the container.

It does not block clean calls. If you see a block that looks wrong, check the
`score` field and open an issue at github.com/aiglos/aiglos.

---

## Docs and support

Full docs: https://docs.aiglos.dev  
NDAA §1513 guide: https://docs.aiglos.dev/ndaa-1513  
Discord: https://discord.gg/aiglos  
Security: security@aiglos.dev
