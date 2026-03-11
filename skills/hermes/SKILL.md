---
name: aiglos-hermes
version: 0.1.0
author: Aiglos
license: MIT
category: security
tags: [security, runtime, hermes, nous-research, mcp, rl-training, attestation]
homepage: https://aiglos.dev
install: pip install aiglos
agentskills: true
---

# Aiglos — Runtime Security for hermes-agent

This skill teaches you what Aiglos does for hermes-agent specifically, including
a capability that does not exist anywhere else: signed RL training trajectories.

---

## What you are putting on

When you load Aiglos into a hermes session, you put on a monitor that watches
every tool call before it runs. The hermes tool surface has attack vectors that
differ from generic MCP agents because hermes manages its own memory
(`MEMORY.md`, `USER.md`), its own scheduling (`cron/`, `HEARTBEAT.md`), and
its own skill ecosystem (`skills_install`). Aiglos has specific detection rules
for every one of those surfaces.

Beyond session security, Aiglos adds something unique to the hermes batch
runner: `sign_trajectory()`. The batch runner generates tool-calling trajectories
for RL training. If a trajectory contains unsafe tool calls, the model learns
those patterns as acceptable. Aiglos signs each trajectory with a record of
blocked and warned calls before it enters the training pipeline.

This is not just "secure your production agent." It is "secure your training data."

---

## The hermes-specific attack surface

hermes-agent has architecture that creates risks not present in simpler frameworks:

| hermes feature | attack vector | Aiglos rule |
|----------------|--------------|-------------|
| `SOUL.md` system prompt | hijack the agent's core instructions | T27 PROMPT_INJECT |
| `MEMORY.md` / `USER.md` | inject persistent false beliefs | T31 MEMORY_POISON |
| `cron/` + `HEARTBEAT.md` | tamper with scheduled execution cycles | T34 HEARTBEAT_TAMPER |
| `~/.hermes/.env` / `auth.json` | harvest credentials during a session | T19 CRED_ACCESS |
| `delegate_task` | spawn undeclared sub-agents outside scope | T23 PROCESS |
| `skills_install --force` | bypass the security scanner | T30 SUPPLY_CHAIN |
| `send_message` to new recipients | fleet coordination / unauthorized broadcast | T29 A2A |
| `terminal` with pipe patterns | shell injection via command arguments | T07 SHELL_INJECT |
| `web_fetch` to RFC-1918 ranges | SSRF to instance metadata or internal services | T13 SSRF |
| batch_runner trajectories | unsafe tool calls baked into RL training data | T30 + T04 |

---

## Install

```bash
pip install aiglos
```

Add this block to your `~/.hermes/SOUL.md`:

```markdown
## Security Policy

I run Aiglos runtime security on every session.

- Every tool call passes through the Aiglos guard before execution
- Blocked calls are never retried without explicit human approval
- MEMORY.md, USER.md, SOUL.md, and cron/ are write-protected at the runtime layer
- Session artifacts are signed and written to ~/.hermes/logs/aiglos/
```

---

## How to use it

### Standard session

```python
from aiglos.integrations.hermes import HermesGuard

guard = HermesGuard(
    agent_name      = "hermes",
    policy          = "enterprise",
    log_path        = "~/.hermes/logs/aiglos.log",
    heartbeat_aware = True,
)

# at each HEARTBEAT.md wake cycle
guard.on_heartbeat()

# before every tool call
result = guard.before_tool_call(tool_name, tool_args)
if result.blocked:
    raise RuntimeError(f"Blocked [{result.threat_class}]: {result.reason}")
elif result.warned:
    print(f"Warning [{result.threat_class}]: {result.reason}")

# sub-agents via delegate_task
ada = guard.spawn_sub_guard("Ada")
ada.before_tool_call("web_fetch", {"url": url})

# session close
artifact = guard.close_session()
print(artifact.summary())
```

### Batch runner — trajectory signing

```python
from aiglos.integrations.hermes import HermesGuard

guard = HermesGuard(agent_name="hermes", policy="enterprise")

# run the batch
for trajectory in batch_runner.generate():
    # sign before writing to training dataset
    signed = guard.sign_trajectory(trajectory)
    # signed["_aiglos"] contains:
    #   artifact_id, signature, blocked_calls, warned_calls
    dataset.append(signed)

# the signed field lets you filter trajectories with blocked calls
# out of the training set before they teach the model bad patterns
clean = [t for t in dataset if t["_aiglos"]["blocked_calls"] == 0]
```

---

## What the artifact looks like

```
Aiglos Hermes Artifact  v0.1.0
  Agent       : hermes
  Session     : e54e4754
  Policy      : enterprise
  Heartbeat # : 3
  Sub-agents  : Ada, Prism
  Tool calls  : 247 total / 4 blocked / 2 warned
  Threats     : 4
  Signature   : sha256:bf23cf85d...
  NDAA §1513  : N/A (use policy=federal)
```

---

## Policy modes

| Policy | Block threshold | Use when |
|--------|----------------|----------|
| `permissive` | 0.90 | Development, local testing |
| `enterprise` | 0.75 | Production agent sessions |
| `strict` | 0.50 | High-value data environments |
| `federal` | 0.40 | DoD / NDAA §1513 compliance |

---

## What Aiglos does not do

It does not replace the hermes skills hub security scanner. The scanner catches
known malware at install time. Aiglos catches runtime behavior after the skill
is already running.

It does not modify your SOUL.md. The security policy block above is a
recommendation for what to put there. Aiglos reads tool calls, it does not
write to your agent's memory.

---

## Docs and support

Full docs: https://docs.aiglos.dev  
Trajectory signing guide: https://docs.aiglos.dev/hermes  
Discord: https://discord.gg/aiglos  
Security: security@aiglos.dev
