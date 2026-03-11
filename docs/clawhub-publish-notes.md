# Aiglos on ClawHub

**A note for OpenClaw's security-conscious operators.**

---

OpenClaw publishes a threat model at
[docs.openclaw.ai/security/THREAT-MODEL-ATLAS](https://docs.openclaw.ai/security/THREAT-MODEL-ATLAS).
It is thorough, honest, and structured on MITRE ATLAS. It also contains a
risk matrix that lists three threats as Critical P0 with "no current
mitigation" or "planned improvements" as the only remediation path:

| OpenClaw Threat ID | Description | Their residual risk |
|-------------------|-------------|---------------------|
| T-EXEC-001 | Direct prompt injection | Critical — detection only, no blocking |
| T-PERSIST-001 | Malicious skill installation | Critical — no sandboxing, limited review |
| T-EXFIL-003 | Credential harvesting via skill context | Critical — no mitigation specific to skills |

It also rates T-EXEC-004 (exec approval bypass), T-EXFIL-001 (data theft via
web_fetch), and T-IMPACT-001 (unauthorized command execution) as High residual
risk, with mitigations described as either in-progress or reliant on user
judgment.

Publishing on ClawHub closes all six of those gaps at the runtime layer —
before execution, not after.

---

## Why this publish matters

T-PERSIST-001 and T-PERSIST-002 in OpenClaw's own threat model describe the
ClawHub supply chain as a Critical attack surface: malicious skill installation
and skill update poisoning. Their current mitigations are GitHub account age
verification and a pattern-based moderation flag system that their own
documentation rates as "low effectiveness" against obfuscation.

Aiglos is a security skill that ships as a ClawHub skill. The artifact is
self-referential: installing a security monitor from the marketplace that the
security monitor is designed to protect is the cleanest possible signal that
the system works. If Aiglos can pass ClawHub's own moderation pipeline, the
runtime protection it provides is demonstrably above that baseline.

The narrative: their threat model says "supply chain is Critical." Their fix is
"VirusTotal integration — in progress." Aiglos ships runtime protection today,
distributed through the exact channel their threat model identifies as the
attack surface.

---

## Files in this publish

```
aiglos/
├── SKILL.md                   -- Main skill doc (OpenClaw integration)
├── aiglos_openclaw.py         -- Runtime module, pip install aiglos
├── aiglos_hermes.py           -- hermes-agent integration module
├── references/
│   ├── THREAT-MAP-OC.md       -- Aiglos T-number to OpenClaw ATLAS cross-map
│   ├── THREAT-MAP-HERMES.md   -- Aiglos T-number to hermes-agent surface map
│   └── NDAA-1513.md           -- NDAA §1513 compliance guide
└── assets/
    └── banner.png
```

---

## Publish checklist

- [ ] SKILL.md includes MITRE ATLAS cross-reference table
- [ ] aiglos_openclaw.py passes `python aiglos_openclaw.py demo` clean
- [ ] aiglos_hermes.py passes `python aiglos_hermes.py demo` clean
- [ ] No `--force` flags in install instructions
- [ ] No `eval()`, `os.system()`, or `subprocess` in skill code (static scan passes)
- [ ] HMAC secret documented as env var, not hardcoded
- [ ] Pricing table includes free tier
- [ ] Link to docs.openclaw.ai/security/THREAT-MODEL-ATLAS included
- [ ] agentskills.io frontmatter valid

---

## agentskills.io frontmatter

```yaml
---
name: aiglos
description: >
  Runtime security monitor for AI agents. Intercepts tool calls before
  execution, blocks T1-T36 threat classes, and produces signed session
  artifacts for audit and NDAA §1513 compliance. Closes the Critical P0
  gaps in OpenClaw's own MITRE ATLAS threat model.
version: 0.1.0
metadata:
  hermes:
    tags: [security, monitoring, compliance, ndaa, runtime]
    category: security
  aiglos:
    threat_classes: [T01,T05,T07,T08,T13,T19,T23,T28,T30,T34,T36]
    policies: [permissive, enterprise, strict, federal]
    attestation: hmac-sha256
    ndaa_1513: true
---
```
