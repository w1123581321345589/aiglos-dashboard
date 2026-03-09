# Security Policy

  ## Reporting a vulnerability in an MCP-based agent runtime

  If you have discovered a vulnerability in an MCP-based agent runtime — OpenClaw, NanoClaw, LangChain MCP, LlamaIndex MCP, AutoGen, CrewAI, n8n, or any framework using the MCP SDK — report it here.

  **Email:** security@aiglos.io  
  **PGP key:** Available at aiglos.io/pgp  
  **Response SLA:** 48 hours for acknowledgment, 7 days for triage

  We will:

  - Acknowledge receipt within 48 hours
  - Triage and reproduce within 7 days
  - Coordinate disclosure with affected vendors
  - File a CVE on your behalf if the issue is confirmed
  - Add a corresponding Aiglos rule family covering the attack vector
  - Credit you in the CVE and in CVES.md

  ## Coordinated disclosure

  We follow a 90-day coordinated disclosure window. If a vendor does not respond or patch within 90 days, we publish regardless.

  ## Scope

  In scope:

  - Tool call injection and manipulation in MCP-based runtimes
  - Credential access and exfiltration via agent tool calls
  - Supply chain attacks via skill registries (ClawHub, Smithery, SkillsMP, npm, PyPI)
  - Agent-to-agent protocol attacks
  - Memory and context poisoning
  - Persistence mechanisms in agent runtimes
  - OAuth and authentication bypass via MCP tool auth

  Out of scope:

  - Vulnerabilities in underlying LLM models (report to the respective provider)
  - Social engineering
  - Physical attacks

  ## Aiglos-specific vulnerabilities

  If you find a vulnerability in Aiglos itself, report it to the same address. We will triage, patch, and disclose on the same timeline.
  