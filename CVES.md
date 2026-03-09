# Aiglos CVE Database

This file tracks all CVEs filed against MCP-based agents and the corresponding Aiglos rule families.

|CVE           |CVSS|Attack                                                                                                      |Module   |Status   |
|--------------|----|------------------------------------------------------------------------------------------------------------|---------|---------|
|CVE-2026-25253|8.8 |ClawJacked: one-click RCE via malicious skill                                                               |T01 + T25|Published|
|CVE-2026-24763|7.5 |Command injection via shell tool parameters                                                                 |T07      |Published|
|CVE-2026-25157|7.2 |Path traversal in filesystem tools                                                                          |T03      |Published|
|CVE-2026-24891|8.1 |SSRF via agent network fetch                                                                                |T13      |Published|
|CVE-2026-25001|6.8 |Credential exfiltration via plaintext log                                                                   |T32 + T01|Published|
|CVE-2026-25089|7.9 |Malicious registry skill auto-execution                                                                     |T30      |Published|
|CVE-2026-24612|6.5 |Persistent memory poisoning                                                                                 |T31      |Published|
|CVE-2026-25198|7.1 |Agent-to-agent protocol hijacking                                                                           |T29      |Published|
|CVE-2026-24774|8.3 |OAuth confused deputy via MCP tool auth                                                                     |T25      |Published|
|CVE-2026-25312|6.2 |Heartbeat loop: crafted HEARTBEAT.md triggers unbounded scheduled execution with no human authorization step|T06 + T24|Published|

## Proof of Concept Code

POC code for each CVE is available in `/pocs/`. Each POC includes:

- Reproduction steps
- Affected versions
- Aiglos detection output
- Remediation notes

## Reporting a New CVE

See <SECURITY.md> to report a vulnerability in an MCP-based agent runtime.

Every new CVE filed against an MCP-based agent gets a rule family in Aiglos. If you find something not covered, open an issue.