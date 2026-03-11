# Changelog

All notable changes to Aiglos are documented here.

---

## [0.1.0] — 2026-03-12 — Public Launch

### Added

**Core detection engine**
- T1-T36 threat class library — 36 named threat classes across 7 categories
- Full MITRE ATLAS technique mapping for all threat classes
- Four policy modes: `permissive`, `enterprise`, `strict`, `federal`
- HMAC-SHA256 signed session artifacts after every heartbeat cycle
- Module-level one-liner API: `attach()` / `check()` / `on_heartbeat()` / `close()`
- Zero required dependencies — stdlib only for detection

**OpenClaw integration** (`aiglos.integrations.openclaw`)
- `OpenClawGuard` class with full T1-T36 detection on OpenClaw tool surface
- Heartbeat-aware session splitting (HEARTBEAT.md cycle tracking)
- Sub-agent guard hierarchy: `spawn_sub_guard()` for Doraemon/Ada/Prism
- `SessionArtifact` with per-cycle audit records and NDAA §1513 flag
- Closes all six Critical/High residual-risk gaps in OpenClaw's own MITRE ATLAS threat model
- ClawHub `SKILL.md` with MITRE ATLAS cross-reference table

**hermes-agent integration** (`aiglos.integrations.hermes`)
- `HermesGuard` class covering hermes-specific tool surfaces:
  - `MEMORY.md` / `USER.md` write injection (T36)
  - `SOUL.md` / `AGENTS.md` payload detection (T05)
  - `cron/` and `HEARTBEAT.md` tampering (T34)
  - `delegate_task` audit trail (T23)
  - `~/.hermes/.env` / `auth.json` credential access (T19)
  - batch runner trajectory signing: `sign_trajectory()`
- Skills hub `SKILL.md` for agentskills.io compatible distribution

**CVE database**
- 10 published CVEs covering T07, T13, T19, T30, T34, T36

**Documentation**
- NDAA §1513 compliance guide
- MITRE ATLAS threat map
- OpenClaw and hermes-agent integration guides

### Architecture

Detection engine is entirely zero-dependency. Optional `cryptography` package
unlocks RSA-2048 signing for Pro/Enterprise attestation. `full` extras add
CLI tooling (`rich`, `click`, `structlog`).

### Known limitations

- TypeScript package (`@aiglos/core`) not yet published — Q2 2026
- RSA-2048 PDF report for NDAA §1513 submission — Q2 2026
- LangChain, LlamaIndex, AutoGen, CrewAI integrations — Q2 2026

---

## [0.0.1] — 2026-01-15 — Internal Alpha

Initial architecture. T1-T33 detection, MCP proxy prototype, OpenClaw integration draft.
