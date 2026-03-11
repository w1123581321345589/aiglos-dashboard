# Changelog

All notable changes to Aiglos are documented here.

---

## [0.1.1] — 2026-03-11 — Pre-launch session

### Added

**`aiglos/autoresearch/` — detection rule evolution engine**
- `corpus.py`: 32 labeled test cases across 4 threat categories (CRED_ACCESS, PROMPT_INJECT, SHELL_INJECT, SSRF), 4 malicious / 4 safe per category. Seed corpus is ground truth for all autoresearch evaluation.
- `loop.py`: `AutoresearchLoop` -- LLM-driven optimization loop that proposes improved detection rules, evaluates on `TPR - beta * FPR`, keeps the winner, and optionally runs adversarial case generation every N rounds
- `loop.py`: `evaluate_rule()` -- deterministic evaluator scoring any `(tool_name, tool_args) -> float` callable against labeled corpus
- `loop.py`: Adversarial expansion -- after each interval, asks LLM to generate evasion cases against current best rule; adds only cases that actually evade; corpus and rules co-evolve
- `loop.py`: Git commit support -- winning rules auto-committed with TPR/FPR/fitness in commit message
- `loop.py`: Experiment log output -- every run writes a JSON audit record (TPR, FPR, fitness per round, adversarial cases added, final rule). This log is the NDAA §1513 audit trail.
- CLI: `python -m aiglos autoresearch --category CRED_ACCESS --rounds 20 --adversarial`
- `tests/test_autoresearch.py`: 21 tests covering corpus integrity, rule evaluation mechanics, edge cases (exception handling, null rule, perfect selective rule), and spot checks on labeled cases

**`CLAUDE.md`** (repo root)
- Added: architecture map, T-number system, detection rule anatomy, key data types, naming conventions, policy thresholds, decisions already made (do not re-litigate section)

**`skills/openclaw/SKILL.md`** -- rewritten as a teaching document
- Restructured: opens with "what you are putting on" not an install command
- Added: OpenClaw threat model gap table with their own residual risk ratings
- Added: VirusTotal quote from their docs explaining what their scanner does not cover
- Added: explicit "What Aiglos does not do" section handling NanoClaw and VirusTotal questions

**`skills/hermes/SKILL.md`** -- rewritten as a teaching document
- Added: hermes-specific attack surface table mapping every hermes file/feature to Aiglos rule
- Added: `sign_trajectory()` use case with filtering pattern for RL training data integrity
- Restructured: leads with threat surface, not install instructions

**`README.md`**
- "What just happened" section: updated from 2 events to 4 events (Amazon outage Mar 10, OpenClaw threat model Mar 10, China Bloomberg ban Mar 11, NDAA deadline Jun 16)
- Added: "Using memory stacks?" section -- maps every memory stack write-target (SOUL.md, MEMORY.md, Obsidian vault via MCP, cron/, secrets) to the Aiglos threat class covering it

**`docs/autoresearch-applications.md`**
- Six creative applications of autoresearch beyond detection rules: policy threshold calibration per framework, CVE-to-rule synthesis, attestation report quality evolution, prompt injection detection loop with public benchmark, behavioral fingerprinting for zero-day detection
- Implementation priority table with time estimates and dependencies

**`aiglos/__main__.py`**
- Wired `python -m aiglos autoresearch` to `aiglos.autoresearch.loop.main`

### Changed

**`pitch/Aiglos_AD_Updated.pptx`** (now v3)
- Slide 4 (Why Now): updated title from "Three events" to "Four events"; China Bloomberg ban added as fourth event (Mar 11, 2026); prior NDAA §1513 slot repurposed
- Slide 11 (Team): Marshall Sanford column fully removed; associated Armed Services Committee, Boeing/Lockheed/Booz Allen, "CO-FOUNDER (IN CONVERSATION)", and "political infrastructure" text removed; right panel layout cleaned up

**`pitch/KB_Memo.docx`** (now v3)
- Bloomberg China ban paragraph added after Promptfoo acquisition paragraph in Why Now section
- Marshall Sanford paragraph removed
- PhishLabs cofounder advisor paragraph removed  
- Heikenwälder/DKFZ reference removed from milestones section
- Closing relationship capital paragraph rewritten to reference only D/CDAO and Okta
- TPM Sciences removed from founder bio venture list

**`skills/openclaw/SKILL.md`**, **`skills/hermes/SKILL.md`**
- Domain corrected: `.io` references replaced with `.dev` throughout

### Tests

- 40 existing core tests: all passing
- 21 new autoresearch tests: all passing
- Total: 61 tests passing

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
