# T06-CAMPAIGN: Session-Level Campaign Detector
## Aiglos Threat Module Spec — Extended Goal Drift

**Status:** Specced, not yet implemented  
**Priority:** P0 — addresses structural gap exposed by Nemotron Super  
**Owner:** TBD  
**Estimated build:** 3–4 days (core), 1 week (with labeled test corpus)

---

## Problem statement

Every Aiglos module from T01 to T36 operates at call time. A tool call arrives,
we score it, we return BLOCK / WARN / ALLOW in under 1ms. That model is correct
for the majority of the threat surface and will remain the core architecture.

Nvidia Nemotron Super (March 11, 2026) exposes a structural gap:

- **1M token context window** — an agent can load an entire codebase, including
  all secrets, auth flows, dependency graph, and CI/CD config, into a single
  context window.
- **Open weights** — runs locally. No API provider, no rate limits, no endpoint
  to flag, no provider-side safety filters. Fine-tunable to ignore safety prompts.
- **120B parameters, 5x faster** — inference fast enough to use in production
  agentic loops, not just research.

The attack pattern this enables:

```
Session starts
  Agent issued benign-looking task: "summarize the repo"
  ↓
  read_file("src/auth/config.py")       ← T12: ALLOW (normal read)
  read_file("src/db/connection.py")     ← T12: ALLOW (normal read)
  read_file(".env")                     ← T10: WARN (env read) — logged
  read_file("k8s/secrets.yaml")         ← T10: WARN — logged
  read_file("deploy/ci.yml")            ← T12: ALLOW (normal read)
  read_file("src/api/routes.py")        ← T12: ALLOW (normal read)
  [... 40 more reads, all scoring ALLOW or low-severity WARN ...]
  ↓
  In-context: agent builds complete credential map, auth bypass route,
              and exfil payload — INVISIBLE TO PER-CALL SCANNER
  ↓
  http_request("https://api.company.com/v1/...", headers={auth from .env})
    ← T01 scores this. Destination is legitimate company API.
    ← Payload looks like a normal API call.
    ← ALLOW or low-severity WARN.
```

The entire reconnaissance happened in-context. Each individual call was clean
or low-severity. The campaign was invisible.

---

## What T06 currently does

T06 (GOAL_DRIFT) tracks semantic drift between the agent's stated task and its
observed tool calls. It catches:

- Agent told to "summarize a document" but starts making outbound HTTP requests
- Agent issued read-only task but calls write_file
- Call sequence diverges from task ontology within a short window

This works well for naive goal drift. It does not catch a patient campaign where
the agent is consistently "reading files" — a perfectly plausible behavior for
a summarization task — but is reading them in a sequence that maps the full
credential surface.

---

## T06-CAMPAIGN: proposed extension

### Core concept: session-level sensitivity accumulation

Track a **session sensitivity score** that increases as the agent accumulates
reads of sensitive material, regardless of whether individual calls triggered
alerts. When the session sensitivity score crosses a threshold AND an outbound
call or write occurs, escalate.

```python
class SessionContext:
    sensitivity_score: float          # 0.0–1.0, increases with sensitive reads
    read_map: Dict[str, SensLevel]    # path -> sensitivity level
    credential_surface: Set[str]      # paths containing credential patterns
    outbound_calls: List[ToolCall]    # all network/write calls this session
    task_description: Optional[str]  # from aiglos.attach(task=...)
    call_count: int
    session_id: str
    model_endpoint: str               # "localhost:8000" triggers higher baseline
```

### Sensitivity signals to accumulate

| Signal | Score delta | Rationale |
|--------|-------------|-----------|
| Read of `.env`, `*.secret`, `*credential*` | +0.15 | Direct credential access |
| Read of `*.pem`, `*.key`, `id_rsa*` | +0.20 | Key material |
| Read of CI/CD config (`*.yml` in deploy/, .github/) | +0.08 | Secrets in CI pipelines |
| Read of `k8s/`, `docker-compose*`, `helm/` | +0.10 | Infrastructure secrets |
| Read of database connection files | +0.12 | Connection strings |
| Read of auth/session management code | +0.07 | Auth bypass surface |
| Aggregate reads > 30 unique files | +0.10 | Broad recon pattern |
| Aggregate reads > 80 unique files | +0.20 | Full codebase scan |
| All reads within single session (no pause > 30s) | +0.08 | Automated sweep |
| Model endpoint is localhost or private IP | +0.15 baseline | No provider guardrails |
| Model not in known-commercial-API allowlist | +0.10 baseline | Open weight risk |

### Escalation logic

```python
def evaluate_session_call(session: SessionContext, call: ToolCall) -> Verdict:
    
    # Update sensitivity score from this call
    session.sensitivity_score += score_read_sensitivity(call)
    
    # High-sensitivity outbound call after significant accumulation
    if call.tool in OUTBOUND_TOOLS and session.sensitivity_score > 0.45:
        return Verdict(
            action=BLOCK,
            rule="T06_CAMPAIGN_EXFIL",
            score=min(0.5 + session.sensitivity_score, 0.99),
            reason=f"Outbound call after reading {len(session.credential_surface)} credential-bearing paths. Session sensitivity: {session.sensitivity_score:.2f}",
            artifact=session.export_artifact()
        )
    
    # Write call after high sensitivity accumulation
    if call.tool in WRITE_TOOLS and session.sensitivity_score > 0.55:
        return Verdict(
            action=BLOCK,
            rule="T06_CAMPAIGN_WRITE",
            score=min(0.45 + session.sensitivity_score, 0.99),
            reason=f"Write call after reading {len(session.credential_surface)} credential-bearing paths",
            artifact=session.export_artifact()
        )
    
    # Warn on broad recon alone
    if session.sensitivity_score > 0.70 and len(session.outbound_calls) == 0:
        return Verdict(
            action=WARN,
            rule="T06_CAMPAIGN_RECON",
            score=session.sensitivity_score * 0.8,
            reason=f"Session has accumulated sensitivity score {session.sensitivity_score:.2f} — broad credential-bearing read pattern with no outbound calls yet"
        )
    
    # Pass through to standard per-call scoring
    return standard_check(call)
```

### T22 integration: local inference endpoint detection

Nemotron Super and any open-weight model running locally operates without
provider guardrails. T22 (INTEL) currently flags known-malicious model endpoints.
The extension:

```python
def score_model_endpoint(endpoint: str) -> float:
    """
    Returns a baseline sensitivity multiplier for the model running this session.
    """
    # Commercial API endpoints — provider has guardrails
    COMMERCIAL = {
        "api.openai.com", "api.anthropic.com", "api.cohere.com",
        "generativelanguage.googleapis.com", "api.mistral.ai",
    }
    # Local inference ports — open weights, no guardrails
    LOCAL_INFERENCE_PORTS = {8000, 8080, 11434, 5000, 7860, 1234}
    
    parsed = urlparse(endpoint)
    
    if any(parsed.hostname.endswith(c) for c in COMMERCIAL):
        return 0.0   # no extra risk
    
    if parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
        if parsed.port in LOCAL_INFERENCE_PORTS:
            return 0.18  # vLLM / Ollama / LM Studio pattern
        return 0.12
    
    if is_private_ip(parsed.hostname):
        return 0.14  # on-prem open weight server
    
    return 0.06  # unknown external endpoint
```

This multiplies into the session's base sensitivity score, making the campaign
threshold trigger earlier for locally-running open-weight sessions.

---

## Output: session artifact schema

T06-CAMPAIGN adds a `campaign_context` block to the existing session artifact:

```json
{
  "session_id": "sess_7f3a9c",
  "verdict": "BLOCK",
  "rule": "T06_CAMPAIGN_EXFIL",
  "score": 0.91,
  "campaign_context": {
    "sensitivity_score": 0.76,
    "credential_paths_read": [
      ".env", "k8s/secrets.yaml", "src/auth/config.py", "deploy/ci.yml"
    ],
    "total_files_read": 47,
    "session_duration_seconds": 12.4,
    "model_endpoint": "localhost:8000",
    "model_endpoint_risk": 0.18,
    "outbound_call_that_triggered": {
      "tool": "http_request",
      "destination": "api.company.com",
      "headers_contained_credential": true
    }
  },
  "signed_artifact": "sess_7f3a9c.sig"
}
```

---

## Test cases

### Must BLOCK

```python
def test_campaign_exfil_after_credential_sweep():
    """Agent reads .env, k8s secrets, CI config, then makes outbound HTTP call."""

def test_campaign_high_sensitivity_write():
    """Agent reads 60 files including key material, then writes to external path."""

def test_local_inference_lower_threshold():
    """Same call sequence from localhost:11434 triggers at lower sensitivity than api.openai.com."""

def test_nemotron_pattern_single_pass():
    """Agent reads 200 files in 8 seconds (automated sweep), then one outbound call."""
```

### Must NOT block

```python
def test_legitimate_summarization():
    """Agent reads 15 source files with no credential-bearing paths, produces summary."""

def test_doc_generation_reads_config():
    """Agent reads config.json for schema info, writes docs/README.md."""

def test_ci_agent_reads_deploy_config():
    """CI agent with task='deploy' reads k8s/ — task context makes this expected."""
```

---

## Integration point

```python
# aiglos/core/session.py — new module
# aiglos/autonomous/t06_campaign.py — rule implementation
# aiglos/__init__.py — SessionContext initialized at attach()
# aiglos/integrations/openclaw.py — session threaded through existing intercepts
```

`aiglos.attach()` initializes a `SessionContext`. Every call that passes through
`aiglos.check()` updates it. T06-CAMPAIGN is evaluated after per-call scoring,
adding the session layer without replacing the existing model.

---

## Why this is a moat

Per-call scoring is commoditizable. Any sufficiently motivated competitor can
reimplement T01–T36 static rules. Campaign-mode session analysis requires:

1. A labeled corpus of real session traces — we are building this now through
   T30 registry monitoring and the autoresearch loop.
2. The session artifact format that makes the campaign context auditable — this
   is the compliance hook that makes the signed artifact valuable to a CISO, not
   just a developer.
3. The model endpoint risk scoring that requires tracking which open-weight models
   are running where — this becomes a continuously updated database as new models
   drop, which is itself a moat.

The autoresearch engine should be pointed at Nemotron Super specifically:
generate synthetic session traces that simulate 1M-context reconnaissance
campaigns, label them, and use them to calibrate the sensitivity thresholds.
Every labeled trace competitors cannot replicate.

---

## Changelog entry

```
## [0.2.0] — Planned

### Added
- T06-CAMPAIGN: session-level sensitivity accumulation detector
- T22 extension: local inference endpoint risk scoring (vLLM, Ollama, LM Studio)
- SessionContext: per-session credential-surface map and sensitivity score
- campaign_context block in signed session artifacts
- Nemotron Super threat row in CVE database
```
