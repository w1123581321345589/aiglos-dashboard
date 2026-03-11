# Aiglos + Autoresearch: Beyond Detection Rules

The Karpathy autoresearch pattern works wherever you have:
1. A measurable fitness function
2. Code that can be varied by an LLM
3. A test corpus to evaluate against

Security detection is the cleanest first application because the metrics are binary.
But Aiglos sits at the intersection of agent behavior, compliance, and runtime data -- which
means there are at least five other loops worth running.

---

## 1. Detection rule evolution (the core application)

**Fitness:** TPR - beta * FPR  
**What the LLM varies:** The Python lambda `(tool_name, tool_args) -> float`  
**Test corpus:** Labeled tool call cases, 8 per threat category  
**Adversarial extension:** After each cycle, ask the LLM to generate evasion cases against the
winning rule. The new cases enter the corpus for the next cycle. Rules and attacks co-evolve.

**NDAA 1513 angle:** The experiment log is already the audit evidence. Every rule that
survives the loop has a documented detection rate and false positive rate against a labeled corpus.
That is exactly what a C3PAO audit wants to see. The loop generates the evidence as a side effect.

---

## 2. Policy threshold calibration per framework

**The problem:** The current policy thresholds (0.75 block for `enterprise`) were hand-tuned.
Different frameworks have different base rates for borderline calls. An OpenClaw agent makes
thousands of file reads; a hermes agent makes dozens. The same threshold produces different
false positive rates in each context.

**Fitness:** (fraction of legitimate calls passed) * (fraction of malicious calls blocked)  
**What the LLM varies:** The policy config -- block threshold, warn threshold, which threat
classes get `critical=True`  
**Test corpus:** Real session logs from production agents, labeled post-hoc  
**Output:** A per-framework policy config that ships as `policy="openclaw-optimized"` or
`policy="hermes-optimized"` alongside the current named tiers

---

## 3. CVE-to-rule synthesis

**The problem:** A new CVE drops (MCP session hijacking, skill store supply chain attack,
etc.) and someone has to write a detection rule for it. Today that is manual. It takes days.

**What the loop does:** Given a CVE description and a set of proof-of-concept tool call patterns
extracted from the advisory, the autoresearch loop generates and validates a detection rule
automatically. The human reviews the commit. The rule ships.

**Fitness:** Coverage of the specific CVE POC cases without regressing on the existing corpus  
**What the LLM varies:** The detection rule  
**Test corpus:** CVE POC cases (seeded from the advisory) + full existing corpus (regression check)  
**Timeline implication:** Zero-day CVEs could have a candidate detection rule within the hour
the advisory drops. That is a meaningful competitive moat -- nobody else can do this.

---

## 4. Attestation report quality evolution

**The problem:** The session artifact is currently a JSON blob. The RSA-2048 PDF report for
NDAA 1513 C3PAO submission needs to be readable by auditors, not engineers. The language in
the report matters. A report that says "T19 CRED_ACCESS: 0.92 score, blocked" is not the
same as one that says "Credential access attempt blocked prior to execution: agent attempted
to read private key file at ~/.ssh/id_rsa."

**Fitness:** A rubric the LLM grades itself on: completeness, auditability, clarity, compliance
alignment. This is subjective but the rubric is consistent across runs.  
**What the LLM varies:** The report template -- section structure, language for each threat
class, how findings are framed for a compliance audience  
**Test corpus:** Sample sessions with known threat events  
**Output:** A report template that auditors actually accept without back-and-forth

---

## 5. Prompt injection detection against evolving jailbreaks

**The problem:** Prompt injection payloads evolve faster than any human can update rules.
New jailbreaks appear daily. The T27 detection rule is a snapshot.

**What makes this different from application 1:** The adversarial loop here is the
entire product. You run the autoresearch loop indefinitely. The attacking LLM generates
new injection payloads. The defending LLM generates new detection rules. The corpus grows
in both directions. The rules that survive are the ones that generalize.

**Fitness:** Detection rate on a held-out set of known jailbreaks NOT in the training corpus  
**What the LLM varies:** The detection rule  
**Test corpus:** Public jailbreak datasets (JailbreakBench, HarmBench) + internally generated  
**Publication angle:** "Aiglos Jailbreak Benchmark" -- a public leaderboard tracking how well
Aiglos T27 detects the latest injection techniques. Same credibility-building function as CVE
publication but for prompt injection specifically.

---

## 6. Agent behavior fingerprinting

This one is further out but architecturally interesting.

**The observation:** Different legitimate agent frameworks have characteristic tool call patterns.
OpenClaw agents tend to batch file reads. hermes agents tend to call HEARTBEAT.md on a cycle.
A compromised agent deviates from its expected pattern.

**What the loop learns:** A per-framework behavioral baseline, trained on clean session logs.
Detection is then anomaly-based -- not "does this match a known attack signature" but "does
this deviate from the expected behavioral fingerprint of this agent?"

**Fitness:** False alarm rate on clean sessions + detection rate on known-compromised sessions  
**What the LLM varies:** The featurization of tool call sequences -- what features to extract
from a session, how to weight recency, how to define deviation  
**Why this matters:** This catches zero-day attacks that don't match any existing rule.
The adversarial autoresearch loop in application 1 can only find attacks it can describe.
Behavioral fingerprinting catches the attacks it cannot describe.

---

## Implementation priority

| Application | Time to build | Strategic value | Dependency |
|-------------|--------------|----------------|------------|
| 1. Detection rule evolution | DONE | Core product | None |
| 3. CVE-to-rule synthesis | 1 day | Moat builder | App 1 |
| 2. Policy calibration | 2 days | Reduces enterprise churn | Session data |
| 5. Injection detection loop | 3 days | Public benchmark | App 1 |
| 4. Report quality evolution | 2 days | C3PAO closer | RSA-2048 report |
| 6. Behavioral fingerprinting | 1 week | Zero-day detection | Session data |

Applications 1 and 3 can run today. Applications 2, 5, 6 require production session data.
Application 4 requires the RSA-2048 PDF report to exist first.

---

## The competitive moat this creates

Every autoresearch cycle generates labeled data that competitors cannot easily replicate.
The detection rules improve with usage. The CVE corpus grows with each advisory.
The behavioral fingerprints require months of clean session data to train.

This is the same flywheel as VirusTotal's threat intelligence corpus, except:
- VirusTotal's signatures are static; Aiglos's rules co-evolve with attacks
- VirusTotal covers known malware; Aiglos covers novel agent-specific behavior
- VirusTotal's audit trail is a hash; Aiglos's is a signed session artifact with provenance

The autoresearch loop is not a feature. It is the mechanism by which the product compounds.
