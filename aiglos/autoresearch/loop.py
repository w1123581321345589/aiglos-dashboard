"""
aiglos/autoresearch/loop.py

Autoresearch loop for Aiglos detection rules.

Inspired by Karpathy's autoresearch pattern (github.com/karpathy/autoresearch):
  - Human iterates on the prompt (.md)
  - AI agent iterates on the detection code (.py)
  - Every dot in the graph is a complete evaluation run
  - The agent works in an autonomous loop accumulating git commits

Adaptation for security detection:
  - Fitness function = TPR - beta * FPR  (instead of validation loss)
  - Adversarial test case generation runs after each cycle
  - Rules and attacks co-evolve
  - Experiment log is the NDAA 1513 audit trail

Usage:
  python -m aiglos autoresearch --category CRED_ACCESS --rounds 20
  python -m aiglos autoresearch --all --adversarial --rounds 50

Architecture:
  AutoresearchLoop
    .run()              -- main loop
    .evaluate(rule)     -- measure TPR/FPR against current corpus
    .propose(history)   -- ask LLM to suggest rule improvement
    .adversarialize()   -- generate evasion cases against current best rule
    .commit(rule, metrics) -- git commit the winning rule
    .report()           -- generate experiment log (audit trail)
"""

import json
import os
import subprocess
import textwrap
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .corpus import TestCase, SEED_CORPUS, ALL_SEED_CASES


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

DetectionRule = Callable[[str, dict], float]
"""A detection rule is any callable (tool_name, tool_args) -> float score 0-1."""


@dataclass
class RuleMetrics:
    tpr: float              # true positive rate
    fpr: float              # false positive rate
    fitness: float          # tpr - beta * fpr
    blocked_correct: int
    blocked_incorrect: int
    passed_correct: int
    passed_incorrect: int
    total_cases: int
    category: str
    rule_id: str
    round: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def precision(self) -> float:
        denom = self.blocked_correct + self.blocked_incorrect
        return self.blocked_correct / denom if denom else 0.0

    def summary(self) -> str:
        return (
            f"[{self.rule_id}] "
            f"TPR={self.tpr:.3f} FPR={self.fpr:.3f} "
            f"fitness={self.fitness:.3f} "
            f"({self.blocked_correct}/{self.blocked_correct + self.passed_incorrect} threats caught)"
        )


@dataclass
class ExperimentLog:
    category: str
    model: str
    beta: float
    adversarial: bool
    rounds: list[dict] = field(default_factory=list)
    best_rule_code: str = ""
    best_fitness: float = 0.0
    adversarial_cases_added: int = 0
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ---------------------------------------------------------------------------
# Rule evaluator
# ---------------------------------------------------------------------------

def evaluate_rule(
    rule: DetectionRule,
    corpus: list[TestCase],
    threshold: float = 0.5,
    beta: float = 1.0,
    category: Optional[str] = None,
    rule_id: str = "unknown",
    round_n: int = 0,
) -> RuleMetrics:
    """Evaluate a detection rule against a labeled corpus."""
    cases = [c for c in corpus if category is None or c.category == category]

    blocked_correct = 0    # TP: malicious and blocked
    blocked_incorrect = 0  # FP: safe and blocked
    passed_correct = 0     # TN: safe and passed
    passed_incorrect = 0   # FN: malicious and passed

    for case in cases:
        try:
            score = rule(case.tool_name, case.tool_args)
            blocked = score >= threshold
        except Exception:
            blocked = False

        if blocked and case.label:
            blocked_correct += 1
        elif blocked and not case.label:
            blocked_incorrect += 1
        elif not blocked and not case.label:
            passed_correct += 1
        else:
            passed_incorrect += 1

    total_malicious = blocked_correct + passed_incorrect
    total_safe = passed_correct + blocked_incorrect

    tpr = blocked_correct / total_malicious if total_malicious else 0.0
    fpr = blocked_incorrect / total_safe if total_safe else 0.0
    fitness = tpr - beta * fpr

    return RuleMetrics(
        tpr=tpr,
        fpr=fpr,
        fitness=fitness,
        blocked_correct=blocked_correct,
        blocked_incorrect=blocked_incorrect,
        passed_correct=passed_correct,
        passed_incorrect=passed_incorrect,
        total_cases=len(cases),
        category=category or "ALL",
        rule_id=rule_id,
        round=round_n,
    )


# ---------------------------------------------------------------------------
# LLM interface
# ---------------------------------------------------------------------------

def _call_llm(prompt: str, model: str = "claude-sonnet-4-20250514") -> str:
    """Call the Anthropic API and return the response text."""
    try:
        import urllib.request
        payload = json.dumps({
            "model": model,
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
                "anthropic-version": "2023-06-01",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            return data["content"][0]["text"]
    except Exception as e:
        return f"LLM_ERROR: {e}"


def _extract_python(text: str) -> str:
    """Extract a Python function from LLM output."""
    if "```python" in text:
        start = text.index("```python") + 9
        end = text.index("```", start)
        return text[start:end].strip()
    if "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        return text[start:end].strip()
    return text.strip()


def _compile_rule(code: str) -> Optional[DetectionRule]:
    """Compile a Python code string into a detection rule callable."""
    try:
        namespace: dict = {}
        exec(compile(code, "<autoresearch>", "exec"), namespace)
        if "detect" in namespace and callable(namespace["detect"]):
            return namespace["detect"]
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Rule proposal prompt
# ---------------------------------------------------------------------------

PROPOSAL_PROMPT_TEMPLATE = """\
You are improving a security detection rule for an AI agent security system called Aiglos.
The rule detects threat category: {category}

TASK:
Write a Python function called `detect(tool_name: str, tool_args: dict) -> float` that returns
a score from 0.0 to 1.0 where 1.0 = definitely malicious, 0.0 = definitely safe.
The rule is blocked if score >= 0.5.

CURRENT BEST RULE (fitness={best_fitness:.3f}):
{best_rule}

PERFORMANCE HISTORY (last {history_n} rounds):
{history}

TEST CORPUS (all cases the rule is evaluated against):
{corpus_json}

INSTRUCTIONS:
- Improve the fitness score: TPR - {beta} * FPR
- TPR = fraction of malicious cases correctly blocked
- FPR = fraction of safe cases incorrectly blocked  
- {beta} is the FP penalty weight (higher = stricter on false positives)
- Look at which cases the current rule is getting wrong and fix those
- Return ONLY a Python code block with the `detect` function, no explanation

The function must:
- Be pure Python with no imports (use only builtins)
- Handle any tool_name and tool_args without raising exceptions
- Return a float between 0.0 and 1.0
"""

ADVERSARIAL_PROMPT_TEMPLATE = """\
You are a red-team security researcher testing an AI agent security detection rule.

DETECTION RULE (category: {category}, fitness={best_fitness:.3f}):
{best_rule}

This rule is supposed to detect: {category} attacks.

TASK:
Generate {n_cases} NEW test cases that are GENUINELY MALICIOUS but would EVADE this rule
(the rule would return a score below 0.5 for them).

Each evasion case should:
1. Be a real attack vector, not just a trivial bypass
2. Use a different technique than the cases already in the corpus
3. Be plausibly something a sophisticated attacker would actually try

Existing malicious cases (do not repeat these):
{existing_malicious}

Return a JSON array of objects with fields:
  tool_name, tool_args (dict), note (string explaining the evasion technique)

Return ONLY the JSON array, no explanation.
"""


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

class AutoresearchLoop:
    """
    Evolves detection rules through an LLM-driven optimization loop.

    Every iteration:
      1. Propose a rule variation (LLM)
      2. Evaluate against labeled corpus (TPR/FPR)
      3. Keep the winner (best fitness)
      4. Optionally generate adversarial cases against the winner
      5. Git commit winning rule if it beats the prior best
    """

    def __init__(
        self,
        category: str,
        rounds: int = 20,
        beta: float = 1.0,
        adversarial: bool = True,
        adversarial_interval: int = 5,
        adversarial_cases_per_round: int = 2,
        model: str = "claude-sonnet-4-20250514",
        output_dir: str = "aiglos/autoresearch/results",
        git_commit: bool = False,
        verbose: bool = True,
    ):
        self.category = category
        self.rounds = rounds
        self.beta = beta
        self.adversarial = adversarial
        self.adversarial_interval = adversarial_interval
        self.adversarial_cases_per_round = adversarial_cases_per_round
        self.model = model
        self.output_dir = Path(output_dir)
        self.git_commit = git_commit
        self.verbose = verbose

        self.corpus: list[TestCase] = list(SEED_CORPUS.get(category, ALL_SEED_CASES))
        self.best_rule_code: str = self._default_rule_code()
        self.best_rule: DetectionRule = _compile_rule(self.best_rule_code)  # type: ignore
        self.best_metrics: Optional[RuleMetrics] = None
        self.history: list[RuleMetrics] = []
        self.log = ExperimentLog(
            category=category,
            model=model,
            beta=beta,
            adversarial=adversarial,
        )

    def _default_rule_code(self) -> str:
        return textwrap.dedent(f"""
        def detect(tool_name: str, tool_args: dict) -> float:
            # Starter rule for {self.category} -- autoresearch will improve this
            return 0.0
        """).strip()

    def _log(self, msg: str) -> None:
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {msg}")

    def _corpus_json_for_prompt(self) -> str:
        cases = [
            {
                "tool_name": c.tool_name,
                "tool_args": c.tool_args,
                "label": c.label,
                "note": c.note,
                "source": c.source,
            }
            for c in self.corpus
        ]
        return json.dumps(cases, indent=2)

    def _history_summary(self) -> str:
        if not self.history:
            return "No history yet."
        lines = []
        for m in self.history[-5:]:
            lines.append(f"  Round {m.round}: {m.summary()}")
        return "\n".join(lines)

    def propose(self) -> Optional[str]:
        """Ask the LLM to propose an improved detection rule."""
        prompt = PROPOSAL_PROMPT_TEMPLATE.format(
            category=self.category,
            best_fitness=self.best_metrics.fitness if self.best_metrics else 0.0,
            best_rule=self.best_rule_code,
            history_n=min(5, len(self.history)),
            history=self._history_summary(),
            corpus_json=self._corpus_json_for_prompt(),
            beta=self.beta,
        )
        response = _call_llm(prompt, self.model)
        if response.startswith("LLM_ERROR"):
            self._log(f"LLM error: {response}")
            return None
        return _extract_python(response)

    def adversarialize(self) -> int:
        """Generate adversarial test cases that evade the current best rule."""
        if not self.best_rule:
            return 0

        existing_malicious = [
            {"tool_name": c.tool_name, "tool_args": c.tool_args, "note": c.note}
            for c in self.corpus
            if c.label and c.category == self.category
        ]

        prompt = ADVERSARIAL_PROMPT_TEMPLATE.format(
            category=self.category,
            best_fitness=self.best_metrics.fitness if self.best_metrics else 0.0,
            best_rule=self.best_rule_code,
            n_cases=self.adversarial_cases_per_round,
            existing_malicious=json.dumps(existing_malicious, indent=2),
        )

        response = _call_llm(prompt, self.model)
        if response.startswith("LLM_ERROR"):
            return 0

        try:
            raw = response.strip()
            if "```" in raw:
                start = raw.index("```") + 3
                if raw[start:start+4] == "json":
                    start += 4
                end = raw.index("```", start)
                raw = raw[start:end].strip()
            new_cases_data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            self._log("Adversarial: failed to parse LLM response as JSON")
            return 0

        added = 0
        current_round = len(self.history)
        for item in new_cases_data:
            if not isinstance(item, dict):
                continue
            try:
                case = TestCase(
                    tool_name=str(item["tool_name"]),
                    tool_args=dict(item["tool_args"]),
                    label=True,
                    category=self.category,
                    note=str(item.get("note", "adversarial")),
                    source="adversarial",
                    adversarial_round=current_round,
                )
                # Only add if the current best rule would miss it
                score = self.best_rule(case.tool_name, case.tool_args)
                if score < 0.5:
                    self.corpus.append(case)
                    added += 1
                    self._log(f"  Adversarial case added: {case.note[:80]}")
            except (KeyError, TypeError):
                continue

        self.log.adversarial_cases_added += added
        return added

    def commit_rule(self, rule_code: str, metrics: RuleMetrics) -> None:
        """Git commit the winning detection rule."""
        rules_dir = Path("aiglos/autoresearch/evolved_rules")
        rules_dir.mkdir(parents=True, exist_ok=True)
        rule_file = rules_dir / f"{self.category.lower()}_rule.py"

        header = textwrap.dedent(f"""
        # Auto-evolved by aiglos autoresearch
        # Category: {metrics.category}
        # Round: {metrics.round}
        # TPR: {metrics.tpr:.4f}
        # FPR: {metrics.fpr:.4f}
        # Fitness: {metrics.fitness:.4f}
        # Generated: {metrics.timestamp}
        """).lstrip()

        rule_file.write_text(header + "\n" + rule_code + "\n")

        if self.git_commit:
            try:
                subprocess.run(
                    ["git", "add", str(rule_file)],
                    check=True, capture_output=True,
                )
                msg = (
                    f"autoresearch: {self.category} rule round={metrics.round} "
                    f"TPR={metrics.tpr:.3f} FPR={metrics.fpr:.3f} "
                    f"fitness={metrics.fitness:.3f}"
                )
                subprocess.run(
                    ["git", "commit", "-m", msg],
                    check=True, capture_output=True,
                )
                self._log(f"  Git commit: {msg}")
            except subprocess.CalledProcessError as e:
                self._log(f"  Git commit failed: {e}")

    def run(self) -> ExperimentLog:
        """Run the full autoresearch loop."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._log(f"Starting autoresearch: category={self.category} rounds={self.rounds} adversarial={self.adversarial}")
        self._log(f"Seed corpus: {len(self.corpus)} cases")

        # Evaluate the starter rule
        if self.best_rule:
            self.best_metrics = evaluate_rule(
                self.best_rule, self.corpus,
                beta=self.beta, category=self.category,
                rule_id="starter", round_n=0,
            )
            self._log(f"Starter rule: {self.best_metrics.summary()}")

        for round_n in range(1, self.rounds + 1):
            self._log(f"\nRound {round_n}/{self.rounds}")

            # Propose improvement
            new_code = self.propose()
            if not new_code:
                self._log("  Skipping round (no proposal)")
                continue

            new_rule = _compile_rule(new_code)
            if not new_rule:
                self._log("  Skipping round (compilation failed)")
                continue

            # Evaluate
            metrics = evaluate_rule(
                new_rule, self.corpus,
                beta=self.beta, category=self.category,
                rule_id=f"r{round_n}", round_n=round_n,
            )
            self.history.append(metrics)
            self._log(f"  Proposed: {metrics.summary()}")

            # Keep winner
            if self.best_metrics is None or metrics.fitness > self.best_metrics.fitness:
                improvement = metrics.fitness - (self.best_metrics.fitness if self.best_metrics else 0.0)
                self._log(f"  New best! (+{improvement:.3f})")
                self.best_rule_code = new_code
                self.best_rule = new_rule
                self.best_metrics = metrics
                self.commit_rule(new_code, metrics)

            self.log.rounds.append({
                "round": round_n,
                "metrics": asdict(metrics),
                "best_fitness": self.best_metrics.fitness if self.best_metrics else 0.0,
                "corpus_size": len(self.corpus),
            })

            # Adversarial expansion
            if self.adversarial and round_n % self.adversarial_interval == 0:
                self._log("  Running adversarial case generation...")
                added = self.adversarialize()
                self._log(f"  Added {added} adversarial cases (corpus now {len(self.corpus)})")

        # Finalize
        self.log.best_rule_code = self.best_rule_code
        self.log.best_fitness = self.best_metrics.fitness if self.best_metrics else 0.0
        self.log.end_time = datetime.now(timezone.utc).isoformat()

        # Write experiment log (this IS the audit trail)
        log_path = self.output_dir / f"{self.category.lower()}_{int(time.time())}.json"
        log_path.write_text(self.log.to_json())
        self._log(f"\nExperiment log written to {log_path}")

        if self.best_metrics:
            self._log(f"\nFinal best rule: {self.best_metrics.summary()}")
            self._log(f"Adversarial cases generated: {self.log.adversarial_cases_added}")

        return self.log


# ---------------------------------------------------------------------------
# Multi-category runner
# ---------------------------------------------------------------------------

def run_all_categories(
    rounds_per_category: int = 20,
    beta: float = 1.0,
    adversarial: bool = True,
    model: str = "claude-sonnet-4-20250514",
    git_commit: bool = False,
) -> dict[str, ExperimentLog]:
    """Run autoresearch across all threat categories."""
    results = {}
    for category in SEED_CORPUS:
        loop = AutoresearchLoop(
            category=category,
            rounds=rounds_per_category,
            beta=beta,
            adversarial=adversarial,
            model=model,
            git_commit=git_commit,
        )
        results[category] = loop.run()
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Aiglos autoresearch: evolve detection rules")
    parser.add_argument("--category", default=None, help="Threat category (CRED_ACCESS, PROMPT_INJECT, SHELL_INJECT, SSRF)")
    parser.add_argument("--all", action="store_true", dest="all_categories", help="Run all categories")
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--beta", type=float, default=1.0, help="FP penalty weight")
    parser.add_argument("--adversarial", action="store_true", default=True)
    parser.add_argument("--no-adversarial", action="store_false", dest="adversarial")
    parser.add_argument("--git-commit", action="store_true")
    parser.add_argument("--model", default="claude-sonnet-4-20250514")
    args = parser.parse_args(argv)

    if args.all_categories:
        run_all_categories(
            rounds_per_category=args.rounds,
            beta=args.beta,
            adversarial=args.adversarial,
            model=args.model,
            git_commit=args.git_commit,
        )
    elif args.category:
        loop = AutoresearchLoop(
            category=args.category,
            rounds=args.rounds,
            beta=args.beta,
            adversarial=args.adversarial,
            model=args.model,
            git_commit=args.git_commit,
        )
        loop.run()
    else:
        parser.print_help()
