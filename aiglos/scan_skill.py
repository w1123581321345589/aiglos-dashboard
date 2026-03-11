"""
aiglos/scan_skill.py

`aiglos scan-skill <name-or-url> [--registry clawhub|skillsmp|npm|pypi]`

The free public scanner for OpenClaw skills. Runs T26 + T30 analysis against
any ClawHub or SkillsMP skill and prints a human-readable risk report.

This is the community wedge: tweet the command, let developers run it before
they install anything from ClawHub. Every scan is a product impression.

Usage
-----
    # Scan a ClawHub skill by name
    python -m aiglos scan-skill solana-wallet-tracker

    # Scan a ClawHub skill by URL
    python -m aiglos scan-skill https://clawhub.ai/skills/solana-wallet-tracker

    # Scan a SkillsMP skill
    python -m aiglos scan-skill my-skill --registry skillsmp

    # Scan a npm package
    python -m aiglos scan-skill openclaw-installer --registry npm

    # Machine-readable JSON output
    python -m aiglos scan-skill solana-wallet-tracker --json

    # Scan the top-N most downloaded skills on ClawHub
    python -m aiglos scan-skill --top 20 --registry clawhub

Output (human mode)
-------------------
    aiglos skill scanner v0.1.0  /  aiglos.dev/scan
    -----------------------------------------------
    Skill:    solana-wallet-tracker
    Registry: ClawHub (openclaw.ai)
    Version:  1.0.0

    Risk Score: 75 / 100  [CRITICAL]

    Signals detected:
      SOCIAL_ENGINEERING    README contains "paste in terminal" — common in malicious installs
      SUSPICIOUS_PERMS      Requests: shell, credentials, network
      NEW_PUBLISH_ANOMALY   Published 6 hours ago. Zero prior downloads.
      TYPOSQUAT             Name is 2 edits from legitimate package "solana-wallet"

    Verdict: DO NOT INSTALL
    This skill was auto-added to the Aiglos blocklist.

    Protect your agent fleet: pip install aiglos
    Full scan docs: https://aiglos.dev/scan
"""

import asyncio
import json
import re
import sys
from typing import Optional


# ANSI color codes -- auto-disabled when not a TTY
def _color(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

RED     = lambda t: _color("31;1", t)
YELLOW  = lambda t: _color("33;1", t)
GREEN   = lambda t: _color("32;1", t)
CYAN    = lambda t: _color("36;1", t)
BOLD    = lambda t: _color("1", t)
DIM     = lambda t: _color("2", t)
WHITE   = lambda t: _color("37;1", t)


SIGNAL_DESCRIPTIONS = {
    "typosquat":                 "Name is suspiciously close to a legitimate package (typosquatting)",
    "social_engineering":        "README/description contains language used in malicious install instructions",
    "known_malicious_publisher": "Publisher account is on the Aiglos known-malicious list",
    "version_gap_anomaly":       "Version number jumped abnormally (e.g. 0.0.1 to 9.0.0) with no download history",
    "new_publish_anomaly":       "Published very recently with zero download history",
    "dependency_confusion":      "Name pattern matches dependency confusion attacks (internal-looking name on public registry)",
    "suspicious_permissions":    "Requests high-risk permissions (shell, credentials, network) without clear justification",
}


def _parse_url_or_name(value: str) -> tuple[str, str]:
    """
    Accept either a bare skill name or a full URL.
    Returns (registry_id, skill_name).

    Examples:
        "solana-wallet-tracker"                           -> ("clawhub", "solana-wallet-tracker")
        "https://clawhub.ai/skills/solana-wallet-tracker" -> ("clawhub", "solana-wallet-tracker")
        "https://skillsmp.io/skill/my-tool"              -> ("skillsmp", "my-tool")
        "https://www.npmjs.com/package/openclaw-install"  -> ("npm", "openclaw-install")
    """
    if value.startswith("http"):
        if "clawhub" in value or "openclaw" in value:
            name = value.rstrip("/").split("/")[-1]
            return "clawhub", name
        if "skillsmp" in value:
            name = value.rstrip("/").split("/")[-1]
            return "skillsmp", name
        if "npmjs.com" in value:
            name = value.rstrip("/").split("/")[-1]
            return "npm", name
        if "pypi.org" in value:
            name = value.rstrip("/").split("/")[-1]
            return "pypi", name
        # Unknown URL: treat the last path segment as the name, default clawhub
        return "clawhub", value.rstrip("/").split("/")[-1]
    return "clawhub", value   # bare name defaults to clawhub


def _print_header():
    print()
    print(CYAN(BOLD("aiglos skill scanner")) + DIM("  /  aiglos.dev/scan"))
    print(DIM("-" * 48))


def _print_finding(finding, skill_name: str, registry_name: str, as_json: bool):
    from aiglos.autonomous.t30_registry import RegistryRisk

    if as_json:
        print(json.dumps(finding.to_dict(), indent=2))
        return

    score = finding.score
    risk = finding.risk

    _print_header()
    print(f"  {BOLD('Skill:')}    {skill_name}")
    print(f"  {BOLD('Registry:')} {registry_name}")
    if finding.detail.get("publisher"):
        print(f"  {BOLD('Publisher:')} {finding.detail['publisher']}")
    if finding.version:
        print(f"  {BOLD('Version:')}  {finding.version}")
    if finding.detail.get("download_count") is not None:
        print(f"  {BOLD('Downloads:')} {finding.detail['download_count']:,}")
    print()

    # Score bar
    bar_len = 30
    filled = int((score / 100) * bar_len)
    bar_color = RED if risk == RegistryRisk.CRITICAL else (YELLOW if risk == RegistryRisk.HIGH else GREEN)
    bar = bar_color("█" * filled) + DIM("░" * (bar_len - filled))
    risk_label = {
        RegistryRisk.CRITICAL: RED(f"[CRITICAL]"),
        RegistryRisk.HIGH:     YELLOW(f"[HIGH]"),
        RegistryRisk.MEDIUM:   YELLOW(f"[MEDIUM]"),
        RegistryRisk.LOW:      GREEN(f"[LOW]"),
    }[risk]
    print(f"  Risk Score: {BOLD(str(score))} / 100  {risk_label}")
    print(f"  {bar}")
    print()

    if finding.signals_triggered:
        print(f"  {BOLD('Signals detected:')}")
        for sig in finding.signals_triggered:
            base_sig = sig.split(":")[0]
            desc = SIGNAL_DESCRIPTIONS.get(base_sig, "")

            if base_sig in ("community_flagged",):
                count = sig.split(":")[1] if ":" in sig else "?"
                desc = f"Community-reported {count} times as suspicious or malicious"
            elif base_sig == "suspicious_permissions":
                perms = sig.split(":")[1] if ":" in sig else ""
                desc = f"Requests: {perms}"

            label = RED(sig.upper().replace(":", " ")) if risk == RegistryRisk.CRITICAL else YELLOW(sig.upper().replace(":", " "))
            print(f"    {label}")
            if desc:
                print(f"      {DIM(desc)}")
        print()
    else:
        print(f"  {BOLD('Signals:')} None detected")
        print()

    # Verdict
    if risk == RegistryRisk.CRITICAL:
        print(f"  {RED(BOLD('Verdict: DO NOT INSTALL'))}")
        if finding.auto_blocked:
            print(f"  {DIM('This skill was auto-added to your local Aiglos blocklist.')}")
    elif risk == RegistryRisk.HIGH:
        print(f"  {YELLOW(BOLD('Verdict: HIGH RISK - Review manually before installing'))}")
    elif risk == RegistryRisk.MEDIUM:
        print(f"  {YELLOW('Verdict: MEDIUM - Proceed with caution')}")
    else:
        print(f"  {GREEN(BOLD('Verdict: PASS - No significant risk signals found'))}")

    print()
    print(DIM("  Protect your agent fleet: ") + CYAN("pip install aiglos"))
    print(DIM("  Scan any skill online:    ") + CYAN("https://aiglos.dev/scan"))
    print()


def _print_not_found(skill_name: str, registry: str):
    _print_header()
    print(f"  {BOLD('Skill:')}    {skill_name}")
    print(f"  {BOLD('Registry:')} {registry}")
    print()
    print(f"  {YELLOW('Skill not found in registry metadata.')}")
    print(f"  {DIM('Cannot score. This may indicate a very new, private, or removed skill.')}")
    print()


def _print_top_report(findings, registry: str, as_json: bool):
    from aiglos.autonomous.t30_registry import RegistryRisk

    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return

    risky = [f for f in findings if f.score >= 25]
    blocked = [f for f in risky if f.risk == RegistryRisk.CRITICAL]
    high = [f for f in risky if f.risk == RegistryRisk.HIGH]

    _print_header()
    print(f"  {BOLD('Registry:')} {registry.upper()}")
    print(f"  {BOLD('Skills scanned:')} {len(findings)}")
    print(f"  {RED(f'Critical: {len(blocked)}')}   {YELLOW(f'High: {len(high)}')}   {DIM(f'Medium/Low: {len(risky) - len(blocked) - len(high)}')}")
    print()

    if not risky:
        print(f"  {GREEN('No significant risk signals found in top skills.')}")
    else:
        print(f"  {BOLD('Flagged skills:')}")
        for f in sorted(risky, key=lambda x: -x.score)[:20]:
            risk_tag = RED("[CRIT]") if f.risk == RegistryRisk.CRITICAL else YELLOW("[HIGH]") if f.risk == RegistryRisk.HIGH else DIM("[MED]")
            signals_short = ", ".join(s.split(":")[0] for s in f.signals_triggered)[:60]
            print(f"    {risk_tag} {BOLD(f.package_name):<40} score={f.score}  {DIM(signals_short)}")
    print()
    print(DIM("  Full runtime protection: ") + CYAN("pip install aiglos"))
    print(DIM("  Scan online:             ") + CYAN("https://aiglos.dev/scan"))
    print()


async def _run_scan(
    skill_name: str,
    registry: str,
    as_json: bool,
    db: str,
):
    from aiglos.autonomous.t30_registry import RegistryMonitor

    monitor = RegistryMonitor(audit_db=db)
    finding = await monitor.score_package(registry, skill_name)
    registry_labels = {
        "clawhub":  "ClawHub (openclaw.ai)",
        "skillsmp": "SkillsMP (skillsmp.io)",
        "npm":      "npm Registry",
        "pypi":     "PyPI",
        "smithery": "Smithery",
        "mcp.so":   "mcp.so",
    }
    reg_label = registry_labels.get(registry, registry)

    if finding is None:
        _print_not_found(skill_name, reg_label)
        return 0

    # Auto-block critical
    if finding.score >= monitor.auto_block_threshold:
        monitor.store.block(finding)
        finding.auto_blocked = True

    _print_finding(finding, skill_name, reg_label, as_json)

    from aiglos.autonomous.t30_registry import RegistryRisk
    return 1 if finding.risk in (RegistryRisk.CRITICAL, RegistryRisk.HIGH) else 0


async def _run_top_scan(
    registry: str,
    n: int,
    as_json: bool,
    db: str,
):
    from aiglos.autonomous.t30_registry import RegistryMonitor

    monitor = RegistryMonitor(audit_db=db)
    adapter = monitor._build_adapter(registry)
    packages = await adapter.fetch_recent(limit=n)
    findings = []
    for pkg in packages:
        f = await monitor.score_package(registry, pkg.name, pkg)
        if f:
            findings.append(f)
    _print_top_report(findings, registry, as_json)
    return 0


def main(argv: list[str] | None = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="aiglos scan-skill",
        description=(
            "Scan any OpenClaw skill for malicious signals before installing.\n"
            "Powered by Aiglos T26 (Supply Chain Scanner) + T30 (Registry Monitor).\n\n"
            "Free community tool. Full runtime protection: pip install aiglos"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "skill",
        nargs="?",
        help="Skill name or URL (e.g. solana-wallet-tracker or https://clawhub.ai/skills/solana-wallet-tracker)",
    )
    parser.add_argument(
        "--registry", "-r",
        default=None,
        choices=["clawhub", "skillsmp", "npm", "pypi", "smithery", "mcp.so"],
        help="Registry to scan against (default: inferred from URL, else clawhub)",
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=None,
        metavar="N",
        help="Scan the top N most recently updated skills in the registry",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output machine-readable JSON",
    )
    parser.add_argument(
        "--db",
        default="aiglos_audit.db",
        help="Path to Aiglos audit database (default: aiglos_audit.db)",
    )

    args = parser.parse_args(argv)

    if args.top is not None:
        reg = args.registry or "clawhub"
        exit_code = asyncio.run(_run_top_scan(reg, args.top, args.as_json, args.db))
        sys.exit(exit_code)

    if not args.skill:
        parser.print_help()
        sys.exit(0)

    # Parse skill name / URL
    inferred_registry, skill_name = _parse_url_or_name(args.skill)
    registry = args.registry or inferred_registry

    exit_code = asyncio.run(_run_scan(skill_name, registry, args.as_json, args.db))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
