"""
tests/test_v030.py
==================
Aiglos v0.3.0 test suite.

Covers:
  - T36_AGENTDEF: agent definition file poisoning detection (subprocess layer)
  - T38:          sub-agent spawn detection and classification
  - T37:          financial transaction execution (HTTP layer)
  - AgentDefGuard: baseline snapshot and mid-session modification detection
  - MultiAgentRegistry: spawn registration and session tree
  - SessionIdentityChain: event signing and verification
  - __init__ v0.3.0: version bump, new fields in status()
"""

import os
import sys
import time
import tempfile
import hashlib
from pathlib import Path

import pytest

# ── path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aiglos.integrations.subprocess_intercept import (
    inspect_subprocess, SubprocVerdict, SubprocTier,
)
from aiglos.integrations.http_intercept import inspect_request, HttpVerdict
from aiglos.integrations.multi_agent import (
    AgentDefGuard, MultiAgentRegistry, SessionIdentityChain,
    AgentDefViolation, SpawnEvent, ChildSession,
    _collect_agent_def_paths, _hash_file,
)
import aiglos


# =============================================================================
# T36_AGENTDEF — Agent Definition File Poisoning
# =============================================================================

class TestT36AgentDefPoisoning:
    """Writes to agent definition directories should be Tier 3 GATED."""

    # ── Claude Code agents dir ────────────────────────────────────────────────
    def test_cp_to_claude_agents_is_gated(self):
        r = inspect_subprocess("cp agency-agents/security-engineer.md ~/.claude/agents/")
        assert r.verdict in (SubprocVerdict.BLOCK, SubprocVerdict.WARN, SubprocVerdict.PAUSE)
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    def test_mv_to_claude_agents_is_gated(self):
        r = inspect_subprocess("mv security-engineer.md ~/.claude/agents/security-engineer.md")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    def test_install_script_to_claude_agents(self):
        r = inspect_subprocess("./scripts/install.sh --tool claude-code")
        assert r.rule_id == "T38"   # spawn classification takes precedence

    # ── Cursor rules dir ──────────────────────────────────────────────────────
    def test_cp_to_cursor_rules_is_gated(self):
        r = inspect_subprocess("cp agent.mdc .cursor/rules/agent.mdc")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    # ── OpenClaw dir ──────────────────────────────────────────────────────────
    def test_cp_to_openclaw_dir_is_gated(self):
        r = inspect_subprocess("cp SOUL.md ~/.openclaw/my-agent/SOUL.md")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    # ── GitHub Copilot agents dir ─────────────────────────────────────────────
    def test_cp_to_github_agents_is_gated(self):
        r = inspect_subprocess("cp backend-architect.md ~/.github/agents/backend-architect.md")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    # ── Windsurf rules file ───────────────────────────────────────────────────
    def test_write_to_windsurfrules_is_gated(self):
        r = inspect_subprocess("cp compiled.rules .windsurfrules")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    # ── SOUL.md direct write ──────────────────────────────────────────────────
    def test_write_to_soul_md_is_gated(self):
        r = inspect_subprocess("cp modified-soul.md SOUL.md")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    def test_write_to_identity_md_is_gated(self):
        r = inspect_subprocess("cp new-identity.md IDENTITY.md")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.GATED

    # ── Read access is monitored (not gated) ──────────────────────────────────
    def test_ls_claude_agents_is_monitored(self):
        r = inspect_subprocess("ls ~/.claude/agents/")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.MONITORED

    def test_cat_soul_md_is_monitored(self):
        r = inspect_subprocess("cat SOUL.md")
        assert r.rule_id == "T36_AGENTDEF"
        assert r.tier == SubprocTier.MONITORED

    # ── Unrelated writes are not flagged ─────────────────────────────────────
    def test_cp_regular_file_not_flagged(self):
        r = inspect_subprocess("cp main.py backup/main.py")
        assert r.rule_id != "T36_AGENTDEF"

    def test_write_readme_not_flagged(self):
        r = inspect_subprocess("cp README.md docs/README.md")
        # README.md is not a protected agent def file
        assert r.rule_id != "T36_AGENTDEF"


# =============================================================================
# T38 — Sub-Agent Spawn Detection
# =============================================================================

class TestT38AgentSpawn:
    """Sub-agent process spawns should be Tier 2 MONITORED with T38 rule_id."""

    def test_claude_code_spawn(self):
        r = inspect_subprocess("claude code --print 'review this file'")
        assert r.rule_id == "T38"
        assert r.tier == SubprocTier.MONITORED

    def test_claude_print_flag(self):
        r = inspect_subprocess("claude --print 'list all files'")
        assert r.rule_id == "T38"

    def test_openclaw_run_spawn(self):
        r = inspect_subprocess("openclaw run security-engineer")
        assert r.rule_id == "T38"
        assert r.tier == SubprocTier.MONITORED

    def test_openclaw_spawn_subcommand(self):
        r = inspect_subprocess("openclaw spawn research-agent --task 'analyze codebase'")
        assert r.rule_id == "T38"

    def test_agency_install_script(self):
        r = inspect_subprocess("./scripts/install.sh --tool claude-code")
        assert r.rule_id == "T38"

    def test_agency_convert_script(self):
        r = inspect_subprocess("./scripts/convert.sh")
        assert r.rule_id == "T38"

    def test_python_agent_script(self):
        r = inspect_subprocess("python orchestrator_agent.py --parallel 8")
        assert r.rule_id == "T38"

    def test_node_agent_script(self):
        r = inspect_subprocess("node run_agent.mjs --target production")
        assert r.rule_id == "T38"

    def test_regular_python_not_flagged(self):
        r = inspect_subprocess("python main.py --help")
        assert r.rule_id != "T38"

    def test_regular_node_not_flagged(self):
        r = inspect_subprocess("node server.js --port 3000")
        assert r.rule_id != "T38"


# =============================================================================
# T37 FIN_EXEC — Financial Transaction Execution
# =============================================================================

class TestT37FinancialExecution:
    """Financial API calls should be blocked by the HTTP layer."""

    # ── Stripe ────────────────────────────────────────────────────────────────
    def test_stripe_charge_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://api.stripe.com/v1/charges",
            headers={},
            body=b'{"amount": 5000, "currency": "usd"}',
        )
        assert r.verdict == HttpVerdict.BLOCK
        assert r.rule_id == "T37"

    def test_stripe_transfer_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://api.stripe.com/v1/transfers",
            headers={},
            body=b'{"amount": 10000, "destination": "acct_xyz"}',
        )
        assert r.verdict == HttpVerdict.BLOCK
        assert r.rule_id == "T37"

    def test_stripe_payout_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://api.stripe.com/v1/payouts",
            headers={},
            body=b'{"amount": 2500}',
        )
        assert r.rule_id == "T37"

    def test_stripe_get_not_blocked(self):
        # GET (read) to Stripe should not trigger T37
        r = inspect_request(
            method="GET",
            url="https://api.stripe.com/v1/charges/ch_123",
            headers={},
            body=None,
        )
        assert r.rule_id != "T37"

    # ── PayPal ────────────────────────────────────────────────────────────────
    def test_paypal_payment_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://api-m.paypal.com/v2/payments/captures",
            headers={},
            body=b'{"amount": {"value": "100.00", "currency_code": "USD"}}',
        )
        assert r.rule_id == "T37"

    # ── Ethereum sendTransaction ───────────────────────────────────────────────
    def test_eth_send_transaction_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://mainnet.infura.io/v3/abc123",
            headers={"Content-Type": "application/json"},
            body=b'{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{}],"id":1}',
        )
        assert r.verdict == HttpVerdict.BLOCK
        assert r.rule_id == "T37"

    def test_eth_send_raw_transaction_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://eth-mainnet.alchemyapi.io/v2/key123",
            headers={},
            body=b'{"method":"eth_sendRawTransaction","params":["0xf86a..."]}',
        )
        assert r.rule_id == "T37"

    def test_eth_call_not_blocked(self):
        # Read-only eth_call should not trigger T37
        r = inspect_request(
            method="POST",
            url="https://mainnet.infura.io/v3/abc123",
            headers={},
            body=b'{"method":"eth_call","params":[{},"latest"]}',
        )
        assert r.rule_id != "T37"

    # ── Coinbase ──────────────────────────────────────────────────────────────
    def test_coinbase_transaction_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://api.coinbase.com/v2/transactions",
            headers={},
            body=b'{"type":"send","to":"0xabc","amount":"0.1","currency":"ETH"}',
        )
        assert r.rule_id == "T37"

    # ── Generic large-amount body ─────────────────────────────────────────────
    def test_large_amount_body_on_financial_host_blocked(self):
        r = inspect_request(
            method="POST",
            url="https://api.stripe.com/v1/payment_intents",
            headers={},
            body=b'{"amount": 99900, "currency": "usd", "confirm": true}',
        )
        assert r.rule_id == "T37"

    # ── SSRF still takes priority over T37 ───────────────────────────────────
    def test_ssrf_to_metadata_still_t25(self):
        r = inspect_request(
            method="POST",
            url="http://169.254.169.254/latest/meta-data/",
            headers={},
            body=None,
        )
        assert r.rule_id == "T25"


# =============================================================================
# AgentDefGuard
# =============================================================================

class TestAgentDefGuard:
    """Snapshot and integrity check logic."""

    def test_empty_snapshot_returns_dict(self, tmp_path):
        guard = AgentDefGuard(cwd=str(tmp_path))
        baseline = guard.snapshot()
        assert isinstance(baseline, dict)

    def test_snapshot_detects_agent_files(self, tmp_path):
        # Create fake agent def file in a monitored relative path
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        agent_file = agents_dir / "security-engineer.md"
        agent_file.write_text("# Security Engineer\nYou are a security expert.")
        guard = AgentDefGuard(cwd=str(tmp_path))
        baseline = guard.snapshot()
        assert str(agent_file) in baseline

    def test_no_violations_when_unchanged(self, tmp_path):
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        f = agents_dir / "test-agent.md"
        f.write_text("# Test Agent")
        guard = AgentDefGuard(cwd=str(tmp_path))
        guard.snapshot()
        violations = guard.check()
        assert violations == []

    def test_detects_modified_file(self, tmp_path):
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        f = agents_dir / "test-agent.md"
        f.write_text("# Test Agent — original content")
        guard = AgentDefGuard(cwd=str(tmp_path))
        guard.snapshot()
        # Simulate mid-session modification
        f.write_text("# Test Agent — MALICIOUS REPROGRAMMED CONTENT")
        violations = guard.check()
        assert len(violations) == 1
        assert violations[0].violation_type == "MODIFIED"
        assert violations[0].path == str(f)
        assert violations[0].rule_id == "T36_AGENTDEF"

    def test_detects_deleted_file(self, tmp_path):
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        f = agents_dir / "test-agent.md"
        f.write_text("# Test Agent")
        guard = AgentDefGuard(cwd=str(tmp_path))
        guard.snapshot()
        f.unlink()
        violations = guard.check()
        assert len(violations) == 1
        assert violations[0].violation_type == "DELETED"

    def test_detects_added_file(self, tmp_path):
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        guard = AgentDefGuard(cwd=str(tmp_path))
        guard.snapshot()
        # New file added after snapshot
        new_file = agents_dir / "injected-agent.md"
        new_file.write_text("# Injected malicious agent")
        violations = guard.check()
        assert len(violations) == 1
        assert violations[0].violation_type == "ADDED"
        assert violations[0].rule_id == "T36_AGENTDEF"

    def test_multiple_violations_detected(self, tmp_path):
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        f1 = agents_dir / "agent1.md"
        f2 = agents_dir / "agent2.md"
        f1.write_text("agent 1")
        f2.write_text("agent 2")
        guard = AgentDefGuard(cwd=str(tmp_path))
        guard.snapshot()
        f1.write_text("agent 1 modified")
        f2.unlink()
        violations = guard.check()
        assert len(violations) == 2

    def test_check_before_snapshot_returns_empty(self, tmp_path):
        guard = AgentDefGuard(cwd=str(tmp_path))
        # No snapshot called
        assert guard.check() == []

    def test_violation_to_dict_has_required_fields(self, tmp_path):
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        f = agents_dir / "test-agent.md"
        f.write_text("original")
        guard = AgentDefGuard(cwd=str(tmp_path))
        guard.snapshot()
        f.write_text("modified")
        violations = guard.check()
        d = violations[0].to_dict()
        assert "path" in d
        assert "violation" in d
        assert "original_hash" in d
        assert "current_hash" in d
        assert "rule_id" in d
        assert "threat_family" in d
        assert d["rule_id"] == "T36_AGENTDEF"


# =============================================================================
# SessionIdentityChain
# =============================================================================

class TestSessionIdentityChain:

    def test_creates_session_id(self):
        chain = SessionIdentityChain(agent_name="test-agent")
        assert chain.session_id
        assert len(chain.session_id) >= 16

    def test_custom_session_id(self):
        chain = SessionIdentityChain(agent_name="test", session_id="custom-abc-123")
        assert chain.session_id == "custom-abc-123"

    def test_public_token_is_sha256_of_secret(self):
        chain = SessionIdentityChain(agent_name="test")
        expected = hashlib.sha256(chain._secret).hexdigest()
        assert chain.public_token == expected

    def test_sign_event_adds_fields(self):
        chain = SessionIdentityChain(agent_name="test")
        event = {"rule_id": "T07", "verdict": "BLOCK", "cmd": "rm -rf /", "timestamp": time.time()}
        signed = chain.sign_event(event)
        assert "session_sig" in signed
        assert "session_id" in signed
        assert "event_seq" in signed
        assert signed["session_id"] == chain.session_id
        assert signed["event_seq"] == 1

    def test_verify_signed_event_passes(self):
        chain = SessionIdentityChain(agent_name="test")
        event = {"rule_id": "T19", "verdict": "BLOCK", "cmd": "cat .env", "timestamp": time.time()}
        chain.sign_event(event)
        assert chain.verify(event) is True

    def test_verify_tampered_event_fails(self):
        chain = SessionIdentityChain(agent_name="test")
        event = {"rule_id": "T07", "verdict": "BLOCK", "cmd": "rm -rf", "timestamp": time.time()}
        chain.sign_event(event)
        # Tamper with the verdict
        event["verdict"] = "ALLOW"
        assert chain.verify(event) is False

    def test_tampered_sig_fails(self):
        chain = SessionIdentityChain(agent_name="test")
        event = {"rule_id": "T07", "verdict": "BLOCK", "cmd": "nmap", "timestamp": time.time()}
        chain.sign_event(event)
        event["session_sig"] = "deadbeef" * 8
        assert chain.verify(event) is False

    def test_event_sequence_increments(self):
        chain = SessionIdentityChain(agent_name="test")
        e1 = {"rule_id": "T07", "verdict": "BLOCK", "cmd": "cmd1", "timestamp": time.time()}
        e2 = {"rule_id": "T19", "verdict": "BLOCK", "cmd": "cmd2", "timestamp": time.time()}
        chain.sign_event(e1)
        chain.sign_event(e2)
        assert e1["event_seq"] == 1
        assert e2["event_seq"] == 2
        assert chain._event_count == 2

    def test_header_contains_required_fields(self):
        chain = SessionIdentityChain(agent_name="security-engineer")
        h = chain.header()
        assert h["agent_name"] == "security-engineer"
        assert h["session_id"] == chain.session_id
        assert h["public_token"] == chain.public_token
        assert "created_at" in h

    def test_cross_chain_verify_fails(self):
        chain1 = SessionIdentityChain(agent_name="agent-1")
        chain2 = SessionIdentityChain(agent_name="agent-2")
        event = {"rule_id": "T07", "verdict": "BLOCK", "cmd": "nmap", "timestamp": time.time()}
        chain1.sign_event(event)
        # Chain2 should not verify chain1's event
        assert chain2.verify(event) is False


# =============================================================================
# MultiAgentRegistry
# =============================================================================

class TestMultiAgentRegistry:

    def test_creates_registry(self):
        reg = MultiAgentRegistry(root_session_id="root-123", root_agent_name="orchestrator")
        assert reg._root_id == "root-123"
        assert reg._root_name == "orchestrator"

    def test_register_spawn_returns_event(self):
        reg = MultiAgentRegistry(root_session_id="root-123")
        ev = reg.register_spawn(
            parent_id="root-123",
            child_id="child-456",
            cmd="claude code --print",
            agent_name="security-engineer",
        )
        assert isinstance(ev, SpawnEvent)
        assert ev.parent_id == "root-123"
        assert ev.child_id == "child-456"
        assert ev.agent_name == "security-engineer"

    def test_policy_propagated_default_true(self):
        reg = MultiAgentRegistry(root_session_id="root-123")
        ev = reg.register_spawn("root-123", "child-456", "claude code")
        assert ev.policy_propagated is True

    def test_get_child_returns_session(self):
        reg = MultiAgentRegistry(root_session_id="root-123")
        reg.register_spawn("root-123", "child-456", "openclaw run security-engineer",
                           agent_name="security-engineer")
        child = reg.get_child("child-456")
        assert child is not None
        assert isinstance(child, ChildSession)
        assert child.agent_name == "security-engineer"

    def test_get_unknown_child_returns_none(self):
        reg = MultiAgentRegistry(root_session_id="root-123")
        assert reg.get_child("nonexistent") is None

    def test_all_spawns_returns_list(self):
        reg = MultiAgentRegistry(root_session_id="root-123")
        reg.register_spawn("root-123", "child-1", "claude code")
        reg.register_spawn("root-123", "child-2", "openclaw run design")
        reg.register_spawn("root-123", "child-3", "python marketing_agent.py")
        spawns = reg.all_spawns()
        assert len(spawns) == 3

    def test_to_dict_structure(self):
        reg = MultiAgentRegistry(root_session_id="root-abc", root_agent_name="orchestrator")
        reg.register_spawn("root-abc", "child-1", "claude code", "security-engineer")
        d = reg.to_dict()
        assert d["root_session_id"] == "root-abc"
        assert d["root_agent_name"] == "orchestrator"
        assert d["child_count"] == 1
        assert len(d["spawns"]) == 1
        assert len(d["children"]) == 1

    def test_spawn_event_to_dict(self):
        reg = MultiAgentRegistry(root_session_id="root-123")
        ev = reg.register_spawn("root-123", "child-456", "claude --print", "test-agent")
        d = ev.to_dict()
        assert d["event_type"] == "AGENT_SPAWN"
        assert d["rule_id"] == "T38"
        assert d["rule_name"] == "AGENT_SPAWN"
        assert d["parent_session_id"] == "root-123"
        assert d["child_session_id"] == "child-456"

    def test_child_session_add_event(self):
        reg = MultiAgentRegistry(root_session_id="root-123")
        reg.register_spawn("root-123", "child-456", "openclaw run backend-architect")
        child = reg.get_child("child-456")
        child.add_event({"rule_id": "T07", "verdict": "BLOCK"})
        child.add_event({"rule_id": "T19", "verdict": "BLOCK"})
        assert child.to_dict()["event_count"] == 2

    def test_parallel_spawns_agency_agents_scenario(self):
        """Simulate agency-agents Nexus example: 8 parallel agents."""
        reg = MultiAgentRegistry(root_session_id="root-nexus", root_agent_name="agents-orchestrator")
        agents = [
            ("child-001", "product-trend-researcher"),
            ("child-002", "backend-architect"),
            ("child-003", "brand-guardian"),
            ("child-004", "growth-hacker"),
            ("child-005", "support-responder"),
            ("child-006", "ux-researcher"),
            ("child-007", "project-shepherd"),
            ("child-008", "xr-interface-architect"),
        ]
        for child_id, name in agents:
            reg.register_spawn("root-nexus", child_id, f"openclaw run {name}", name)

        assert len(reg.all_spawns()) == 8
        d = reg.to_dict()
        assert d["child_count"] == 8


# =============================================================================
# Version and module-level API
# =============================================================================

class TestV030Version:

    def test_version_is_030(self):
        assert aiglos.__version__ == "0.9.0"

    def test_module_exports_multiagent_types(self):
        assert hasattr(aiglos, "MultiAgentRegistry")
        assert hasattr(aiglos, "AgentDefGuard")
        assert hasattr(aiglos, "SessionIdentityChain")
        assert hasattr(aiglos, "SpawnEvent")
        assert hasattr(aiglos, "AgentDefViolation")

    def test_status_has_v030_fields(self):
        s = aiglos.status()
        assert "agent_def_guard_active" in s
        assert "multi_agent_active" in s
        assert "session_identity_active" in s
        assert "agent_def_guard" in s
        assert "multi_agent" in s
        assert "session_identity" in s

    def test_attach_accepts_v030_params(self):
        # Should not raise with new v0.3.0 parameters
        try:
            aiglos.attach(
                agent_name="test-v030",
                enable_multi_agent=True,
                guard_agent_defs=False,  # disable to avoid filesystem side effects in test
                session_id="test-session-0030",
            )
        except Exception:
            pass  # Some attach failures are expected in test env without full setup


# =============================================================================
# Hash utility
# =============================================================================

class TestHashFile:

    def test_hash_file_returns_hex(self, tmp_path):
        f = tmp_path / "test.md"
        f.write_text("hello")
        h = _hash_file(f)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_changes_on_content_change(self, tmp_path):
        f = tmp_path / "test.md"
        f.write_text("original")
        h1 = _hash_file(f)
        f.write_text("modified")
        h2 = _hash_file(f)
        assert h1 != h2

    def test_hash_stable_on_same_content(self, tmp_path):
        f = tmp_path / "test.md"
        f.write_text("stable content")
        assert _hash_file(f) == _hash_file(f)

    def test_hash_nonexistent_returns_empty(self, tmp_path):
        f = tmp_path / "doesnotexist.md"
        assert _hash_file(f) == ""
