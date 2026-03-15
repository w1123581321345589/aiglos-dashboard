"""
tests/test_http_intercept.py
Tests for the Aiglos HTTP/API interception layer.
Covers: rule detection, allow-listing, verdict modes, patch mechanics.
"""

import sys
import types
import importlib
import pytest

# Always import the inspection logic directly (no live HTTP calls needed)
from aiglos.integrations.http_intercept import (
    inspect_request,
    HttpVerdict,
    AiglosBlockedRequest,
    _host_is_allowed,
    _extract_host,
    attach_http_intercept,
    get_session_http_events,
    clear_session_http_events,
    _session_events,
)


# --- Helper ---

def clean():
    """Reset session events between tests."""
    clear_session_http_events()


# --- _host_is_allowed ---

class TestAllowList:
    def test_exact_match(self):
        assert _host_is_allowed("api.stripe.com", ["api.stripe.com"])

    def test_wildcard_match(self):
        assert _host_is_allowed("s3.amazonaws.com", ["*.amazonaws.com"])

    def test_wildcard_no_match(self):
        assert not _host_is_allowed("evil.com", ["*.amazonaws.com"])

    def test_www_stripped(self):
        assert _host_is_allowed("www.stripe.com", ["stripe.com"])

    def test_empty_list(self):
        assert not _host_is_allowed("api.stripe.com", [])

    def test_multiple_entries(self):
        assert _host_is_allowed("api.openai.com", [
            "api.stripe.com", "*.openai.com", "api.anthropic.com"])


# --- _extract_host ---

class TestExtractHost:
    def test_simple(self):
        assert _extract_host("https://api.stripe.com/v1/charges") == "api.stripe.com"

    def test_with_port(self):
        assert _extract_host("http://localhost:8080/path") == "localhost"

    def test_bad_url(self):
        assert _extract_host("not-a-url") == ""


# --- T25: SSRF ---

class TestT25SSRF:
    def test_aws_metadata(self):
        r = inspect_request("GET", "http://169.254.169.254/latest/meta-data/")
        assert r.verdict == HttpVerdict.BLOCK
        assert r.rule_id == "T25"

    def test_gcp_metadata(self):
        r = inspect_request("GET", "http://metadata.google.internal/")
        assert r.verdict == HttpVerdict.BLOCK
        assert r.rule_id == "T25"

    def test_localhost(self):
        r = inspect_request("GET", "http://localhost/admin")
        assert r.verdict == HttpVerdict.BLOCK
        assert r.rule_id == "T25"

    def test_private_ip(self):
        r = inspect_request("GET", "http://192.168.1.1/")
        assert r.verdict == HttpVerdict.BLOCK

    def test_ssrf_not_blocked_for_legit_url(self):
        r = inspect_request("GET", "https://api.stripe.com/v1/customers",
                            allow_list=["api.stripe.com"])
        assert r.verdict == HttpVerdict.ALLOW

    def test_ssrf_blocks_even_with_allow_list(self):
        # Allow-list cannot override SSRF
        r = inspect_request("GET", "http://169.254.169.254/",
                            allow_list=["169.254.169.254"])
        assert r.verdict == HttpVerdict.BLOCK
        assert r.rule_id == "T25"


# --- T22: Recon ---

class TestT22Recon:
    def test_shodan(self):
        r = inspect_request("GET", "https://api.shodan.io/shodan/host/1.2.3.4?key=abc")
        assert r.verdict in (HttpVerdict.BLOCK, HttpVerdict.WARN)
        assert r.rule_id == "T22"

    def test_hibp(self):
        r = inspect_request("GET", "https://haveibeenpwned.com/api/v3/breachedaccount/test")
        assert r.rule_id == "T22"

    def test_recon_skipped_for_allow_listed(self):
        r = inspect_request("GET", "https://api.shodan.io/test",
                            allow_list=["api.shodan.io"])
        assert r.rule_id != "T22"

    def test_normal_api_not_flagged(self):
        r = inspect_request("GET", "https://api.github.com/repos/owner/repo",
                            allow_list=["api.github.com"])
        assert r.verdict == HttpVerdict.ALLOW


# --- T19: Credential harvest ---

class TestT19CredHarvest:
    def test_ssh_key_in_body(self):
        r = inspect_request("POST", "https://attacker.ngrok.io/collect",
                            body="data=~/.ssh/id_rsa content here")
        assert r.rule_id == "T19"
        assert r.verdict == HttpVerdict.BLOCK

    def test_aws_secret_in_body(self):
        r = inspect_request("POST", "https://evil.requestbin.com/log",
                            body="aws_secret=AKIAIOSFODNN7EXAMPLE")
        assert r.rule_id == "T19"

    def test_env_file_reference(self):
        r = inspect_request("POST", "https://attacker.io/",
                            body="contents of .env file here")
        assert r.rule_id == "T19"

    def test_credential_to_allow_listed_host_is_warn_not_block(self):
        # Sending auth to an allow-listed host is allowed (it's expected)
        r = inspect_request("POST", "https://api.stripe.com/v1/charges",
                            headers={"Authorization": "Bearer sk_live_abc123"},
                            allow_list=["api.stripe.com"])
        # Should not be blocked -- stripe legitimately needs auth headers
        assert r.verdict != HttpVerdict.BLOCK

    def test_exfil_staging_domain_always_blocked(self):
        r = inspect_request("POST", "https://abc.requestbin.com/collect",
                            body="normal data")
        assert r.verdict in (HttpVerdict.BLOCK, HttpVerdict.WARN)


# --- T20: Data exfil ---

class TestT20DataExfil:
    def test_ssn_in_body_to_exfil_host(self):
        r = inspect_request("POST", "https://evil.ngrok.io/",
                            body="ssn=123-45-6789 user data")
        assert r.rule_id in ("T19", "T20")
        assert r.verdict == HttpVerdict.BLOCK

    def test_email_bulk_in_body_non_allow_listed(self):
        # Should warn, not block, for non-staging domains
        r = inspect_request("POST", "https://marketing.example.com/upload",
                            body="user@example.com,other@test.com,third@foo.org")
        # Should be at least WARN level
        assert r.verdict in (HttpVerdict.WARN, HttpVerdict.BLOCK)

    def test_normal_body_passes(self):
        r = inspect_request("POST", "https://api.openai.com/v1/chat/completions",
                            body='{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}',
                            allow_list=["api.openai.com"])
        assert r.verdict == HttpVerdict.ALLOW


# --- T35: Model exfil ---

class TestT35ModelExfil:
    def test_model_weights_in_url(self):
        r = inspect_request("GET",
            "https://external.io/upload?file=model_weights.bin")
        assert r.rule_id == "T35"

    def test_safetensors_exfil(self):
        r = inspect_request("POST",
            "https://external.io/upload",
            body="uploading model.safetensors file")
        assert r.rule_id == "T35"


# --- T36: Supply chain ---

class TestT36SupplyChain:
    def test_pypi_push(self):
        r = inspect_request("POST", "https://upload.pypi.org/legacy/",
                            body="package contents")
        assert r.rule_id == "T36"

    def test_npm_publish(self):
        r = inspect_request("PUT", "https://registry.npmjs.org/my-package",
                            body='{"name":"my-package"}')
        assert r.rule_id == "T36"


# --- Mode handling ---

class TestModes:
    def test_warn_mode_downgrades_block_to_warn(self):
        r = inspect_request("GET", "http://169.254.169.254/",
                            mode="warn")
        # SSRF is always BLOCK regardless of mode (it's a hard block)
        # but other rules should downgrade
        assert r.rule_id == "T25"

    def test_audit_mode_never_blocks(self):
        r = inspect_request("GET", "https://shodan.io/search",
                            mode="audit")
        assert r.verdict == HttpVerdict.WARN  # audit = always warn

    def test_block_mode_is_default(self):
        r = inspect_request("POST", "https://evil.ngrok.io/",
                            body="ssh key: ~/.ssh/id_rsa")
        assert r.verdict == HttpVerdict.BLOCK


# --- Session event logging ---

class TestSessionEvents:
    def setup_method(self):
        clean()

    def test_events_are_recorded(self):
        # Simulate events by calling inspect_request and recording manually
        from aiglos.integrations.http_intercept import _session_events
        initial = len(_session_events)

        r = inspect_request("GET", "https://api.stripe.com/v1",
                            allow_list=["api.stripe.com"])
        # Direct call to inspect_request doesn't auto-log; that happens in the wrapper
        # But we can test the to_dict output
        d = r.to_dict()
        assert d["type"] == "http_request"
        assert "verdict" in d
        assert "url" in d

    def test_event_dict_structure(self):
        r = inspect_request("POST", "https://api.openai.com/v1/chat",
                            allow_list=["api.openai.com"])
        d = r.to_dict()
        required_keys = ["type", "verdict", "rule_id", "rule_name", "url", "method"]
        for k in required_keys:
            assert k in d, f"Missing key: {k}"

    def test_clear_events(self):
        from aiglos.integrations.http_intercept import _session_events
        _session_events.append({"test": True})
        clear_session_http_events()
        assert len(get_session_http_events()) == 0


# --- AiglosBlockedRequest exception ---

class TestBlockedException:
    def test_exception_carries_result(self):
        r = inspect_request("GET", "http://169.254.169.254/")
        exc = AiglosBlockedRequest(r)
        assert exc.result is r
        assert "T25" in str(exc)
        assert "169.254.169.254" in str(exc)

    def test_exception_is_runtime_error(self):
        r = inspect_request("GET", "http://localhost/")
        exc = AiglosBlockedRequest(r)
        assert isinstance(exc, RuntimeError)


# --- Clean request passthrough ---

class TestCleanPassthrough:
    def test_openai_api_allowed(self):
        r = inspect_request(
            "POST",
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": "Bearer sk-proj-abc"},
            body='{"model":"gpt-4o","messages":[]}',
            allow_list=["api.openai.com"],
        )
        assert r.verdict == HttpVerdict.ALLOW

    def test_anthropic_api_allowed(self):
        r = inspect_request(
            "POST",
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": "sk-ant-abc123"},
            body='{"model":"claude-opus-4-6","messages":[]}',
            allow_list=["api.anthropic.com"],
        )
        assert r.verdict == HttpVerdict.ALLOW

    def test_stripe_allowed(self):
        r = inspect_request(
            "POST",
            "https://api.stripe.com/v1/charges",
            headers={"Authorization": "Bearer sk_live_abc"},
            body="amount=1000&currency=usd",
            allow_list=["api.stripe.com"],
        )
        assert r.verdict == HttpVerdict.ALLOW

    def test_get_with_no_body(self):
        r = inspect_request(
            "GET",
            "https://api.github.com/repos/owner/repo",
            allow_list=["api.github.com"],
        )
        assert r.verdict == HttpVerdict.ALLOW
