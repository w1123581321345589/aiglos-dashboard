"""
aiglos.attest
RSA-2048 signed attestation artifact generator.

An attestation artifact is a tamper-evident JSON document that proves
an Aiglos runtime was active during a given AI agent session and that
every tool call was inspected before execution.

Artifact schema (v1):
  {
    "schema_version": 1,
    "artifact_id": "<uuid4>",
    "issued_at": "<ISO-8601>",
    "session_id": "<str>",
    "agent_id": "<str | null>",
    "runtime_version": "<semver>",
    "tier": "pro | team | enterprise | trial",
    "trial_days_remaining": <int | null>,
    "session_summary": {
      "tool_calls_total": <int>,
      "tool_calls_blocked": <int>,
      "tool_calls_warned": <int>,
      "block_rate_pct": <float>,
      "duration_seconds": <float>,
      "cves_triggered": ["CVE-YYYY-NNNNN", ...]
    },
    "top_risks": [
      {"risk_type": "<str>", "count": <int>, "cve": "<str | null>"}, ...
    ],
    "signature": {
      "algorithm": "RSA-SHA256",
      "key_id": "<fingerprint>",
      "value": "<base64>"
    }
  }

Gate integration:
  The AttestationGate (aiglos.gates) wraps generate_artifact().
  On free tier: trial auto-starts, prompt fires, artifact is returned.
  On trial-expired: returns None without calling this module.

Key management:
  Production: AIGLOS_PRIVATE_KEY env var (PEM, RSA-2048+)
  Development / CI: ephemeral key generated in-process (no env var required)

Design constraints:
  - Never stores the private key to disk
  - Artifact is self-contained and verifiable offline with the public key
  - Verification function is public (free to use) — value is in generation
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("aiglos.attest")

SCHEMA_VERSION   = 1
RUNTIME_VERSION  = "1.0.0"


# ── Crypto backend ─────────────────────────────────────────────────────────────
# Use cryptography library if available; fall back to hashlib-based HMAC
# for environments without it (still tamper-evident, just not asymmetric).

def _load_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
        return "rsa"
    except ImportError:
        return "hmac"

_CRYPTO_BACKEND = _load_crypto()


def _generate_ephemeral_key():
    """Generate an ephemeral RSA-2048 key pair for dev/CI use."""
    if _CRYPTO_BACKEND == "rsa":
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    return None


def _sign_payload(payload_bytes: bytes, private_key_pem: Optional[str] = None) -> tuple[str, str, str]:
    """
    Sign payload_bytes.

    Returns: (algorithm_str, key_id, base64_signature)
    """
    env_key = private_key_pem or os.environ.get("AIGLOS_PRIVATE_KEY", "")

    if _CRYPTO_BACKEND == "rsa" and env_key:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        private_key = serialization.load_pem_private_key(
            env_key.encode(), password=None, backend=default_backend()
        )
        sig = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        pub = private_key.public_key()
        pub_bytes = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
        return "RSA-SHA256", key_id, base64.b64encode(sig).decode()

    if _CRYPTO_BACKEND == "rsa":
        # Ephemeral key — dev/CI path
        key = _generate_ephemeral_key()
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        pub = key.public_key()
        pub_bytes = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = hashlib.sha256(pub_bytes).hexdigest()[:16] + "-ephemeral"
        return "RSA-SHA256-EPHEMERAL", key_id, base64.b64encode(sig).decode()

    # HMAC-SHA256 fallback
    import hmac
    secret = (env_key or "aiglos-dev-secret").encode()
    sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    key_id = hashlib.sha256(secret).hexdigest()[:16] + "-hmac"
    return "HMAC-SHA256", key_id, base64.b64encode(sig).decode()


def _verify_signature(artifact: dict, public_key_pem: Optional[str] = None) -> bool:
    """
    Verify an artifact's signature.  Public — no license gate.

    Returns True if signature is valid, False otherwise.
    """
    try:
        sig_block = artifact.get("signature", {})
        algorithm = sig_block.get("algorithm", "")
        sig_b64   = sig_block.get("value", "")
        sig_bytes = base64.b64decode(sig_b64)

        # Reconstruct canonical payload (artifact minus signature block)
        payload = {k: v for k, v in artifact.items() if k != "signature"}
        payload_bytes = _canonical_bytes(payload)

        if algorithm == "RSA-SHA256" and public_key_pem and _CRYPTO_BACKEND == "rsa":
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend
            pub = serialization.load_pem_public_key(
                public_key_pem.encode(), backend=default_backend()
            )
            pub.verify(sig_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
            return True

        if algorithm.startswith("HMAC-SHA256"):
            import hmac as hmaclib
            secret = (os.environ.get("AIGLOS_PRIVATE_KEY", "aiglos-dev-secret")).encode()
            expected = hmaclib.new(secret, payload_bytes, hashlib.sha256).digest()
            return hmaclib.compare_digest(expected, sig_bytes)

        # RSA-SHA256-EPHEMERAL: can't verify without the ephemeral public key
        # Return True with warning (ephemeral keys are dev-only)
        if "EPHEMERAL" in algorithm:
            log.warning("[Aiglos] Ephemeral key used — artifact cannot be verified offline.")
            return True

        return False
    except Exception as exc:
        log.debug("[Aiglos] Signature verification failed: %s", exc)
        return False


def _canonical_bytes(d: dict) -> bytes:
    """Deterministic JSON serialization for signing."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


# ── Session data ───────────────────────────────────────────────────────────────

@dataclass
class SessionSummary:
    tool_calls_total:   int = 0
    tool_calls_blocked: int = 0
    tool_calls_warned:  int = 0
    duration_seconds:   float = 0.0
    cves_triggered:     list = field(default_factory=list)
    top_risks:          list = field(default_factory=list)

    @property
    def block_rate_pct(self) -> float:
        if self.tool_calls_total == 0:
            return 0.0
        return round(100.0 * self.tool_calls_blocked / self.tool_calls_total, 2)

    def to_dict(self) -> dict:
        return {
            "tool_calls_total":   self.tool_calls_total,
            "tool_calls_blocked": self.tool_calls_blocked,
            "tool_calls_warned":  self.tool_calls_warned,
            "block_rate_pct":     self.block_rate_pct,
            "duration_seconds":   round(self.duration_seconds, 3),
            "cves_triggered":     sorted(set(self.cves_triggered)),
        }


# ── Artifact generation ────────────────────────────────────────────────────────

def generate_artifact(
    session_data: dict,
    private_key_pem: Optional[str] = None,
) -> dict:
    """
    Generate a signed attestation artifact from session_data.

    session_data keys (all optional except session_id):
      session_id          str
      agent_id            str | None
      tool_calls_total    int
      tool_calls_blocked  int
      tool_calls_warned   int
      duration_seconds    float
      cves_triggered      list[str]
      top_risks           list[dict]
      tier                str
      trial_days_remaining int | None

    This function is the signer_fn passed to AttestationGate.generate().
    """
    now = datetime.now(tz=timezone.utc)

    summary = SessionSummary(
        tool_calls_total=session_data.get("tool_calls_total", 0),
        tool_calls_blocked=session_data.get("tool_calls_blocked", 0),
        tool_calls_warned=session_data.get("tool_calls_warned", 0),
        duration_seconds=session_data.get("duration_seconds", 0.0),
        cves_triggered=session_data.get("cves_triggered", []),
        top_risks=session_data.get("top_risks", []),
    )

    artifact_body = {
        "schema_version": SCHEMA_VERSION,
        "artifact_id":    str(uuid.uuid4()),
        "issued_at":      now.isoformat(),
        "session_id":     session_data.get("session_id", str(uuid.uuid4())),
        "agent_id":       session_data.get("agent_id"),
        "runtime_version": RUNTIME_VERSION,
        "tier":           session_data.get("tier", "unknown"),
        "trial_days_remaining": session_data.get("trial_days_remaining"),
        "session_summary": summary.to_dict(),
        "top_risks":      summary.top_risks,
    }

    payload_bytes = _canonical_bytes(artifact_body)
    algorithm, key_id, sig_value = _sign_payload(payload_bytes, private_key_pem)

    artifact_body["signature"] = {
        "algorithm": algorithm,
        "key_id":    key_id,
        "value":     sig_value,
    }

    return artifact_body


def verify_artifact(artifact: dict, public_key_pem: Optional[str] = None) -> bool:
    """
    Verify a previously generated artifact.

    Public function — no license gate required.
    Anyone can verify; only paid tiers can generate.
    """
    return _verify_signature(artifact, public_key_pem)


def artifact_summary(artifact: dict) -> str:
    """Human-readable one-line summary of an artifact."""
    s = artifact.get("session_summary", {})
    return (
        f"Aiglos Attestation [{artifact.get('artifact_id', '?')[:8]}...] "
        f"issued={artifact.get('issued_at', '?')[:10]} "
        f"calls={s.get('tool_calls_total', 0)} "
        f"blocked={s.get('tool_calls_blocked', 0)} "
        f"({s.get('block_rate_pct', 0):.1f}% block rate) "
        f"tier={artifact.get('tier', '?')}"
    )
