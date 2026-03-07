"""
aiglos.gates
Feature gate enforcement with upgrade prompts.

Three gate classes, one per gated surface:
  AttestationGate   — wraps RSA artifact generation
  TelemetryGate     — wraps cloud dashboard / event upload
  ComplianceGate    — wraps compliance PDF generation

All gates share the same design contract:
  1. Check the LicenseManager.  If allowed: proceed.
  2. If free tier hits a gate: auto-start trial, emit upgrade prompt, proceed
     (non-blocking — the feature works during trial).
  3. If trial expired or tier insufficient: emit prompt, return None / raise
     UpgradeRequired (depending on context).
  4. The upgrade prompt goes to stderr via the aiglos logger.
     It is persistent (appears on every gated call) but never crashes
     the agent runtime.

Design constraints:
  - check_gate() is always sub-millisecond
  - No network calls in gate code paths
  - Never raises into the agent call path
  - Works in both sync and async contexts
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from typing import Any, Callable, Optional

from aiglos_licensing import (
    Feature,
    GateResult,
    GateStatus,
    LicenseManager,
    Tier,
    AIGLOS_SIGNUP_URL,
    TRIAL_DURATION_DAYS,
)

log = logging.getLogger("aiglos.gates")

# ── Upgrade prompt rendering ───────────────────────────────────────────────────

_PROMPT_LOCK = threading.Lock()
_LAST_PROMPT: dict[str, float] = {}  # feature -> last printed timestamp
_PROMPT_COOLDOWN_SECONDS = 60.0      # don't spam — one prompt per minute per feature


def _emit_upgrade_prompt(result: GateResult) -> None:
    """
    Print a persistent but non-blocking upgrade prompt to stderr.
    Rate-limited to once per minute per feature to avoid log spam.
    """
    with _PROMPT_LOCK:
        now = time.monotonic()
        key = result.feature.value
        last = _LAST_PROMPT.get(key, 0.0)
        if now - last < _PROMPT_COOLDOWN_SECONDS:
            return
        _LAST_PROMPT[key] = now

    lines = _format_prompt(result)
    print("\n".join(lines), file=sys.stderr)
    log.warning("[Aiglos Gate] %s", result.message)


def _format_prompt(result: GateResult) -> list[str]:
    """Format a boxed upgrade prompt for terminal output."""
    feature_label = result.feature.value.replace("_", " ").title()
    border = "─" * 58

    if result.status == GateStatus.UPGRADE_PROMPT and result.trial_days_remaining == TRIAL_DURATION_DAYS:
        # Trial just started
        lines = [
            "",
            f"┌{border}┐",
            f"│  Aiglos Pro Trial Started — 30 days free           │",
            f"│{' ' * 58}│",
            f"│  Feature:  {feature_label:<46}│",
            f"│  Access:   Full Pro features, 30 days              │",
            f"│  Expires:  30 days from today                      │",
            f"│{' ' * 58}│",
            f"│  Keep access: set AIGLOS_KEY in your environment   │",
            f"│  Upgrade now: {result.upgrade_url:<43}│",
            f"└{border}┘",
            "",
        ]
    elif result.status == GateStatus.TRIAL_ACTIVE:
        days = result.trial_days_remaining or 0
        urgency = "⚠ " if days <= 7 else "  "
        lines = [
            "",
            f"┌{border}┐",
            f"│  {urgency}Aiglos Pro Trial — {days} day{'s' if days != 1 else ''} remaining{' ' * max(0, 34 - len(str(days)))}│",
            f"│{' ' * 58}│",
            f"│  Feature:  {feature_label:<46}│",
            f"│  Upgrade:  {result.upgrade_url:<46}│",
            f"└{border}┘",
            "",
        ]
    elif result.status == GateStatus.TRIAL_EXPIRED:
        lines = [
            "",
            f"┌{border}┐",
            f"│  Aiglos Pro Trial Expired                          │",
            f"│{' ' * 58}│",
            f"│  Feature:  {feature_label:<46}│",
            f"│  Your 30-day trial has ended. This feature is now  │",
            f"│  locked on the free tier.                          │",
            f"│{' ' * 58}│",
            f"│  Upgrade:  {result.upgrade_url:<46}│",
            f"└{border}┘",
            "",
        ]
    else:
        lines = [
            "",
            f"┌{border}┐",
            f"│  Aiglos — Feature Requires Upgrade                 │",
            f"│{' ' * 58}│",
            f"│  Feature:  {feature_label:<46}│",
            f"│  Current:  {result.tier.value:<46}│",
            f"│  Upgrade:  {result.upgrade_url:<46}│",
            f"└{border}┘",
            "",
        ]
    return lines


# ── Base gate ──────────────────────────────────────────────────────────────────

class _BaseGate:
    """
    Shared gate mechanics.  Subclasses define which Feature they guard.
    """

    feature: Feature  # must be set by subclass

    def __init__(self, license_manager: Optional[LicenseManager] = None):
        self._lm = license_manager or LicenseManager.from_env()

    def _check(self) -> GateResult:
        result = self._lm.check_gate(self.feature)
        if not result.allowed or result.status == GateStatus.TRIAL_ACTIVE:
            # Emit prompt on every non-allowed hit; also on active trial
            # (persistent reminder that trial is ticking)
            _emit_upgrade_prompt(result)
        return result

    @property
    def tier(self) -> Tier:
        return self._lm.tier

    @property
    def trial_active(self) -> bool:
        return self._lm.trial_active

    @property
    def trial_days_remaining(self) -> Optional[int]:
        return self._lm.trial_days_remaining


# ── AttestationGate ────────────────────────────────────────────────────────────

class AttestationGate(_BaseGate):
    """
    Guards RSA-2048 attestation artifact generation.

    Free tier: zero artifacts.  First attempt auto-starts trial, prints prompt,
    then returns the artifact (non-blocking — developer gets the value).

    Trial expired: prompt fires, returns None.

    Usage:
        gate = AttestationGate()
        artifact = gate.generate(session_data, signer_fn)
        if artifact is None:
            # trial expired or tier insufficient — prompt already printed
            ...
    """

    feature = Feature.ATTESTATION

    def generate(
        self,
        session_data: dict,
        signer_fn: Callable[[dict], dict],
    ) -> Optional[dict]:
        """
        Attempt to generate an attestation artifact.

        Returns:
            dict  — signed artifact on ALLOWED or TRIAL_ACTIVE
            None  — on TRIAL_EXPIRED or insufficient tier (prompt already emitted)
        """
        result = self._check()

        if result.status == GateStatus.TRIAL_EXPIRED:
            return None

        # Feature not on this tier (e.g. called without a key and beyond trial)
        if result.status == GateStatus.UPGRADE_PROMPT and (result.trial_days_remaining or 0) == 0 and result.tier != Tier.TRIAL:
            # Pure "tier too low" case with no active trial
            if result.trial_days_remaining is None:
                return None

        if not result.allowed and result.status not in (GateStatus.UPGRADE_PROMPT,):
            return None

        # Allowed: generate artifact
        # (UPGRADE_PROMPT status on first free-tier hit means trial just started
        #  — feature IS accessible during trial)
        try:
            artifact = signer_fn(session_data)
            artifact["_aiglos_tier"] = self._lm.tier.value
            artifact["_aiglos_trial_days_remaining"] = result.trial_days_remaining
            return artifact
        except Exception as exc:
            log.error("[Aiglos] Attestation generation failed: %s", exc)
            return None

    def can_generate(self) -> bool:
        """Non-side-effectful check — does not start trial or emit prompt."""
        tier = self._lm.tier
        if tier == Tier.FREE:
            # Trial not started yet
            state = self._lm._state
            if state.trial_start_ts is None:
                return False  # will start on first actual generate() call
            if state.trial_expired:
                return False
            return True
        allowed_features = {
            Tier.TRIAL:      True,
            Tier.PRO:        True,
            Tier.TEAM:       True,
            Tier.ENTERPRISE: True,
        }
        return allowed_features.get(tier, False)


# ── TelemetryGate ──────────────────────────────────────────────────────────────

class TelemetryGate(_BaseGate):
    """
    Guards cloud telemetry: event upload to api.aiglos.io and the
    live threat dashboard feed.

    Free tier: local-only.  First cloud telemetry attempt auto-starts trial
    and prints prompt.  Events are buffered locally and flushed once trial
    activates.

    Usage:
        gate = TelemetryGate()
        if gate.allow_upload():
            upload_events(batch)
    """

    feature = Feature.CLOUD_TELEMETRY

    def allow_upload(self) -> bool:
        """
        Returns True if cloud upload is permitted.
        Side effect: starts trial on first free-tier hit, emits prompt.
        """
        result = self._check()
        if result.status == GateStatus.TRIAL_EXPIRED:
            return False
        if result.status == GateStatus.UPGRADE_PROMPT and result.trial_days_remaining == 0:
            return False
        # UPGRADE_PROMPT with days_remaining > 0 means trial just started — allow
        return result.allowed or (
            result.status == GateStatus.UPGRADE_PROMPT
            and (result.trial_days_remaining or 0) > 0
        )

    def allow_dashboard(self) -> bool:
        """Same gate as upload — dashboard and telemetry are one feature."""
        return self.allow_upload()


# ── ComplianceGate ─────────────────────────────────────────────────────────────

class ComplianceGate(_BaseGate):
    """
    Guards compliance PDF and SOC 2 report generation.

    Available on: TRIAL, PRO, TEAM, ENTERPRISE.
    Free tier: zero reports.  First attempt starts trial (same mechanic as attestation).

    Usage:
        gate = ComplianceGate()
        pdf_bytes = gate.generate_report(report_fn, params)
    """

    feature = Feature.COMPLIANCE_PDF

    def generate_report(
        self,
        report_fn: Callable[..., bytes],
        *args: Any,
        **kwargs: Any,
    ) -> Optional[bytes]:
        """
        Attempt to generate a compliance PDF.

        Returns bytes on success, None on trial expired / insufficient tier.
        """
        result = self._check()
        if result.status == GateStatus.TRIAL_EXPIRED:
            return None
        if result.status == GateStatus.UPGRADE_PROMPT and (result.trial_days_remaining or 0) == 0 and result.trial_days_remaining is not None:
            return None
        if not result.allowed and result.status not in (GateStatus.UPGRADE_PROMPT,):
            return None
        try:
            return report_fn(*args, **kwargs)
        except Exception as exc:
            log.error("[Aiglos] Compliance report generation failed: %s", exc)
            return None


# ── SiemGate ───────────────────────────────────────────────────────────────────

class SiemGate(_BaseGate):
    """
    Guards SIEM / webhook integration (Team tier and above).
    """

    feature = Feature.SIEM_WEBHOOK

    def allow_webhook(self) -> bool:
        result = self._check()
        return result.allowed


# ── Convenience: unified gate registry ────────────────────────────────────────

class GateRegistry:
    """
    Singleton-style registry holding one instance of each gate,
    sharing a single LicenseManager.

    Usage:
        from aiglos.gates import GateRegistry
        gates = GateRegistry()
        if gates.telemetry.allow_upload():
            ...
        artifact = gates.attestation.generate(session, sign)
    """

    def __init__(self, license_manager: Optional[LicenseManager] = None):
        lm = license_manager or LicenseManager.from_env()
        self.attestation  = AttestationGate(lm)
        self.telemetry    = TelemetryGate(lm)
        self.compliance   = ComplianceGate(lm)
        self.siem         = SiemGate(lm)
        self._lm          = lm

    @property
    def license(self) -> LicenseManager:
        return self._lm

    def stats(self) -> dict:
        return self._lm.stats()
