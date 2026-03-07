"""
aiglos.licensing
Tier management, trial state machine, and feature gate authorization.

Tier hierarchy:
  FREE     — local-only scanning, no attestation artifacts, no cloud telemetry
  TRIAL    — full Pro access, 30-day clock starts on first gated feature hit
  PRO      — $20/month, unlimited attestation artifacts, cloud telemetry
  TEAM     — $200/month, multi-agent, SIEM, compliance PDF
  ENTERPRISE — $12K+/month, air-gap, CMMC, §1513, DoD

Gated features:
  ATTESTATION      — RSA-2048 signed artifact generation
  CLOUD_TELEMETRY  — sending events to api.aiglos.io
  COMPLIANCE_PDF   — monthly compliance report generation
  SIEM_WEBHOOK     — webhook/SIEM integration
  MULTI_AGENT      — multi-agent centralized management

State persistence:
  ~/.aiglos/license.json — trial start date, tier, key fingerprint
  AIGLOS_KEY env var     — overrides local state, determines tier

Design constraints:
  - Never blocks the agent call path (all gate checks are sub-millisecond)
  - Never raises exceptions from gate checks (returns GateResult instead)
  - Graceful degradation if state file is corrupt or unwritable
  - Trial auto-starts on first gated feature hit — no opt-in required
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

log = logging.getLogger("aiglos.licensing")

# ── Constants ──────────────────────────────────────────────────────────────────

TRIAL_DURATION_DAYS   = 30
STATE_FILE_PATH       = Path.home() / ".aiglos" / "license.json"
STATE_FILE_VERSION    = 2
AIGLOS_SIGNUP_URL     = "https://aiglos.io/pricing"
AIGLOS_TRIAL_URL      = "https://aiglos.io/trial"


# ── Enums ──────────────────────────────────────────────────────────────────────

class Tier(str, Enum):
    FREE       = "free"
    TRIAL      = "trial"
    PRO        = "pro"
    TEAM       = "team"
    ENTERPRISE = "enterprise"


class Feature(str, Enum):
    ATTESTATION     = "attestation"
    CLOUD_TELEMETRY = "cloud_telemetry"
    COMPLIANCE_PDF  = "compliance_pdf"
    SIEM_WEBHOOK    = "siem_webhook"
    MULTI_AGENT     = "multi_agent"


class GateStatus(str, Enum):
    ALLOWED        = "allowed"       # feature accessible on current tier
    TRIAL_ACTIVE   = "trial_active"  # trial running — feature accessible
    TRIAL_EXPIRED  = "trial_expired" # trial ended — feature locked, show prompt
    UPGRADE_PROMPT = "upgrade_prompt"# free tier hit gate — trial auto-started


# ── Feature access matrix ──────────────────────────────────────────────────────

_TIER_FEATURES: dict[Tier, set[Feature]] = {
    Tier.FREE:       set(),                                     # nothing gated
    Tier.TRIAL:      {Feature.ATTESTATION, Feature.CLOUD_TELEMETRY,
                      Feature.COMPLIANCE_PDF},
    Tier.PRO:        {Feature.ATTESTATION, Feature.CLOUD_TELEMETRY,
                      Feature.COMPLIANCE_PDF},
    Tier.TEAM:       {Feature.ATTESTATION, Feature.CLOUD_TELEMETRY,
                      Feature.COMPLIANCE_PDF, Feature.SIEM_WEBHOOK,
                      Feature.MULTI_AGENT},
    Tier.ENTERPRISE: {Feature.ATTESTATION, Feature.CLOUD_TELEMETRY,
                      Feature.COMPLIANCE_PDF, Feature.SIEM_WEBHOOK,
                      Feature.MULTI_AGENT},
}


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class GateResult:
    status: GateStatus
    feature: Feature
    tier: Tier
    trial_days_remaining: Optional[int] = None
    trial_start_iso: Optional[str] = None
    message: str = ""
    upgrade_url: str = AIGLOS_SIGNUP_URL

    @property
    def allowed(self) -> bool:
        return self.status in (GateStatus.ALLOWED, GateStatus.TRIAL_ACTIVE)

    def __repr__(self) -> str:
        return (
            f"GateResult(status={self.status.value!r}, "
            f"feature={self.feature.value!r}, "
            f"tier={self.tier.value!r}, "
            f"allowed={self.allowed})"
        )


@dataclass
class LicenseState:
    """Persisted state written to ~/.aiglos/license.json"""
    version: int = STATE_FILE_VERSION
    tier: str = Tier.FREE.value
    trial_start_ts: Optional[float] = None   # Unix timestamp, None = not started
    key_fingerprint: Optional[str] = None    # SHA-256[:16] of API key
    first_gate_hit_ts: Optional[float] = None
    gate_hits: dict = field(default_factory=dict)  # feature -> hit count

    @property
    def trial_start_dt(self) -> Optional[datetime]:
        if self.trial_start_ts is None:
            return None
        return datetime.fromtimestamp(self.trial_start_ts, tz=timezone.utc)

    @property
    def trial_days_remaining(self) -> Optional[int]:
        if self.trial_start_ts is None:
            return None
        elapsed = time.time() - self.trial_start_ts
        remaining = TRIAL_DURATION_DAYS - int(elapsed / 86400)
        return max(0, remaining)

    @property
    def trial_expired(self) -> bool:
        if self.trial_start_ts is None:
            return False
        return (time.time() - self.trial_start_ts) >= (TRIAL_DURATION_DAYS * 86400)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> LicenseState:
        # Forward-compat: ignore unknown keys
        known = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


# ── License manager ────────────────────────────────────────────────────────────

class LicenseManager:
    """
    Thread-safe license tier and trial state manager.

    Single source of truth for:
      - What tier the current installation is on
      - Whether the 30-day trial is active, pending, or expired
      - Whether a given feature is accessible

    Usage:
        lm = LicenseManager.from_env()
        result = lm.check_gate(Feature.ATTESTATION)
        if result.allowed:
            generate_artifact(...)
        else:
            show_upgrade_prompt(result)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        state_path: Path = STATE_FILE_PATH,
    ):
        self._api_key = api_key
        self._state_path = state_path
        self._lock = threading.Lock()
        self._state: LicenseState = self._load_state()
        self._tier: Tier = self._resolve_tier()

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls, state_path: Path = STATE_FILE_PATH) -> LicenseManager:
        key = os.environ.get("AIGLOS_KEY", "").strip() or None
        return cls(api_key=key, state_path=state_path)

    # ── Public API ─────────────────────────────────────────────────────────────

    @property
    def tier(self) -> Tier:
        return self._tier

    @property
    def is_free(self) -> bool:
        return self._tier == Tier.FREE

    @property
    def trial_active(self) -> bool:
        return (
            self._tier == Tier.TRIAL
            and self._state.trial_start_ts is not None
            and not self._state.trial_expired
        )

    @property
    def trial_days_remaining(self) -> Optional[int]:
        return self._state.trial_days_remaining

    def check_gate(self, feature: Feature) -> GateResult:
        """
        Check whether a feature is accessible.

        Side effect on FREE tier: auto-starts the 30-day trial on first hit
        and mutates tier to TRIAL.  Writes state to disk.

        Never raises.  Always returns a GateResult.
        """
        with self._lock:
            return self._check_gate_locked(feature)

    def stats(self) -> dict:
        with self._lock:
            return {
                "tier": self._tier.value,
                "trial_active": self.trial_active,
                "trial_days_remaining": self._state.trial_days_remaining,
                "trial_start": self._state.trial_start_dt.isoformat()
                               if self._state.trial_start_dt else None,
                "gate_hits": dict(self._state.gate_hits),
                "api_key_present": bool(self._api_key),
            }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _resolve_tier(self) -> Tier:
        """Determine tier from API key + persisted state."""
        if self._api_key:
            fp = _key_fingerprint(self._api_key)
            tier_from_key = _tier_from_key_prefix(self._api_key)
            # Update state if fingerprint changed (new key)
            if self._state.key_fingerprint != fp:
                self._state.key_fingerprint = fp
                self._state.tier = tier_from_key.value
                self._save_state()
            return tier_from_key

        # No API key — use persisted tier
        try:
            return Tier(self._state.tier)
        except ValueError:
            return Tier.FREE

    def _check_gate_locked(self, feature: Feature) -> GateResult:
        """Must be called under self._lock."""
        tier = self._tier

        # Record hit and persist (best-effort, always — so reloads see fresh counts)
        key = feature.value
        self._state.gate_hits[key] = self._state.gate_hits.get(key, 0) + 1
        self._save_state_quiet()

        # ── Expiry check FIRST — before any feature-access logic ──────────────
        # A TRIAL tier with an expired clock locks ALL features regardless of
        # what _TIER_FEATURES says.
        if tier == Tier.TRIAL and self._state.trial_expired:
            return GateResult(
                status=GateStatus.TRIAL_EXPIRED,
                feature=feature,
                tier=tier,
                trial_days_remaining=0,
                message=(
                    f"[Aiglos] Your 30-day Pro trial has ended. "
                    f"{feature.value} is now locked. "
                    f"Upgrade to Pro at {AIGLOS_SIGNUP_URL}"
                ),
                upgrade_url=AIGLOS_SIGNUP_URL,
            )

        # ── FREE tier hitting a gated feature: auto-start trial ───────────────
        if tier == Tier.FREE:
            allowed_on_free = _TIER_FEATURES.get(Tier.FREE, set())
            if feature not in allowed_on_free:
                return self._start_trial_locked(feature)
            # Feature is accessible on free (hypothetically — currently free has none)
            return GateResult(
                status=GateStatus.ALLOWED,
                feature=feature,
                tier=tier,
                message=f"[Aiglos] {feature.value} allowed on free tier.",
            )

        # ── Paid / active-trial tier: check feature access matrix ─────────────
        allowed_features = _TIER_FEATURES.get(tier, set())
        if feature in allowed_features:
            if tier == Tier.TRIAL:
                days_left = self._state.trial_days_remaining
                return GateResult(
                    status=GateStatus.TRIAL_ACTIVE,
                    feature=feature,
                    tier=tier,
                    trial_days_remaining=days_left,
                    trial_start_iso=self._state.trial_start_dt.isoformat()
                                    if self._state.trial_start_dt else None,
                    message=(
                        f"[Aiglos Trial] {feature.value} active — "
                        f"{days_left} day{'s' if days_left != 1 else ''} remaining. "
                        f"Upgrade at {AIGLOS_SIGNUP_URL}"
                    ),
                    upgrade_url=AIGLOS_SIGNUP_URL,
                )
            return GateResult(
                status=GateStatus.ALLOWED,
                feature=feature,
                tier=tier,
                message=f"[Aiglos] {feature.value} allowed on {tier.value} tier.",
            )

        # Feature not on this tier (e.g. SIEM on Pro)
        return GateResult(
            status=GateStatus.UPGRADE_PROMPT,
            feature=feature,
            tier=tier,
            message=(
                f"[Aiglos] {feature.value} requires a higher tier. "
                f"Current tier: {tier.value}. "
                f"Upgrade at {AIGLOS_SIGNUP_URL}"
            ),
            upgrade_url=AIGLOS_SIGNUP_URL,
        )

    def _start_trial_locked(self, trigger_feature: Feature) -> GateResult:
        """
        Auto-start the 30-day Pro trial.
        Called when a FREE tier developer first hits a gated feature.
        Mutates self._tier to TRIAL and persists state.
        """
        now = time.time()
        self._state.trial_start_ts = now
        self._state.tier = Tier.TRIAL.value
        if self._state.first_gate_hit_ts is None:
            self._state.first_gate_hit_ts = now
        self._tier = Tier.TRIAL
        self._save_state_quiet()

        start_dt = datetime.fromtimestamp(now, tz=timezone.utc)
        expire_dt = start_dt + timedelta(days=TRIAL_DURATION_DAYS)

        log.info(
            "[Aiglos] 30-day Pro trial started. "
            "Expires %s. Set AIGLOS_KEY to keep access.",
            expire_dt.strftime("%Y-%m-%d"),
        )

        return GateResult(
            status=GateStatus.UPGRADE_PROMPT,
            feature=trigger_feature,
            tier=Tier.TRIAL,
            trial_days_remaining=TRIAL_DURATION_DAYS,
            trial_start_iso=start_dt.isoformat(),
            message=(
                f"[Aiglos] Your 30-day Pro trial has started automatically.\n"
                f"  Feature:  {trigger_feature.value}\n"
                f"  Expires:  {expire_dt.strftime('%Y-%m-%d')}\n"
                f"  Upgrade:  {AIGLOS_SIGNUP_URL}\n"
                f"  To keep access after trial, set AIGLOS_KEY in your environment."
            ),
            upgrade_url=AIGLOS_TRIAL_URL,
        )

    # ── State persistence ──────────────────────────────────────────────────────

    def _load_state(self) -> LicenseState:
        try:
            if self._state_path.exists():
                raw = json.loads(self._state_path.read_text())
                state = LicenseState.from_dict(raw)
                # Migrate v1 state files
                if state.version < STATE_FILE_VERSION:
                    state.version = STATE_FILE_VERSION
                    self._write_state(state)
                return state
        except Exception as exc:
            log.debug("[Aiglos] Could not load license state: %s", exc)
        return LicenseState()

    def _save_state(self) -> None:
        """Save state, raising on failure (call under lock)."""
        self._write_state(self._state)

    def _save_state_quiet(self) -> None:
        """Save state, swallowing errors (best-effort)."""
        try:
            self._write_state(self._state)
        except Exception as exc:
            log.debug("[Aiglos] Could not persist license state: %s", exc)

    def _write_state(self, state: LicenseState) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state.to_dict(), indent=2))
        tmp.replace(self._state_path)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _key_fingerprint(key: str) -> str:
    """First 16 hex chars of SHA-256 of the key — for state tracking without storing the key."""
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _tier_from_key_prefix(key: str) -> Tier:
    """
    Determine tier from API key prefix convention:
      ak_live_pro_*        -> PRO
      ak_live_team_*       -> TEAM
      ak_live_ent_*        -> ENTERPRISE
      ak_live_* (default)  -> PRO
      ak_trial_*           -> TRIAL
      anything else        -> PRO (assume paid)
    """
    if key.startswith("ak_trial_"):
        return Tier.TRIAL
    if key.startswith("ak_live_team_"):
        return Tier.TEAM
    if key.startswith("ak_live_ent_"):
        return Tier.ENTERPRISE
    if key.startswith("ak_live_"):
        return Tier.PRO
    # Unknown format — treat as paid Pro (benefit of the doubt)
    return Tier.PRO
