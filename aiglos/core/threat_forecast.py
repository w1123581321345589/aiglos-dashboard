"""
aiglos.core.threat_forecast
=============================
Session-scoped threat forecasting and predictive threshold management.

The IntentPredictor tells you what the agent is likely to do next.
ThreatForecast translates that prediction into actionable security posture:
should we tighten blast radius thresholds *before* the predicted action fires?

If the model says there is a 73% probability of T37 FIN_EXEC in the next
5 steps, and the current policy has T37 at Tier 2 MONITORED, the right
response is to pre-tighten to Tier 3 GATED before those 5 steps run —
not to catch the T37 when it fires.

This is the distinction between a reactive security layer and a proactive
one. The forecast is the bridge between prediction and action.

Design:

  SessionForecaster
    Wraps IntentPredictor for a single session lifecycle.
    After each action: observe → predict → check thresholds → propose adjustments.
    Maintains a forecast history for the session artifact.

  ForecastAdjustment
    A proposed threshold change: "elevate T37 from Tier 2 to Tier 3
    for the remainder of this session, given 73% prediction probability."
    Adjustments are session-scoped — they do not persist beyond session close.
    They require no human approval (unlike adaptive amendments) because they
    are temporary and bounded to the current session.

Usage:
    from aiglos.core.threat_forecast import SessionForecaster

    forecaster = SessionForecaster(predictor, policy="enterprise")
    forecaster.start_session(session_id="sess-abc")

    # After each action
    adjustments = forecaster.after_action("T19", "BLOCK")
    for adj in adjustments:
        # adj.rule_id elevated to adj.proposed_tier for this session
        apply_tier_adjustment(adj)

    # At session close
    summary = forecaster.summary()
"""


import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aiglos.core.intent_predictor import IntentPredictor, PredictionResult


# Probability thresholds that trigger session-scoped tier elevation
_ELEVATION_THRESHOLDS = {
    "CRITICAL": 0.80,   # → Tier 3 GATED if currently below
    "HIGH":     0.60,   # → elevate one tier
    "MEDIUM":   0.45,   # → log elevated scrutiny
}

# Rules that get elevated when predicted at high probability
_ELEVATABLE_RULES = {
    "T37":          3,   # FIN_EXEC → always Tier 3 when predicted HIGH
    "T_DEST":       3,
    "T36_AGENTDEF": 3,
    "T19":          2,   # CRED_ACCESS → Tier 2 minimum
    "T11":          3,   # PERSISTENCE
    "T10":          3,   # PRIV_ESC
    "T07":          3,   # SHELL_INJECT
    "T27":          2,   # PROMPT_INJECT
    "T31":          2,   # MEMORY_POISON
}


# How many consecutive steps below half-threshold before elevation is released
_DECAY_STEPS_THRESHOLD = 3

@dataclass
class ForecastAdjustment:
    """
    A session-scoped threshold adjustment proposed by the forecaster.
    Does not persist beyond session close. No human approval required.

    Elevation decays automatically: if the predicted probability of the
    elevated rule drops below half its triggering threshold for
    _DECAY_STEPS_THRESHOLD consecutive steps, the elevation is released.
    """
    rule_id:              str
    proposed_tier:        int             # 2 or 3
    original_tier:        Optional[int]   # what it was before
    probability:          float           # probability that triggered this
    alert_level:          str
    evidence:             str
    session_id:           str
    applied_at_step:      int = 0
    steps_below_threshold: int = 0        # consecutive low-probability steps
    released:             bool = False    # True once decay released it
    applied:              bool = False
    timestamp:            float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "rule_id":                self.rule_id,
            "proposed_tier":          self.proposed_tier,
            "original_tier":          self.original_tier,
            "probability":            round(self.probability, 4),
            "alert_level":            self.alert_level,
            "evidence":               self.evidence,
            "session_id":             self.session_id,
            "applied_at_step":        self.applied_at_step,
            "steps_below_threshold":  self.steps_below_threshold,
            "released":               self.released,
            "applied":                self.applied,
            "timestamp":              self.timestamp,
        }


@dataclass
class ForecastSnapshot:
    """One forecast checkpoint during a session."""
    step:          int
    rule_observed: str
    prediction:    Optional[PredictionResult]
    adjustments:   List[ForecastAdjustment]
    timestamp:     float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "step":           self.step,
            "rule_observed":  self.rule_observed,
            "prediction":     self.prediction.to_dict() if self.prediction else None,
            "adjustments":    [a.to_dict() for a in self.adjustments],
        }


class SessionForecaster:
    """
    Per-session threat forecasting and proactive threshold management.

    Wraps IntentPredictor for a single session. After each observed action,
    updates the prediction and proposes any session-scoped threshold elevations.
    """

    def __init__(
        self,
        predictor:  IntentPredictor,
        session_id: str  = "unknown",
        policy:     str  = "enterprise",
    ):
        self.predictor  = predictor
        self.session_id = session_id
        self.policy     = policy
        self._step      = 0
        self._snapshots: List[ForecastSnapshot] = []
        self._active_adjustments: Dict[str, ForecastAdjustment] = {}
        self._total_adjustments = 0
        predictor.reset_session()

    def after_action(
        self,
        rule_id:  str,
        verdict:  str,
        details:  Optional[Dict[str, Any]] = None,
    ) -> List[ForecastAdjustment]:
        """
        Called after each action is observed. Updates prediction and
        returns any new threshold adjustment proposals.
        """
        self._step += 1
        self.predictor.observe(rule_id, verdict)
        prediction = self.predictor.predict()
        # Check decay before computing new adjustments
        self._decay_elevations(prediction)
        adjustments = self._compute_adjustments(prediction) if prediction else []

        snapshot = ForecastSnapshot(
            step=self._step,
            rule_observed=rule_id,
            prediction=prediction,
            adjustments=adjustments,
        )
        self._snapshots.append(snapshot)
        self._total_adjustments += len(adjustments)

        return adjustments

    def _compute_adjustments(
        self, prediction: PredictionResult
    ) -> List[ForecastAdjustment]:
        """Compute threshold elevation proposals from a prediction."""
        adjustments = []

        if prediction.alert_level in ("NONE", "LOW"):
            return adjustments

        for rule_id, probability in prediction.top_threats:
            if rule_id not in _ELEVATABLE_RULES:
                continue

            target_tier = _ELEVATABLE_RULES[rule_id]
            threshold = _ELEVATION_THRESHOLDS.get(prediction.alert_level, 1.0)

            if probability < threshold:
                continue

            # Don't re-propose if already active at this tier
            existing = self._active_adjustments.get(rule_id)
            if existing and existing.proposed_tier >= target_tier:
                continue

            adj = ForecastAdjustment(
                rule_id=rule_id,
                proposed_tier=target_tier,
                original_tier=None,
                probability=probability,
                alert_level=prediction.alert_level,
                applied_at_step=self._step,
                evidence=(
                    f"{prediction.alert_level} forecast: {rule_id} predicted "
                    f"at {probability:.0%} in next {prediction.horizon} steps. "
                    f"Session sequence: {' → '.join(prediction.current_sequence[-4:])}. "
                    f"Elevating to Tier {target_tier} for remainder of session."
                ),
                session_id=self.session_id,
            )
            self._active_adjustments[rule_id] = adj
            adjustments.append(adj)

        return adjustments

    def _decay_elevations(self, prediction: Optional[PredictionResult]) -> None:
        """
        Re-evaluate active elevations. Release any that have been below
        half their triggering threshold for _DECAY_STEPS_THRESHOLD steps.
        Logs releases for audit trail.
        """
        if not prediction or not self._active_adjustments:
            return

        prob_map = dict(prediction.top_threats)
        to_release = []

        for rule_id, adj in self._active_adjustments.items():
            current_prob = prob_map.get(rule_id, 0.0)
            half_threshold = _ELEVATION_THRESHOLDS.get(adj.alert_level, 1.0) / 2.0

            if current_prob < half_threshold:
                adj.steps_below_threshold += 1
                if adj.steps_below_threshold >= _DECAY_STEPS_THRESHOLD:
                    adj.released = True
                    to_release.append(rule_id)
            else:
                # Reset decay counter — probability recovered
                adj.steps_below_threshold = 0

        for rule_id in to_release:
            released = self._active_adjustments.pop(rule_id)
            import logging
            logging.getLogger("aiglos.threat_forecast").info(
                "[SessionForecaster] Elevation released — rule=%s "
                "applied_at_step=%d released_at_step=%d agent=%s",
                rule_id, released.applied_at_step, self._step, self.session_id,
            )

    def current_forecast(self) -> Optional[PredictionResult]:
        """Return the most recent prediction for this session."""
        if not self._snapshots:
            return None
        last = self._snapshots[-1]
        return last.prediction

    def active_adjustments(self) -> List[ForecastAdjustment]:
        """Return currently active session-scoped threshold adjustments."""
        return list(self._active_adjustments.values())

    def is_elevated(self, rule_id: str) -> bool:
        """Is a specific rule currently elevated for this session?"""
        return rule_id in self._active_adjustments

    def effective_tier(self, rule_id: str, base_tier: int) -> int:
        """
        Return the effective tier for a rule, accounting for forecast elevation.
        Call this in the outbound interceptor before classifying an action.
        """
        adj = self._active_adjustments.get(rule_id)
        if adj and adj.proposed_tier > base_tier:
            return adj.proposed_tier
        return base_tier

    def summary(self) -> dict:
        forecast = self.current_forecast()
        return {
            "session_id":         self.session_id,
            "steps_observed":     self._step,
            "total_adjustments":  self._total_adjustments,
            "active_elevations":  len(self._active_adjustments),
            "elevated_rules":     list(self._active_adjustments.keys()),
            "current_alert_level": forecast.alert_level if forecast else "NONE",
            "top_predicted_threat": (
                forecast.top_threats[0][0] if forecast and forecast.top_threats else None
            ),
            "model_sessions_trained": self.predictor.sessions_trained,
            "snapshots":          len(self._snapshots),
        }

    def to_artifact_section(self) -> dict:
        recent = [s.to_dict() for s in self._snapshots[-5:]]  # last 5 snapshots
        return {
            "forecast_summary":     self.summary(),
            "forecast_adjustments": [a.to_dict() for a in self._active_adjustments.values()],
            "forecast_snapshots":   recent,
        }
