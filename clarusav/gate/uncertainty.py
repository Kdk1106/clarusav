"""Dual-signal uncertainty gating: score band and model disagreement triggers."""

from dataclasses import dataclass
from typing import Any

from clarusav.gate.engine import BandPosition, Verdict


@dataclass
class DualSignalDecision:
    sample_id: str
    primary_score: float
    rf_score: float
    xgb_score: float
    disagreement: float
    band_position: str
    verdict: str
    trigger_fired: str  # "NONE", "SCORE_BAND", "MODEL_DISAGREEMENT", "DUAL_TRIGGER"
    escalation_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "primary_score": round(self.primary_score, 4),
            "rf_score": round(self.rf_score, 4),
            "xgb_score": round(self.xgb_score, 4),
            "disagreement": round(self.disagreement, 4),
            "band_position": self.band_position,
            "verdict": self.verdict,
            "trigger_fired": self.trigger_fired,
            "escalation_reason": self.escalation_reason,
        }


class DualSignalGate:
    """Escalates to disposable sandbox if either the score band is uncertain or models disagree."""

    def __init__(
        self,
        tau_high: float = 0.85,
        tau_low: float = 0.15,
        disagreement_threshold: float = 0.25,
    ) -> None:
        self.tau_high = float(tau_high)
        self.tau_low = float(tau_low)
        self.disagreement_threshold = float(disagreement_threshold)

    def evaluate(
        self,
        rf_score: float,
        xgb_score: float,
        primary_model_type: str = "xgboost",
        sample_id: str = "sample",
    ) -> DualSignalDecision:
        """Evaluate dual signals: score band and inter-model divergence."""
        primary_score = xgb_score if primary_model_type == "xgboost" else rf_score
        disagreement = abs(rf_score - xgb_score)

        score_band_uncertain = self.tau_low < primary_score < self.tau_high
        model_disagreement = disagreement >= self.disagreement_threshold

        if score_band_uncertain and model_disagreement:
            trigger = "DUAL_TRIGGER"
            verdict = Verdict.ESCALATE.value
            band = BandPosition.UNCERTAIN_BAND.value
            reason = (
                f"Score ({primary_score:.4f}) in uncertain band [{self.tau_low:.2f}, {self.tau_high:.2f}] "
                f"AND inter-model disagreement ({disagreement:.4f} >= {self.disagreement_threshold:.2f})."
            )
        elif score_band_uncertain:
            trigger = "SCORE_BAND"
            verdict = Verdict.ESCALATE.value
            band = BandPosition.UNCERTAIN_BAND.value
            reason = f"Primary score ({primary_score:.4f}) falls within uncertain band [{self.tau_low:.2f}, {self.tau_high:.2f}]."
        elif model_disagreement:
            trigger = "MODEL_DISAGREEMENT"
            verdict = Verdict.ESCALATE.value
            band = BandPosition.UNCERTAIN_BAND.value
            reason = (
                f"Inter-model disagreement detected: RF ({rf_score:.4f}) vs XGBoost ({xgb_score:.4f}) "
                f"differs by {disagreement:.4f} >= {self.disagreement_threshold:.2f}."
            )
        else:
            trigger = "NONE"
            if primary_score >= self.tau_high:
                verdict = Verdict.MALICIOUS.value
                band = BandPosition.MALICIOUS_BAND.value
            else:
                verdict = Verdict.BENIGN.value
                band = BandPosition.BENIGN_BAND.value
            reason = None

        return DualSignalDecision(
            sample_id=sample_id,
            primary_score=primary_score,
            rf_score=rf_score,
            xgb_score=xgb_score,
            disagreement=disagreement,
            band_position=band,
            verdict=verdict,
            trigger_fired=trigger,
            escalation_reason=reason,
        )
