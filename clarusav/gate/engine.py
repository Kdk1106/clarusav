"""Confidence gating engine and deterministic threshold search minimizing sandbox escalation."""

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

import numpy as np


class BandPosition(StrEnum):
    MALICIOUS_BAND = "MALICIOUS_BAND"
    BENIGN_BAND = "BENIGN_BAND"
    UNCERTAIN_BAND = "UNCERTAIN_BAND"


class Verdict(StrEnum):
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"
    ESCALATE = "ESCALATE"
    UNRESOLVED = "UNRESOLVED"


GateVerdict = Verdict


@dataclass
class GateDecision:
    """Standardized verdict decision emitted by ClarusAV gating pipeline."""

    sample_id: str
    score: float
    band_position: str
    verdict: str
    deciding_stage: str
    tau_high: float
    tau_low: float
    top_k_shap: list[dict[str, Any]] = field(default_factory=list)
    escalation_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EscalationCurvePoint:
    """Data point on the escalation-rate versus quality trade-off curve."""

    recall_floor: float
    tau_low: float
    tau_high: float
    escalation_rate: float
    static_recall: float
    static_fpr: float
    static_benign_count: int
    static_malicious_count: int
    escalated_count: int


@dataclass
class ThresholdSearchResult:
    """Result of validation-only threshold optimization."""

    tau_low: float
    tau_high: float
    target_recall_floor: float
    validation_escalation_rate: float
    validation_static_recall: float
    validation_static_fpr: float
    escalation_curve: list[EscalationCurvePoint]


class ConfidenceGate:
    """Confidence gate for triaging predictions into confident bands or sandbox escalation."""

    def __init__(
        self,
        tau_high: float = 0.85,
        tau_low: float = 0.15,
        recall_floor: float = 0.98,
        escalation_curve: list[EscalationCurvePoint] | None = None,
    ) -> None:
        self.tau_high = float(tau_high)
        self.tau_low = float(tau_low)
        self.recall_floor = float(recall_floor)
        self.escalation_curve = escalation_curve or []

    @classmethod
    def fit_from_validation(
        cls,
        y_val: np.ndarray,
        p_val: np.ndarray,
        recall_floor: float = 0.98,
        fpr_max: float = 0.02,
        grid_resolution: int = 100,
    ) -> tuple["ConfidenceGate", ThresholdSearchResult]:
        """Search validation split deterministically to minimize escalation rate subject to recall floor.

        Args:
            y_val: Ground truth labels (0=benign, 1=malicious).
            p_val: Calibrated prediction probabilities in [0.0, 1.0].
            recall_floor: Minimum recall required for malicious samples (must not clear as benign).
            fpr_max: Maximum permissible false-positive rate in the static malicious band.
            grid_resolution: Discretization steps for threshold search.

        Returns:
            Tuple of (configured ConfidenceGate instance, ThresholdSearchResult).
        """
        y_true = np.asarray(y_val, dtype=np.int64)
        p_scores = np.asarray(p_val, dtype=np.float64)

        n_samples = len(y_true)
        n_mal = int(np.sum(y_true == 1))
        n_benign = int(np.sum(y_true == 0))

        if n_mal == 0 or n_benign == 0:
            # Fallback for degenerate validation splits
            gate = cls(tau_high=0.85, tau_low=0.15, recall_floor=recall_floor)
            res = ThresholdSearchResult(
                tau_low=0.15,
                tau_high=0.85,
                target_recall_floor=recall_floor,
                validation_escalation_rate=0.0,
                validation_static_recall=1.0,
                validation_static_fpr=0.0,
                escalation_curve=[],
            )
            return gate, res

        # Step 1: Candidate thresholds for tau_low
        # A malicious sample is cleared as benign if p <= tau_low (which is a false negative).
        # We require: (count of mal with p > tau_low) / n_mal >= target_recall
        # Which is equivalent to: (count of mal with p <= tau_low) / n_mal <= (1 - target_recall)
        # Therefore tau_low is bounded by the (1 - target_recall) quantile of malicious scores.
        mal_scores = np.sort(p_scores[y_true == 1])

        def find_optimal_thresholds_for_recall(
            target_rec: float,
        ) -> tuple[float, float, float, float, float]:
            max_missed_mal = int(np.floor(n_mal * (1.0 - target_rec)))
            if max_missed_mal == 0:
                # Cannot miss any malware; tau_low must be strictly below lowest malware score
                tau_l = max(0.0, float(mal_scores[0]) - 1e-4)
            else:
                idx = min(max_missed_mal - 1, len(mal_scores) - 1)
                tau_l = float(mal_scores[idx])

            # Clamp tau_l
            tau_l = min(max(tau_l, 0.0), 0.5)

            # For tau_high, we want static malicious convictions to have FPR <= fpr_max
            # Candidate tau_h from tau_l + epsilon up to 1.0
            candidate_tau_h = np.linspace(tau_l + 0.01, 0.99, grid_resolution)
            best_tau_h = 0.85
            min_escalation = 1.0
            best_fpr = 0.0
            best_rec = 1.0

            for t_h in candidate_tau_h:
                # Static convictions: p >= t_h
                fp = np.sum((p_scores >= t_h) & (y_true == 0))
                tp = np.sum((p_scores >= t_h) & (y_true == 1))
                fpr = fp / n_benign if n_benign > 0 else 0.0

                if fpr <= fpr_max:
                    # Escalated samples: tau_l < p < t_h
                    escalated = np.sum((p_scores > tau_l) & (p_scores < t_h))
                    esc_rate = escalated / n_samples
                    if esc_rate < min_escalation:
                        min_escalation = esc_rate
                        best_tau_h = float(t_h)
                        best_fpr = float(fpr)
                        # Static recall (fraction of all malware convicted statically)
                        best_rec = float(tp / n_mal) if n_mal > 0 else 1.0

            return (
                float(tau_l),
                float(best_tau_h),
                float(min_escalation),
                float(best_rec),
                float(best_fpr),
            )

        # Step 2: Compute escalation-vs-quality trade-off curve
        curve_targets = [0.80, 0.85, 0.90, 0.92, 0.95, 0.98, 0.99, 1.00]
        curve_points: list[EscalationCurvePoint] = []

        for target in curve_targets:
            t_l, t_h, esc_r, stat_rec, stat_fpr = find_optimal_thresholds_for_recall(target)
            benign_cnt = int(np.sum(p_scores <= t_l))
            mal_cnt = int(np.sum(p_scores >= t_h))
            esc_cnt = int(np.sum((p_scores > t_l) & (p_scores < t_h)))
            curve_points.append(
                EscalationCurvePoint(
                    recall_floor=float(target),
                    tau_low=round(t_l, 4),
                    tau_high=round(t_h, 4),
                    escalation_rate=round(esc_r, 4),
                    static_recall=round(stat_rec, 4),
                    static_fpr=round(stat_fpr, 4),
                    static_benign_count=benign_cnt,
                    static_malicious_count=mal_cnt,
                    escalated_count=esc_cnt,
                )
            )

        # Step 3: Optimal thresholds for the requested recall floor
        selected_tau_l, selected_tau_h, selected_esc, selected_rec, selected_fpr = (
            find_optimal_thresholds_for_recall(recall_floor)
        )

        search_result = ThresholdSearchResult(
            tau_low=round(selected_tau_l, 4),
            tau_high=round(selected_tau_h, 4),
            target_recall_floor=float(recall_floor),
            validation_escalation_rate=round(selected_esc, 4),
            validation_static_recall=round(selected_rec, 4),
            validation_static_fpr=round(selected_fpr, 4),
            escalation_curve=curve_points,
        )

        gate = cls(
            tau_high=search_result.tau_high,
            tau_low=search_result.tau_low,
            recall_floor=recall_floor,
            escalation_curve=curve_points,
        )

        return gate, search_result

    def decide(
        self,
        score: float,
        sample_id: str = "sample",
        shap_explanation: dict[str, Any] | None = None,
    ) -> GateDecision:
        """Evaluate a probability score against frozen thresholds and produce an immutable verdict."""
        p = float(score)
        top_k = []
        if shap_explanation and "top_features" in shap_explanation:
            top_k = shap_explanation["top_features"]

        if p >= self.tau_high:
            return GateDecision(
                sample_id=sample_id,
                score=p,
                band_position=BandPosition.MALICIOUS_BAND.value,
                verdict=Verdict.MALICIOUS.value,
                deciding_stage="STATIC_GATE",
                tau_high=self.tau_high,
                tau_low=self.tau_low,
                top_k_shap=top_k,
                escalation_reason=None,
            )
        elif p <= self.tau_low:
            return GateDecision(
                sample_id=sample_id,
                score=p,
                band_position=BandPosition.BENIGN_BAND.value,
                verdict=Verdict.BENIGN.value,
                deciding_stage="STATIC_GATE",
                tau_high=self.tau_high,
                tau_low=self.tau_low,
                top_k_shap=top_k,
                escalation_reason=None,
            )
        else:
            return GateDecision(
                sample_id=sample_id,
                score=p,
                band_position=BandPosition.UNCERTAIN_BAND.value,
                verdict=Verdict.ESCALATE.value,
                deciding_stage="STATIC_GATE",
                tau_high=self.tau_high,
                tau_low=self.tau_low,
                top_k_shap=top_k,
                escalation_reason=f"Score ({p:.4f}) in uncertain band [{self.tau_low:.4f}, {self.tau_high:.4f})",
            )

    def decide_batch(
        self,
        scores: np.ndarray | list[float],
        sample_ids: list[str] | None = None,
    ) -> list[GateDecision]:
        """Process batch of scores through confidence gate."""
        arr = np.asarray(scores, dtype=np.float64)
        decisions: list[GateDecision] = []
        for i, s in enumerate(arr):
            s_id = sample_ids[i] if sample_ids and i < len(sample_ids) else f"sample_{i}"
            decisions.append(self.decide(score=float(s), sample_id=s_id))
        return decisions
