"""Counterfactual explanation generator via SHAP-guided feature perturbation."""

from dataclasses import dataclass
from typing import Any

import numpy as np

from clarusav.explain.explainer import ExplanationResult
from clarusav.models.bundle import ModelBundle


@dataclass
class CounterfactualHint:
    feature_name: str
    original_value: float
    counterfactual_value: float
    target_band: str
    message: str
    disclaimer: str = "Model decision boundary explanation, not file intent."

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "original_value": round(self.original_value, 4),
            "counterfactual_value": round(self.counterfactual_value, 4),
            "target_band": self.target_band,
            "message": self.message,
            "disclaimer": self.disclaimer,
        }


class CounterfactualExplainer:
    """Computes SHAP-guided single-feature perturbations that shift predictions across decision thresholds."""

    @staticmethod
    def generate_counterfactual(
        bundle: ModelBundle,
        x: np.ndarray | list[float],
        explanation: ExplanationResult,
    ) -> CounterfactualHint | None:
        """Find a minimal feature perturbation that would move the sample into the uncertain band."""
        x_orig = np.array(x, dtype=np.float64).flatten()
        current_prob = float(bundle.predict_proba(x_orig.reshape(1, -1))[0])

        tau_h = bundle.tau_high
        tau_l = bundle.tau_low

        # If already in uncertain band, no counterfactual needed
        if tau_l < current_prob < tau_h:
            return CounterfactualHint(
                feature_name="none",
                original_value=0.0,
                counterfactual_value=0.0,
                target_band="UNCERTAIN_BAND",
                message="Sample already resides in the uncertain escalation band.",
            )

        is_malicious = current_prob >= tau_h

        # Iterate top SHAP features in order of importance
        for top_f in explanation.top_features:
            fname = top_f.feature_name
            if fname not in bundle.feature_names:
                continue

            f_idx = bundle.feature_names.index(fname)
            orig_val = x_orig[f_idx]

            # Define search range based on feature semantics
            if fname == "suspicious_import_count":
                grid = [0.0, 1.0, 2.0, 3.0, 5.0, 10.0]
            elif fname == "timestamp_anomaly":
                grid = [0.0, 1.0]
            elif fname == "max_section_entropy":
                grid = list(np.linspace(2.0, 7.9, 30))
            elif fname == "import_count":
                grid = [1.0, 5.0, 15.0, 30.0, 50.0, 100.0]
            elif fname == "section_count":
                grid = [1.0, 2.0, 3.0, 5.0, 8.0]
            else:
                grid = list(np.linspace(orig_val * 0.1, orig_val * 2.0 + 1000, 20))

            # Test candidates
            best_cand = None
            for cand in grid:
                if cand == orig_val:
                    continue
                x_test = x_orig.copy()
                x_test[f_idx] = cand
                test_prob = float(bundle.predict_proba(x_test.reshape(1, -1))[0])

                if is_malicious and test_prob < tau_h:
                    best_cand = cand
                    break
                elif not is_malicious and test_prob > tau_l:
                    best_cand = cand
                    break

            if best_cand is not None:
                val_fmt = (
                    f"{best_cand:.2f}"
                    if isinstance(best_cand, float) and best_cand % 1 != 0
                    else f"{int(best_cand)}"
                )
                orig_fmt = (
                    f"{orig_val:.2f}"
                    if isinstance(orig_val, float) and orig_val % 1 != 0
                    else f"{int(orig_val)}"
                )
                msg = f"Verdict would move to the uncertain band if '{fname}' were {val_fmt} (currently {orig_fmt})."
                return CounterfactualHint(
                    feature_name=fname,
                    original_value=orig_val,
                    counterfactual_value=best_cand,
                    target_band="UNCERTAIN_BAND",
                    message=msg,
                )

        return None
