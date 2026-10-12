"""TreeSHAP explainer module for Random Forest and XGBoost classifiers."""

from dataclasses import dataclass

import numpy as np
import shap

from clarusav.features.registry import default_registry


@dataclass
class FeatureContribution:
    """Individual feature attribution from TreeSHAP."""

    feature_name: str
    feature_value: float
    shap_value: float
    direction: str  # "increases_risk" or "decreases_risk"
    units: str  # "probability" for RF, "log-odds" for XGBoost


@dataclass
class ExplanationResult:
    """Complete SHAP explanation report for a single sample."""

    sample_id: str | None
    model_type: str  # "rf" or "xgboost"
    units: str  # "probability" or "log-odds"
    base_value: float
    output_value: float
    top_features: list[FeatureContribution]
    all_contributions: dict[str, float]

    def summary_dict(self) -> dict:
        """Structured summary suitable for JSON logging and reporting."""
        return {
            "sample_id": self.sample_id,
            "model_type": self.model_type,
            "units": self.units,
            "base_value": round(self.base_value, 5),
            "output_value": round(self.output_value, 5),
            "top_features": [
                {
                    "name": f.feature_name,
                    "value": round(f.feature_value, 4),
                    "shap_value": round(f.shap_value, 5),
                    "direction": f.direction,
                    "units": f.units,
                }
                for f in self.top_features
            ],
            "all_contributions": {k: round(v, 5) for k, v in self.all_contributions.items()},
        }


class TreeSHAPExplainer:
    """TreeSHAP explainer ensuring correct unit reporting across RF and XGBoost."""

    def __init__(
        self,
        model: object,
        model_type: str,
        feature_names: list[str] | None = None,
    ) -> None:
        self.model = model
        self.model_type = model_type.lower()
        self.feature_names = feature_names or default_registry.feature_names

        # Validate and configure units
        if "rf" in self.model_type or "forest" in self.model_type:
            self.model_type = "rf"
            self.units = "probability"
        elif "xgb" in self.model_type:
            self.model_type = "xgboost"
            self.units = "log-odds"
        else:
            self.units = "probability"

        # Initialize TreeExplainer
        self.explainer = shap.TreeExplainer(self.model)

    def _extract_shap_and_base(self, X: np.ndarray) -> tuple[np.ndarray, float]:
        """Extract SHAP values and base value for class 1 (malicious)."""
        shap_values = self.explainer.shap_values(X)
        expected_value = self.explainer.expected_value

        # Handle RF multi-class output (list of arrays for class 0 and 1, or 3D array)
        if isinstance(shap_values, list):
            # Class 1 is malicious
            phi = shap_values[1] if len(shap_values) > 1 else shap_values[0]
            base_val = float(
                expected_value[1]
                if hasattr(expected_value, "__getitem__") and len(expected_value) > 1
                else expected_value
            )
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
            # Shape: (n_samples, n_features, n_classes)
            phi = shap_values[:, :, 1]
            base_val = float(
                expected_value[1]
                if hasattr(expected_value, "__getitem__") and len(expected_value) > 1
                else expected_value
            )
        else:
            # XGBoost binary output: (n_samples, n_features)
            phi = shap_values
            base_val = float(
                expected_value[0]
                if isinstance(expected_value, (list, np.ndarray)) and len(expected_value) > 0
                else expected_value
            )

        return np.asarray(phi, dtype=np.float64), base_val

    def explain_instance(
        self,
        x: np.ndarray | list[float],
        sample_id: str | None = None,
        top_k: int = 5,
    ) -> ExplanationResult:
        """Compute TreeSHAP attribution for a single sample."""
        x_arr = np.asarray(x, dtype=np.float64)
        if x_arr.ndim == 1:
            x_arr = x_arr.reshape(1, -1)

        phi, base_val = self._extract_shap_and_base(x_arr)
        instance_phi = phi[0]
        instance_vals = x_arr[0]

        contributions: list[FeatureContribution] = []
        all_contrib_map: dict[str, float] = {}

        for i, feat_name in enumerate(self.feature_names):
            val = float(instance_vals[i])
            s_val = float(instance_phi[i])
            direction = "increases_risk" if s_val > 0 else "decreases_risk"
            contrib = FeatureContribution(
                feature_name=feat_name,
                feature_value=val,
                shap_value=s_val,
                direction=direction,
                units=self.units,
            )
            contributions.append(contrib)
            all_contrib_map[feat_name] = s_val

        # Sort top-k by absolute SHAP impact
        sorted_top = sorted(contributions, key=lambda c: abs(c.shap_value), reverse=True)[:top_k]
        output_val = float(base_val + np.sum(instance_phi))

        return ExplanationResult(
            sample_id=sample_id,
            model_type=self.model_type,
            units=self.units,
            base_value=base_val,
            output_value=output_val,
            top_features=sorted_top,
            all_contributions=all_contrib_map,
        )

    def explain_batch(
        self,
        X: np.ndarray,
        sample_ids: list[str] | None = None,
        top_k: int = 5,
    ) -> list[ExplanationResult]:
        """Compute TreeSHAP explanations across a batch of samples."""
        X_arr = np.asarray(X, dtype=np.float64)
        phi, base_val = self._extract_shap_and_base(X_arr)

        results: list[ExplanationResult] = []
        n_samples = X_arr.shape[0]

        for idx in range(n_samples):
            s_id = sample_ids[idx] if sample_ids and idx < len(sample_ids) else f"sample_{idx}"
            instance_phi = phi[idx]
            instance_vals = X_arr[idx]

            contributions: list[FeatureContribution] = []
            all_contrib_map: dict[str, float] = {}

            for f_idx, feat_name in enumerate(self.feature_names):
                val = float(instance_vals[f_idx])
                s_val = float(instance_phi[f_idx])
                direction = "increases_risk" if s_val > 0 else "decreases_risk"
                contributions.append(
                    FeatureContribution(
                        feature_name=feat_name,
                        feature_value=val,
                        shap_value=s_val,
                        direction=direction,
                        units=self.units,
                    )
                )
                all_contrib_map[feat_name] = s_val

            sorted_top = sorted(contributions, key=lambda c: abs(c.shap_value), reverse=True)[
                :top_k
            ]
            output_val = float(base_val + np.sum(instance_phi))

            results.append(
                ExplanationResult(
                    sample_id=s_id,
                    model_type=self.model_type,
                    units=self.units,
                    base_value=base_val,
                    output_value=output_val,
                    top_features=sorted_top,
                    all_contributions=all_contrib_map,
                )
            )

        return results
