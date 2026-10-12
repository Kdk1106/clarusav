"""Model bundle packaging, metadata serialization, and schema validation."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from clarusav.features.registry import FeatureRegistry, default_registry


class SchemaMismatchError(ValueError):
    """Raised when the loaded model bundle was trained on a different feature schema."""

    pass


@dataclass
class ModelBundle:
    """Encapsulates trained model, calibrator, explainer artifacts, and provenance metadata."""

    version: str
    seed: int
    feature_schema_hash: str
    feature_names: list[str]
    selected_model_type: str
    model: Any
    calibration_method: str = "none"
    calibrator: Any | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    train_timestamp: float = 0.0

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict calibrated probabilities p(y=1|x) for input feature matrix.

        Args:
            X: 2D numpy array of shape (n_samples, n_features).

        Returns:
            1D numpy array of probabilities in [0.0, 1.0].
        """
        X_arr = np.asarray(X, dtype=np.float64)
        if self.calibrator is not None:
            # CalibratedClassifierCV returns (n_samples, 2)
            proba = self.calibrator.predict_proba(X_arr)
            return proba[:, 1]
        elif hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X_arr)
            return proba[:, 1]
        else:
            raise AttributeError("Model object does not support predict_proba.")

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Predict binary classifications based on probability threshold."""
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(np.int64)

    def save(self, output_path: str | Path) -> Path:
        """Serialize bundle artifact to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(
        cls,
        bundle_path: str | Path,
        registry: FeatureRegistry | None = None,
        verify_schema: bool = True,
    ) -> "ModelBundle":
        """Load and validate bundle from disk.

        Args:
            bundle_path: Path to serialized model bundle file.
            registry: Optional feature registry to verify schema hash against.
            verify_schema: Whether to verify schema hash matches registry.

        Returns:
            Loaded and validated ModelBundle instance.
        """
        path = Path(bundle_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model bundle not found: {path}")

        bundle: ModelBundle = joblib.load(path)
        if not isinstance(bundle, ModelBundle):
            raise TypeError(f"Loaded object is not a ModelBundle (got {type(bundle)}).")

        if verify_schema:
            target_reg = registry or default_registry
            expected_hash = target_reg.schema_hash()
            if bundle.feature_schema_hash != expected_hash:
                raise SchemaMismatchError(
                    f"Feature schema mismatch! Bundle hash: {bundle.feature_schema_hash}, "
                    f"Current registry hash: {expected_hash}. "
                    "Features may have been added, removed, or reordered since training."
                )

        return bundle
