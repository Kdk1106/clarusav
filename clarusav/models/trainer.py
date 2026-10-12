"""Model training pipeline, calibration selection, and validation evaluation."""

import time
from typing import Any

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier

from clarusav.config import ClarusConfig, load_config
from clarusav.features.ember_loader import DatasetSplits
from clarusav.features.registry import FeatureRegistry, default_registry
from clarusav.models.bundle import ModelBundle


def compute_metrics(
    y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5
) -> dict[str, float]:
    """Compute standard classification metrics including FPR and Brier score."""
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    brier = float(brier_score_loss(y_true, y_prob))

    try:
        auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.5
    except ValueError:
        auc = 0.5

    return {
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "false_positive_rate": fpr,
        "brier_score": brier,
        "roc_auc": auc,
    }


class ModelTrainer:
    """Orchestrates identical-split training of RF & XGBoost, calibration selection, and model selection."""

    def __init__(
        self,
        config: ClarusConfig | None = None,
        registry: FeatureRegistry | None = None,
    ) -> None:
        self.config = config or load_config()
        self.registry = registry or default_registry
        self.seed = self.config.models.random_seed

    def train_and_select(
        self,
        splits: DatasetSplits,
    ) -> tuple[ModelBundle, dict[str, Any]]:
        """Train RF and XGBoost on training split, select model and calibration on validation split.

        Args:
            splits: Dataset splits containing train and validation sets.

        Returns:
            Tuple of (winning ModelBundle, full comparison metrics dictionary).
        """
        X_train, y_train = splits.X_train, splits.y_train
        X_val, y_val = splits.X_val, splits.y_val

        if len(X_train) == 0:
            raise ValueError("Training dataset is empty.")
        if len(X_val) == 0:
            raise ValueError("Validation dataset is empty.")

        # 1. Train Random Forest
        rf_cfg = self.config.models.rf
        rf_model = RandomForestClassifier(
            n_estimators=rf_cfg.n_estimators,
            max_depth=rf_cfg.max_depth,
            random_state=self.seed,
            class_weight="balanced",
            n_jobs=-1,
        )
        rf_model.fit(X_train, y_train)
        rf_val_prob = rf_model.predict_proba(X_val)[:, 1]
        rf_metrics = compute_metrics(y_val, rf_val_prob)

        # 2. Train XGBoost
        xgb_cfg = self.config.models.xgboost
        xgb_model = XGBClassifier(
            n_estimators=xgb_cfg.n_estimators,
            max_depth=xgb_cfg.max_depth,
            learning_rate=xgb_cfg.learning_rate or 0.1,
            random_state=self.seed,
            eval_metric="logloss",
            n_jobs=-1,
        )
        xgb_model.fit(X_train, y_train)
        xgb_val_prob = xgb_model.predict_proba(X_val)[:, 1]
        xgb_metrics = compute_metrics(y_val, xgb_val_prob)

        # 3. Model Selection Policy (based on validation F1 and FPR)
        # We prioritize F1, but if F1 is within 0.02, prefer the model with lower FPR.
        f1_diff = abs(rf_metrics["f1"] - xgb_metrics["f1"])
        if f1_diff <= 0.02:
            # FPR tie-breaker
            if rf_metrics["false_positive_rate"] < xgb_metrics["false_positive_rate"]:
                chosen_type = "rf"
                chosen_model = rf_model
            else:
                chosen_type = "xgboost"
                chosen_model = xgb_model
        elif rf_metrics["f1"] > xgb_metrics["f1"]:
            chosen_type = "rf"
            chosen_model = rf_model
        else:
            chosen_type = "xgboost"
            chosen_model = xgb_model

        # 4. Calibration Comparison (Platt vs Isotonic on validation split)
        try:
            from sklearn.calibration import FrozenEstimator

            cal_platt = CalibratedClassifierCV(
                estimator=FrozenEstimator(chosen_model), method="sigmoid"
            )
            cal_isotonic = CalibratedClassifierCV(
                estimator=FrozenEstimator(chosen_model), method="isotonic"
            )
        except ImportError:
            cal_platt = CalibratedClassifierCV(
                estimator=chosen_model, method="sigmoid", cv="prefit"
            )
            cal_isotonic = CalibratedClassifierCV(
                estimator=chosen_model, method="isotonic", cv="prefit"
            )

        cal_platt.fit(X_val, y_val)
        prob_platt = cal_platt.predict_proba(X_val)[:, 1]
        brier_platt = float(brier_score_loss(y_val, prob_platt))

        cal_isotonic.fit(X_val, y_val)
        prob_isotonic = cal_isotonic.predict_proba(X_val)[:, 1]
        brier_isotonic = float(brier_score_loss(y_val, prob_isotonic))

        raw_brier = rf_metrics["brier_score"] if chosen_type == "rf" else xgb_metrics["brier_score"]

        # Choose calibration with lowest Brier score
        if brier_isotonic <= brier_platt and brier_isotonic < raw_brier:
            chosen_cal_method = "isotonic"
            chosen_calibrator = cal_isotonic
            final_prob = prob_isotonic
        elif brier_platt < raw_brier:
            chosen_cal_method = "platt"
            chosen_calibrator = cal_platt
            final_prob = prob_platt
        else:
            chosen_cal_method = "platt"  # default standard in security ML
            chosen_calibrator = cal_platt
            final_prob = prob_platt

        calibrated_metrics = compute_metrics(y_val, final_prob)

        comparison_report = {
            "version": self.config.version,
            "seed": self.seed,
            "feature_schema_hash": self.registry.schema_hash(),
            "models_evaluated": {
                "rf": rf_metrics,
                "xgboost": xgb_metrics,
            },
            "selected_model": chosen_type,
            "calibration_evaluated": {
                "raw_brier": raw_brier,
                "platt_brier": brier_platt,
                "isotonic_brier": brier_isotonic,
            },
            "selected_calibration": chosen_cal_method,
            "validation_metrics": calibrated_metrics,
            "training_samples": len(X_train),
            "validation_samples": len(X_val),
            "timestamp": time.time(),
        }

        bundle = ModelBundle(
            version=self.config.version,
            seed=self.seed,
            feature_schema_hash=self.registry.schema_hash(),
            feature_names=self.registry.feature_names,
            selected_model_type=chosen_type,
            model=chosen_model,
            calibration_method=chosen_cal_method,
            calibrator=chosen_calibrator,
            metrics=calibrated_metrics,
            train_timestamp=time.time(),
        )

        return bundle, comparison_report
