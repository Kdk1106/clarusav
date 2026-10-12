"""Unit tests for probability calibration: Platt scaling vs Isotonic regression."""

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import brier_score_loss

from tests.test_models import _make_synthetic_splits


def test_platt_and_isotonic_calibration():
    """Verify both Platt and Isotonic calibration produce well-behaved probabilities."""
    splits = _make_synthetic_splits(n_train=250, n_val=80, seed=123)
    X_train, y_train = splits.X_train, splits.y_train
    X_val, y_val = splits.X_val, splits.y_val

    rf = RandomForestClassifier(n_estimators=50, random_state=42)
    rf.fit(X_train, y_train)

    raw_prob = rf.predict_proba(X_val)[:, 1]
    raw_brier = brier_score_loss(y_val, raw_prob)

    # 1. Platt scaling (sigmoid)
    try:
        from sklearn.calibration import FrozenEstimator

        cal_platt = CalibratedClassifierCV(estimator=FrozenEstimator(rf), method="sigmoid")
        cal_iso = CalibratedClassifierCV(estimator=FrozenEstimator(rf), method="isotonic")
    except ImportError:
        cal_platt = CalibratedClassifierCV(estimator=rf, method="sigmoid", cv="prefit")
        cal_iso = CalibratedClassifierCV(estimator=rf, method="isotonic", cv="prefit")

    cal_platt.fit(X_val, y_val)
    prob_platt = cal_platt.predict_proba(X_val)[:, 1]
    brier_platt = brier_score_loss(y_val, prob_platt)

    # 2. Isotonic regression
    cal_iso.fit(X_val, y_val)
    prob_iso = cal_iso.predict_proba(X_val)[:, 1]
    brier_iso = brier_score_loss(y_val, prob_iso)

    # Bounds check
    assert np.all((prob_platt >= 0.0) & (prob_platt <= 1.0))
    assert np.all((prob_iso >= 0.0) & (prob_iso <= 1.0))

    # Calibration should produce lower or competitive Brier score compared to raw
    assert brier_platt <= raw_brier + 0.05
    assert brier_iso <= raw_brier + 0.05
