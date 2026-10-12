"""Unit tests for TreeSHAP explainer and unit reporting across RF and XGBoost."""

import math

from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from clarusav.explain.explainer import TreeSHAPExplainer
from tests.test_models import _make_synthetic_splits


def test_shap_explainer_random_forest_units():
    """Verify TreeSHAP for Random Forest reports units as 'probability' and satisfies additivity."""
    splits = _make_synthetic_splits(n_train=100, seed=42)
    rf = RandomForestClassifier(n_estimators=30, max_depth=5, random_state=42)
    rf.fit(splits.X_train, splits.y_train)

    explainer = TreeSHAPExplainer(model=rf, model_type="rf", feature_names=splits.feature_names)
    assert explainer.units == "probability"

    sample = splits.X_val[0]
    explanation = explainer.explain_instance(sample, sample_id="test_rf_sample", top_k=3)

    assert explanation.units == "probability"
    assert explanation.model_type == "rf"
    assert len(explanation.top_features) == 3

    # Additivity check: base_value + sum(shap_values) == output_value
    total_shap = sum(explanation.all_contributions.values())
    expected_output = explanation.base_value + total_shap
    assert math.isclose(explanation.output_value, expected_output, rel_tol=1e-4)

    # Top-k ordering check: absolute shap values must be in descending order
    abs_shaps = [abs(f.shap_value) for f in explanation.top_features]
    assert abs_shaps == sorted(abs_shaps, reverse=True)

    # Direction check
    for f in explanation.top_features:
        assert f.units == "probability"
        if f.shap_value > 0:
            assert f.direction == "increases_risk"
        else:
            assert f.direction == "decreases_risk"


def test_shap_explainer_xgboost_units():
    """Verify TreeSHAP for XGBoost reports units as 'log-odds' and satisfies additivity."""
    splits = _make_synthetic_splits(n_train=100, seed=42)
    xgb = XGBClassifier(n_estimators=30, max_depth=4, random_state=42, eval_metric="logloss")
    xgb.fit(splits.X_train, splits.y_train)

    explainer = TreeSHAPExplainer(
        model=xgb, model_type="xgboost", feature_names=splits.feature_names
    )
    assert explainer.units == "log-odds"

    sample = splits.X_val[0]
    explanation = explainer.explain_instance(sample, sample_id="test_xgb_sample", top_k=4)

    assert explanation.units == "log-odds"
    assert explanation.model_type == "xgboost"
    assert len(explanation.top_features) == 4

    # Additivity check
    total_shap = sum(explanation.all_contributions.values())
    expected_output = explanation.base_value + total_shap
    assert math.isclose(explanation.output_value, expected_output, rel_tol=1e-4)

    for f in explanation.top_features:
        assert f.units == "log-odds"


def test_shap_explainer_batch():
    """Verify batch explanation across multiple samples."""
    splits = _make_synthetic_splits(n_train=80, seed=42)
    rf = RandomForestClassifier(n_estimators=20, random_state=42)
    rf.fit(splits.X_train, splits.y_train)

    explainer = TreeSHAPExplainer(model=rf, model_type="rf", feature_names=splits.feature_names)
    batch = splits.X_val[:5]
    results = explainer.explain_batch(batch, sample_ids=[f"sample_{i}" for i in range(5)], top_k=3)

    assert len(results) == 5
    for i, res in enumerate(results):
        assert res.sample_id == f"sample_{i}"
        assert res.units == "probability"
        assert len(res.top_features) == 3
