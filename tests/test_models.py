"""Unit tests for model training, RF/XGBoost comparison, and bundle schema protection."""

from pathlib import Path

import numpy as np
import pytest

from clarusav.features.ember_loader import DatasetSplits
from clarusav.features.registry import FeatureRegistry, default_registry
from clarusav.models.bundle import ModelBundle, SchemaMismatchError
from clarusav.models.trainer import ModelTrainer


def _make_synthetic_splits(
    n_train=200, n_val=60, n_test=60, n_features=6, seed=42
) -> DatasetSplits:
    """Generate linearly separable synthetic dataset splits with deterministic noise."""
    rng = np.random.RandomState(seed)

    def gen_data(n):
        # 0: benign, 1: malicious
        y = rng.choice([0, 1], size=n, p=[0.6, 0.4])
        # Malicious samples have higher entropy, more suspicious imports, and smaller/larger file sizes
        X = np.zeros((n, n_features), dtype=np.float64)
        for i in range(n):
            if y[i] == 1:
                X[i, 0] = rng.uniform(50000, 200000)  # file_size
                X[i, 1] = rng.uniform(3, 8)  # section_count
                X[i, 2] = rng.uniform(6.5, 7.8)  # max_section_entropy (high)
                X[i, 3] = rng.uniform(10, 50)  # import_count
                X[i, 4] = rng.uniform(2, 6)  # suspicious_import_count (high)
                X[i, 5] = rng.choice([0.0, 1.0], p=[0.3, 0.7])  # timestamp_anomaly
            else:
                X[i, 0] = rng.uniform(10000, 150000)  # file_size
                X[i, 1] = rng.uniform(1, 4)  # section_count
                X[i, 2] = rng.uniform(3.0, 5.5)  # max_section_entropy (low)
                X[i, 3] = rng.uniform(5, 30)  # import_count
                X[i, 4] = rng.uniform(0, 1)  # suspicious_import_count (low)
                X[i, 5] = rng.choice([0.0, 1.0], p=[0.9, 0.1])  # timestamp_anomaly
        shas = [f"sha_{rng.randint(100000, 999999)}_{i}" for i in range(n)]
        return X, y, shas

    X_train, y_train, sha_train = gen_data(n_train)
    X_val, y_val, sha_val = gen_data(n_val)
    X_test, y_test, sha_test = gen_data(n_test)

    return DatasetSplits(
        X_train=X_train,
        y_train=y_train,
        sha256_train=sha_train,
        X_val=X_val,
        y_val=y_val,
        sha256_val=sha_val,
        X_test=X_test,
        y_test=y_test,
        sha256_test=sha_test,
        feature_names=default_registry.feature_names,
        duplicates_detected=0,
        unlabelled_dropped=0,
    )


def test_model_trainer_runs_and_selects():
    """Verify ModelTrainer trains both RF and XGBoost on identical splits and selects a model."""
    splits = _make_synthetic_splits()
    trainer = ModelTrainer()
    bundle, report = trainer.train_and_select(splits)

    assert bundle is not None
    assert bundle.selected_model_type in ["rf", "xgboost"]
    assert bundle.version == "0.1.0"
    assert bundle.seed == 42
    assert bundle.feature_schema_hash == default_registry.schema_hash()

    # Check both models were evaluated
    assert "rf" in report["models_evaluated"]
    assert "xgboost" in report["models_evaluated"]
    assert report["models_evaluated"]["rf"]["f1"] > 0.7
    assert report["models_evaluated"]["xgboost"]["f1"] > 0.7

    # Check predictions work and return valid probabilities
    probs = bundle.predict_proba(splits.X_val)
    assert len(probs) == len(splits.y_val)
    assert np.all((probs >= 0.0) & (probs <= 1.0))

    preds = bundle.predict(splits.X_val)
    assert set(np.unique(preds)).issubset({0, 1})


def test_bundle_save_load_roundtrip(tmp_path: Path):
    """Verify bundle serialization and deserialization."""
    splits = _make_synthetic_splits()
    trainer = ModelTrainer()
    bundle, _ = trainer.train_and_select(splits)

    bundle_file = tmp_path / "test_bundle.joblib"
    bundle.save(bundle_file)

    loaded_bundle = ModelBundle.load(bundle_file)
    assert loaded_bundle.version == bundle.version
    assert loaded_bundle.feature_schema_hash == bundle.feature_schema_hash
    assert loaded_bundle.selected_model_type == bundle.selected_model_type

    # Predictions match identically
    p_orig = bundle.predict_proba(splits.X_val)
    p_loaded = loaded_bundle.predict_proba(splits.X_val)
    np.testing.assert_allclose(p_orig, p_loaded)


def test_schema_mismatch_protection(tmp_path: Path):
    """Verify that loading a bundle with an incompatible schema hash is rejected."""
    splits = _make_synthetic_splits()
    trainer = ModelTrainer()
    bundle, _ = trainer.train_and_select(splits)

    bundle_file = tmp_path / "bundle.joblib"
    bundle.save(bundle_file)

    # Create an altered registry with an extra feature
    altered_reg = FeatureRegistry()
    for f in default_registry.features:
        altered_reg.register(f)
    altered_reg.register_feature("extra_feature", "Extra description")

    # Verification must raise SchemaMismatchError
    with pytest.raises(SchemaMismatchError, match="Feature schema mismatch"):
        ModelBundle.load(bundle_file, registry=altered_reg, verify_schema=True)
