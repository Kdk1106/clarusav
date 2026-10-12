"""Unit tests for Phase 3 Confidence Gate, threshold search, and escalation-quality curve."""

from pathlib import Path

import numpy as np

from clarusav.gate.engine import BandPosition, ConfidenceGate, Verdict
from clarusav.models.bundle import ModelBundle
from clarusav.models.trainer import ModelTrainer
from tests.test_models import _make_synthetic_splits


def test_gate_threshold_search_deterministic():
    """Verify threshold search on validation produces identical results given fixed inputs."""
    rng = np.random.RandomState(42)
    y_val = rng.choice([0, 1], size=100, p=[0.5, 0.5])
    # Malicious scores generally higher, benign lower, some overlap in middle
    p_val = np.where(
        y_val == 1, rng.uniform(0.3, 0.95, size=100), rng.uniform(0.05, 0.65, size=100)
    )

    gate1, search1 = ConfidenceGate.fit_from_validation(
        y_val, p_val, recall_floor=0.95, fpr_max=0.02
    )
    gate2, search2 = ConfidenceGate.fit_from_validation(
        y_val, p_val, recall_floor=0.95, fpr_max=0.02
    )

    assert search1.tau_low == search2.tau_low
    assert search1.tau_high == search2.tau_high
    assert search1.validation_escalation_rate == search2.validation_escalation_rate
    assert gate1.tau_low == gate2.tau_low
    assert gate1.tau_high == gate2.tau_high


def test_gate_minimizes_escalation_subject_to_recall_floor():
    """Verify that tau_low satisfies the recall floor on validation."""
    rng = np.random.RandomState(99)
    y_val = rng.choice([0, 1], size=200, p=[0.5, 0.5])
    p_val = np.where(y_val == 1, rng.uniform(0.2, 0.99, size=200), rng.uniform(0.01, 0.7, size=200))

    recall_target = 0.95
    gate, search = ConfidenceGate.fit_from_validation(
        y_val, p_val, recall_floor=recall_target, fpr_max=0.02
    )

    # Check malware cleared as benign
    mal_mask = y_val == 1
    cleared_as_benign = np.sum((p_val <= gate.tau_low) & mal_mask)
    actual_recall = (np.sum(mal_mask) - cleared_as_benign) / np.sum(mal_mask)

    assert actual_recall >= recall_target - 1e-4
    assert 0.0 <= gate.tau_low < gate.tau_high <= 1.0


def test_escalation_vs_quality_curve_data():
    """Verify escalation-vs-quality trade-off curve points are generated."""
    rng = np.random.RandomState(123)
    y_val = rng.choice([0, 1], size=150, p=[0.5, 0.5])
    p_val = np.where(
        y_val == 1, rng.uniform(0.25, 0.95, size=150), rng.uniform(0.02, 0.70, size=150)
    )

    gate, search = ConfidenceGate.fit_from_validation(y_val, p_val, recall_floor=0.98)

    curve = search.escalation_curve
    assert len(curve) >= 5

    # Check curve fields
    for pt in curve:
        assert 0.0 <= pt.recall_floor <= 1.0
        assert 0.0 <= pt.tau_low < pt.tau_high <= 1.0
        assert 0.0 <= pt.escalation_rate <= 1.0
        assert pt.escalated_count >= 0
        assert pt.static_benign_count + pt.static_malicious_count + pt.escalated_count == len(y_val)


def test_gate_decisions_bands():
    """Verify triaging into confident bands and uncertain escalation."""
    gate = ConfidenceGate(tau_high=0.80, tau_low=0.20, recall_floor=0.95)

    # High score -> MALICIOUS
    dec_mal = gate.decide(score=0.92, sample_id="sha_mal")
    assert dec_mal.verdict == Verdict.MALICIOUS.value
    assert dec_mal.band_position == BandPosition.MALICIOUS_BAND.value
    assert dec_mal.deciding_stage == "STATIC_GATE"
    assert dec_mal.escalation_reason is None

    # Low score -> BENIGN
    dec_ben = gate.decide(score=0.10, sample_id="sha_ben")
    assert dec_ben.verdict == Verdict.BENIGN.value
    assert dec_ben.band_position == BandPosition.BENIGN_BAND.value
    assert dec_ben.deciding_stage == "STATIC_GATE"
    assert dec_ben.escalation_reason is None

    # Middle score -> ESCALATE
    dec_esc = gate.decide(score=0.55, sample_id="sha_esc")
    assert dec_esc.verdict == Verdict.ESCALATE.value
    assert dec_esc.band_position == BandPosition.UNCERTAIN_BAND.value
    assert dec_esc.deciding_stage == "STATIC_GATE"
    assert "uncertain band" in str(dec_esc.escalation_reason)


def test_thresholds_stored_and_frozen_in_bundle(tmp_path: Path):
    """Verify thresholds and escalation curve are stored and frozen in the ModelBundle."""
    splits = _make_synthetic_splits()
    trainer = ModelTrainer()
    bundle, report = trainer.train_and_select(splits)

    assert "gate" in report
    assert bundle.tau_high == report["gate"]["tau_high"]
    assert bundle.tau_low == report["gate"]["tau_low"]
    assert len(bundle.escalation_curve) > 0

    # Save and reload
    bundle_file = tmp_path / "gated_bundle.joblib"
    bundle.save(bundle_file)

    loaded = ModelBundle.load(bundle_file)
    assert loaded.tau_high == bundle.tau_high
    assert loaded.tau_low == bundle.tau_low
    assert loaded.recall_floor == bundle.recall_floor
    assert len(loaded.escalation_curve) == len(bundle.escalation_curve)

    # Test decide method on loaded bundle
    d = loaded.decide(score=0.95)
    assert d.verdict == "MALICIOUS"
