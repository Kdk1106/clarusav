"""Acceptance test verifying `clarusav train` and `clarusav eval` write metrics JSON from real runs."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from clarusav.cli.main import app
from tests.test_ember_loader import _create_sample_record


@pytest.fixture
def synthetic_ember_files(tmp_path: Path):
    """Create realistic synthetic EMBER train and test JSON lines files."""
    train_file = tmp_path / "train.jsonl"
    eval_file = tmp_path / "eval.jsonl"

    train_records = []
    # 60 train/val records with alternating labels and dates
    for i in range(1, 61):
        is_mal = i % 2 == 0
        appeared = f"2018-{1 + (i % 8):02d}"
        rec = _create_sample_record(
            sha=f"train_sha_{i:04d}",
            appeared=appeared,
            label=1 if is_mal else 0,
            size=60000 if is_mal else 15000,
            imports_count=20 if is_mal else 5,
        )
        if is_mal:
            rec["imports"] = {"KERNEL32.dll": ["VirtualAlloc", "WriteProcessMemory"]}
            rec["section"]["sections"][0]["entropy"] = 7.2
        else:
            rec["imports"] = {"KERNEL32.dll": ["ExitProcess"]}
            rec["section"]["sections"][0]["entropy"] = 4.5
        train_records.append(rec)

    with open(train_file, "w", encoding="utf-8") as f:
        for r in train_records:
            f.write(json.dumps(r) + "\n")

    eval_records = []
    # 20 test records
    for i in range(1, 21):
        is_mal = i % 2 == 1
        appeared = f"2018-{9 + (i % 3):02d}"
        rec = _create_sample_record(
            sha=f"eval_sha_{i:04d}",
            appeared=appeared,
            label=1 if is_mal else 0,
            size=70000 if is_mal else 12000,
            imports_count=18 if is_mal else 4,
        )
        if is_mal:
            rec["imports"] = {"KERNEL32.dll": ["VirtualAlloc"]}
            rec["section"]["sections"][0]["entropy"] = 7.1
        else:
            rec["imports"] = {"KERNEL32.dll": ["ExitProcess"]}
            rec["section"]["sections"][0]["entropy"] = 4.2
        eval_records.append(rec)

    with open(eval_file, "w", encoding="utf-8") as f:
        for r in eval_records:
            f.write(json.dumps(r) + "\n")

    return train_file, eval_file


def test_cli_train_and_eval_acceptance(synthetic_ember_files, tmp_path: Path):
    """Test `clarusav train` and `clarusav eval` end-to-end and check written metrics JSON."""
    train_file, eval_file = synthetic_ember_files
    out_dir = tmp_path / "artefacts"
    eval_metrics_file = tmp_path / "eval_metrics.json"

    runner = CliRunner()

    # 1. Execute `clarusav train`
    train_res = runner.invoke(
        app,
        [
            "train",
            "--data",
            str(train_file),
            "--output",
            str(out_dir),
            "--val-fraction",
            "0.25",
            "--seed",
            "42",
        ],
    )
    assert train_res.exit_code == 0, f"train failed: {train_res.stdout}"

    bundle_path = out_dir / "model_bundle.joblib"
    metrics_path = out_dir / "metrics.json"

    assert bundle_path.is_file(), "model_bundle.joblib was not written"
    assert metrics_path.is_file(), "metrics.json was not written"

    # Verify metrics.json contains real calculated values
    with open(metrics_path, encoding="utf-8") as f:
        metrics_data = json.load(f)

    assert "models_evaluated" in metrics_data
    assert "rf" in metrics_data["models_evaluated"]
    assert "xgboost" in metrics_data["models_evaluated"]
    assert metrics_data["selected_model"] in ["rf", "xgboost"]
    assert "validation_metrics" in metrics_data
    assert metrics_data["validation_metrics"]["f1"] > 0.0

    # 2. Execute `clarusav eval`
    eval_res = runner.invoke(
        app,
        [
            "eval",
            "--model",
            str(bundle_path),
            "--data",
            str(eval_file),
            "--output",
            str(eval_metrics_file),
        ],
    )
    assert eval_res.exit_code == 0, f"eval failed: {eval_res.stdout}"
    assert eval_metrics_file.is_file(), "eval_metrics.json was not written"

    with open(eval_metrics_file, encoding="utf-8") as f:
        eval_data = json.load(f)

    assert "metrics" in eval_data
    assert "precision" in eval_data["metrics"]
    assert "recall" in eval_data["metrics"]
    assert "f1" in eval_data["metrics"]
    assert "false_positive_rate" in eval_data["metrics"]
    assert "sample_explanation" in eval_data
    assert eval_data["sample_explanation"]["units"] in ["probability", "log-odds"]
    assert len(eval_data["sample_explanation"]["top_features"]) > 0
