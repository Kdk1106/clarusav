"""Unit tests for EMBER dataset loading, chronological splits, and cross-split sanitization."""

import json
from pathlib import Path

import numpy as np

from clarusav.features.ember_loader import EMBERDataLoader


def _create_sample_record(
    sha: str,
    appeared: str,
    label: int,
    size: int = 1000,
    imports_count: int = 5,
) -> dict:
    return {
        "sha256": sha,
        "appeared": appeared,
        "label": label,
        "general": {"size": size, "imports": imports_count},
        "header": {"coff": {"timestamp": 1515456000}},
        "section": {
            "sections": [
                {"name": ".text", "size": 800, "entropy": 5.5},
                {"name": ".data", "size": 200, "entropy": 2.1},
            ]
        },
        "imports": {"KERNEL32.dll": ["ExitProcess"]},
    }


def test_exclude_unlabelled_rows():
    """EMBER unlabelled rows (label == -1) must be dropped from dataset."""
    records = [
        _create_sample_record("sha1", "2018-01", label=0),
        _create_sample_record("sha2", "2018-02", label=-1),  # unlabelled
        _create_sample_record("sha3", "2018-03", label=1),
        _create_sample_record("sha4", "2018-04", label=-1),  # unlabelled
    ]

    loader = EMBERDataLoader()
    splits = loader.load_from_records(records, val_fraction=0.25, test_fraction=0.25)

    assert splits.unlabelled_dropped == 2
    total_kept = len(splits.y_train) + len(splits.y_val) + len(splits.y_test)
    assert total_kept == 2
    assert "sha2" not in splits.sha256_train + splits.sha256_val + splits.sha256_test
    assert "sha4" not in splits.sha256_train + splits.sha256_val + splits.sha256_test


def test_chronological_ordering_and_splits():
    """Dataset records must be sorted by 'appeared' date before partitioning."""
    dates = [
        "2018-05",
        "2018-01",
        "2018-12",
        "2018-03",
        "2018-08",
        "2018-02",
        "2018-10",
        "2018-04",
        "2018-09",
        "2018-07",
    ]
    records = [_create_sample_record(f"sha_{d}", d, label=(i % 2)) for i, d in enumerate(dates)]

    loader = EMBERDataLoader()
    # 10 records total. test_fraction=0.20 -> 2 test, 8 train_val. val_fraction=0.25 -> 2 val, 6 train.
    splits = loader.load_from_records(records, val_fraction=0.25, test_fraction=0.20)

    assert len(splits.sha256_train) == 6
    assert len(splits.sha256_val) == 2
    assert len(splits.sha256_test) == 2

    # Verify chronological sequence: train dates <= val dates <= test dates
    train_dates = [s.replace("sha_", "") for s in splits.sha256_train]
    val_dates = [s.replace("sha_", "") for s in splits.sha256_val]
    test_dates = [s.replace("sha_", "") for s in splits.sha256_test]

    assert max(train_dates) <= min(val_dates)
    assert max(val_dates) <= min(test_dates)


def test_cross_split_duplicate_detection():
    """Identical SHA-256 hashes occurring across splits or within splits must be deduplicated."""
    records = [
        _create_sample_record("sha_common", "2018-01", label=0),  # Train
        _create_sample_record("sha_unique_1", "2018-02", label=1),
        _create_sample_record("sha_common", "2018-05", label=0),  # Duplicate in val
        _create_sample_record("sha_unique_2", "2018-06", label=0),
        _create_sample_record("sha_common", "2018-10", label=1),  # Duplicate in test
        _create_sample_record("sha_unique_3", "2018-11", label=1),
    ]

    loader = EMBERDataLoader()
    splits = loader.load_from_records(records, val_fraction=0.33, test_fraction=0.33)

    assert splits.duplicates_detected == 2

    # Verify zero overlap between sha sets
    set_train = set(splits.sha256_train)
    set_val = set(splits.sha256_val)
    set_test = set(splits.sha256_test)

    assert len(set_train.intersection(set_val)) == 0
    assert len(set_train.intersection(set_test)) == 0
    assert len(set_val.intersection(set_test)) == 0


def test_load_from_jsonl_file(tmp_path: Path):
    """Verify loading from JSON lines file on disk."""
    jsonl_file = tmp_path / "ember_sample.jsonl"
    records = [_create_sample_record(f"hash_{i}", f"2018-0{i}", label=i % 2) for i in range(1, 9)]
    records.append(_create_sample_record("unlabelled_hash", "2018-05", label=-1))

    with open(jsonl_file, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    loader = EMBERDataLoader()
    splits = loader.load_from_jsonl(jsonl_file, val_fraction=0.25)

    assert splits.unlabelled_dropped == 1
    assert isinstance(splits.X_train, np.ndarray)
    assert splits.X_train.shape[1] == 6  # 6 canonical features
    assert len(splits.y_train) == splits.X_train.shape[0]
