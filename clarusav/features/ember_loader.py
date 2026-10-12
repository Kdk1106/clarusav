"""EMBER raw feature mapper and chronological dataset loader."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from clarusav.config import ClarusConfig, load_config
from clarusav.features.extractor import LivePEFeatureExtractor
from clarusav.features.registry import FeatureRegistry, default_registry


@dataclass
class DatasetSplits:
    """Container for partitioned and sanitized feature matrices."""

    X_train: np.ndarray
    y_train: np.ndarray
    sha256_train: list[str]

    X_val: np.ndarray
    y_val: np.ndarray
    sha256_val: list[str]

    X_test: np.ndarray
    y_test: np.ndarray
    sha256_test: list[str]

    feature_names: list[str]
    duplicates_detected: int
    unlabelled_dropped: int


class EMBERFeatureMapper:
    """Maps EMBER raw feature JSON records into the ClarusAV compact feature space."""

    def __init__(
        self,
        config: ClarusConfig | None = None,
        registry: FeatureRegistry | None = None,
    ) -> None:
        self.config = config or load_config()
        self.registry = registry or default_registry
        self.suspicious_watchlist: set[str] = {
            s.lower() for s in self.config.features.suspicious_imports
        }
        self._extractor = LivePEFeatureExtractor(config=self.config, registry=self.registry)

    def map_record(
        self,
        record: dict[str, Any],
        reference_time: float | None = None,
    ) -> dict[str, float]:
        """Extract the 6 canonical features from an EMBER raw JSON record.

        Args:
            record: Raw EMBER record dictionary.
            reference_time: Reference time for timestamp anomaly detection.

        Returns:
            Dictionary mapping feature names to extracted float values.
        """
        # 1. file_size
        general = record.get("general", {}) or {}
        file_size = float(general.get("size", 0.0))

        # 2. section_count
        section_info = record.get("section", {}) or {}
        sections = section_info.get("sections", []) or []
        section_count = float(len(sections))

        # 3. max_section_entropy
        section_entropies: list[float] = []
        for s in sections:
            ent = s.get("entropy")
            if ent is not None:
                section_entropies.append(float(ent))
        max_entropy = float(max(section_entropies, default=0.0))

        # 4. import_count & 5. suspicious_import_count
        import_dict = record.get("imports", {}) or {}
        total_imports = 0
        suspicious_imports = 0

        if isinstance(import_dict, dict) and import_dict:
            for _lib_name, funcs in import_dict.items():
                if isinstance(funcs, list):
                    for func in funcs:
                        total_imports += 1
                        if (
                            isinstance(func, str)
                            and func.strip().lower() in self.suspicious_watchlist
                        ):
                            suspicious_imports += 1
        else:
            # Fallback to general.imports if import dictionary not populated
            total_imports = int(general.get("imports", 0))

        # 6. timestamp_anomaly
        header = record.get("header", {}) or {}
        coff = header.get("coff", {}) or {}
        timestamp = int(coff.get("timestamp", 0))

        ts_anomaly = float(self._extractor.compute_timestamp_anomaly(timestamp, reference_time))

        return {
            "file_size": file_size,
            "section_count": section_count,
            "max_section_entropy": max_entropy,
            "import_count": float(total_imports),
            "suspicious_import_count": float(suspicious_imports),
            "timestamp_anomaly": ts_anomaly,
        }

    def map_record_to_vector(
        self,
        record: dict[str, Any],
        reference_time: float | None = None,
    ) -> list[float]:
        """Convert an EMBER record to an ordered vector according to registry."""
        feat_map = self.map_record(record, reference_time=reference_time)
        return [feat_map[name] for name in self.registry.feature_names]


class EMBERDataLoader:
    """Loads, cleans, and partitions EMBER dataset records."""

    def __init__(
        self,
        config: ClarusConfig | None = None,
        registry: FeatureRegistry | None = None,
    ) -> None:
        self.config = config or load_config()
        self.registry = registry or default_registry
        self.mapper = EMBERFeatureMapper(config=self.config, registry=self.registry)

    def load_from_records(
        self,
        records: list[dict[str, Any]],
        val_fraction: float = 0.20,
        test_fraction: float = 0.20,
        reference_time: float | None = None,
    ) -> DatasetSplits:
        """Process in-memory EMBER records into chronological train/val/test splits."""
        cleaned_records: list[dict[str, Any]] = []
        unlabelled_dropped = 0

        # Step 1: Exclude unlabelled rows (label == -1)
        for rec in records:
            label = rec.get("label")
            if label is None or int(label) == -1:
                unlabelled_dropped += 1
                continue
            cleaned_records.append(rec)

        # Step 2: Chronological ordering based on 'appeared' field
        cleaned_records.sort(key=lambda r: str(r.get("appeared", "")))

        # Step 3: Chronological partition
        n_total = len(cleaned_records)
        if n_total == 0:
            empty_x = np.empty((0, len(self.registry)), dtype=np.float64)
            empty_y = np.empty((0,), dtype=np.int64)
            return DatasetSplits(
                X_train=empty_x,
                y_train=empty_y,
                sha256_train=[],
                X_val=empty_x,
                y_val=empty_y,
                sha256_val=[],
                X_test=empty_x,
                y_test=empty_y,
                sha256_test=[],
                feature_names=self.registry.feature_names,
                duplicates_detected=0,
                unlabelled_dropped=unlabelled_dropped,
            )

        n_test = int(n_total * test_fraction)
        n_train_val = n_total - n_test
        n_val = int(n_train_val * val_fraction)
        n_train = n_train_val - n_val

        raw_train = cleaned_records[:n_train]
        raw_val = cleaned_records[n_train:n_train_val]
        raw_test = cleaned_records[n_train_val:]

        # Step 4: Duplicate detection and cross-split sanitization
        train_hashes: set[str] = set()
        sanitized_train: list[dict[str, Any]] = []
        duplicates_count = 0

        for r in raw_train:
            sha = str(r.get("sha256", ""))
            if sha and sha in train_hashes:
                duplicates_count += 1
                continue
            if sha:
                train_hashes.add(sha)
            sanitized_train.append(r)

        val_hashes: set[str] = set()
        sanitized_val: list[dict[str, Any]] = []
        for r in raw_val:
            sha = str(r.get("sha256", ""))
            if sha and (sha in train_hashes or sha in val_hashes):
                duplicates_count += 1
                continue
            if sha:
                val_hashes.add(sha)
            sanitized_val.append(r)

        test_hashes: set[str] = set()
        sanitized_test: list[dict[str, Any]] = []
        for r in raw_test:
            sha = str(r.get("sha256", ""))
            if sha and (sha in train_hashes or sha in val_hashes or sha in test_hashes):
                duplicates_count += 1
                continue
            if sha:
                test_hashes.add(sha)
            sanitized_test.append(r)

        def _to_arrays(subset: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray, list[str]]:
            if not subset:
                return (
                    np.empty((0, len(self.registry)), dtype=np.float64),
                    np.empty((0,), dtype=np.int64),
                    [],
                )
            x_list: list[list[float]] = []
            y_list: list[int] = []
            sha_list: list[str] = []
            for item in subset:
                vec = self.mapper.map_record_to_vector(item, reference_time=reference_time)
                x_list.append(vec)
                y_list.append(int(item["label"]))
                sha_list.append(str(item.get("sha256", "")))
            return np.array(x_list, dtype=np.float64), np.array(y_list, dtype=np.int64), sha_list

        X_train, y_train, sha_train = _to_arrays(sanitized_train)
        X_val, y_val, sha_val = _to_arrays(sanitized_val)
        X_test, y_test, sha_test = _to_arrays(sanitized_test)

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
            feature_names=self.registry.feature_names,
            duplicates_detected=duplicates_count,
            unlabelled_dropped=unlabelled_dropped,
        )

    def load_from_jsonl(
        self,
        train_jsonl: str | Path,
        test_jsonl: str | Path | None = None,
        val_fraction: float = 0.20,
        reference_time: float | None = None,
    ) -> DatasetSplits:
        """Load datasets from JSON lines files adhering to EMBER format."""
        train_records: list[dict[str, Any]] = []
        with open(train_jsonl, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    train_records.append(json.loads(line))

        if test_jsonl is not None and Path(test_jsonl).is_file():
            test_records: list[dict[str, Any]] = []
            with open(test_jsonl, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        test_records.append(json.loads(line))
            # If explicit test file is provided, train file is split into train + val
            splits = self.load_from_records(
                train_records,
                val_fraction=val_fraction,
                test_fraction=0.0,
                reference_time=reference_time,
            )
            # Process test records: filter unlabelled and remove duplicates against train/val
            known_shas = set(splits.sha256_train) | set(splits.sha256_val)
            sanitized_test: list[dict[str, Any]] = []
            test_shas: set[str] = set()
            test_dropped_unlabelled = 0
            test_duplicates = 0

            for rec in test_records:
                label = rec.get("label")
                if label is None or int(label) == -1:
                    test_dropped_unlabelled += 1
                    continue
                sha = str(rec.get("sha256", ""))
                if sha and (sha in known_shas or sha in test_shas):
                    test_duplicates += 1
                    continue
                if sha:
                    test_shas.add(sha)
                sanitized_test.append(rec)

            test_x = (
                np.array(
                    [
                        self.mapper.map_record_to_vector(r, reference_time=reference_time)
                        for r in sanitized_test
                    ],
                    dtype=np.float64,
                )
                if sanitized_test
                else np.empty((0, len(self.registry)), dtype=np.float64)
            )
            test_y = (
                np.array([int(r["label"]) for r in sanitized_test], dtype=np.int64)
                if sanitized_test
                else np.empty((0,), dtype=np.int64)
            )
            test_sha_list = [str(r.get("sha256", "")) for r in sanitized_test]

            return DatasetSplits(
                X_train=splits.X_train,
                y_train=splits.y_train,
                sha256_train=splits.sha256_train,
                X_val=splits.X_val,
                y_val=splits.y_val,
                sha256_val=splits.sha256_val,
                X_test=test_x,
                y_test=test_y,
                sha256_test=test_sha_list,
                feature_names=self.registry.feature_names,
                duplicates_detected=splits.duplicates_detected + test_duplicates,
                unlabelled_dropped=splits.unlabelled_dropped + test_dropped_unlabelled,
            )

        # Single file case: partition into train, val, test
        return self.load_from_records(
            train_records,
            val_fraction=val_fraction,
            test_fraction=0.20,
            reference_time=reference_time,
        )
