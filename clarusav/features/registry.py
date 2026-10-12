"""Extensible feature registry for ClarusAV."""

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Feature:
    """Metadata specification for a registered PE feature."""

    name: str
    description: str
    unit: str = "scalar"
    default_value: float = 0.0
    dtype: str = "float64"


class FeatureRegistry:
    """Registry maintaining ordered feature specifications and schema integrity."""

    def __init__(self) -> None:
        self._features: dict[str, Feature] = {}
        self._order: list[str] = []

    def register(self, feature: Feature) -> Feature:
        """Register a new feature specification."""
        if feature.name in self._features:
            raise ValueError(f"Feature '{feature.name}' already registered.")
        self._features[feature.name] = feature
        self._order.append(feature.name)
        return feature

    def register_feature(
        self,
        name: str,
        description: str,
        unit: str = "scalar",
        default_value: float = 0.0,
        dtype: str = "float64",
    ) -> Feature:
        """Helper to create and register a feature."""
        feat = Feature(
            name=name,
            description=description,
            unit=unit,
            default_value=default_value,
            dtype=dtype,
        )
        return self.register(feat)

    def get(self, name: str) -> Feature | None:
        """Retrieve a registered feature by name."""
        return self._features.get(name)

    @property
    def feature_names(self) -> list[str]:
        """Return the canonical ordered list of registered feature names."""
        return list(self._order)

    @property
    def features(self) -> list[Feature]:
        """Return list of Feature objects in canonical order."""
        return [self._features[name] for name in self._order]

    def __len__(self) -> int:
        return len(self._order)

    def schema_dict(self) -> list[dict]:
        """Return deterministic JSON-serializable schema definition."""
        return [
            {
                "name": f.name,
                "description": f.description,
                "unit": f.unit,
                "default_value": f.default_value,
                "dtype": f.dtype,
            }
            for f in self.features
        ]

    def schema_hash(self) -> str:
        """Compute SHA-256 hash of canonical feature schema for version locking."""
        serialized = json.dumps(self.schema_dict(), sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# Global default registry containing the Phase 1 core compact feature set
default_registry = FeatureRegistry()

FEATURE_FILE_SIZE = default_registry.register_feature(
    name="file_size",
    description="Total size of PE binary in bytes",
    unit="bytes",
    default_value=0.0,
)

FEATURE_SECTION_COUNT = default_registry.register_feature(
    name="section_count",
    description="Number of sections defined in section headers",
    unit="count",
    default_value=0.0,
)

FEATURE_MAX_SECTION_ENTROPY = default_registry.register_feature(
    name="max_section_entropy",
    description="Maximum Shannon entropy across all PE sections",
    unit="bits",
    default_value=0.0,
)

FEATURE_IMPORT_COUNT = default_registry.register_feature(
    name="import_count",
    description="Total count of imported API functions across all modules",
    unit="count",
    default_value=0.0,
)

FEATURE_SUSPICIOUS_IMPORT_COUNT = default_registry.register_feature(
    name="suspicious_import_count",
    description="Number of imports matching high-risk security watchlist",
    unit="count",
    default_value=0.0,
)

FEATURE_TIMESTAMP_ANOMALY = default_registry.register_feature(
    name="timestamp_anomaly",
    description="Indicator flag for anomalous or manipulated compile timestamp",
    unit="flag",
    default_value=0.0,
)
