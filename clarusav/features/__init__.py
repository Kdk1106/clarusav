"""Feature extraction, registry, and dataset loader modules for ClarusAV."""

from clarusav.features.ember_loader import EMBERDataLoader, EMBERFeatureMapper
from clarusav.features.entropy import calculate_entropy
from clarusav.features.extractor import LivePEFeatureExtractor
from clarusav.features.registry import Feature, FeatureRegistry

__all__ = [
    "calculate_entropy",
    "FeatureRegistry",
    "Feature",
    "LivePEFeatureExtractor",
    "EMBERFeatureMapper",
    "EMBERDataLoader",
]
