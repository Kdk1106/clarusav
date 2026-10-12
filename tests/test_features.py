"""Unit tests verifying LivePEFeatureExtractor and EMBERFeatureMapper agreement on synthetic PE binaries."""

import math

import pytest

from clarusav.config import load_config
from clarusav.features.ember_loader import EMBERFeatureMapper
from clarusav.features.extractor import LivePEFeatureExtractor
from clarusav.features.registry import FeatureRegistry, default_registry
from tests.conftest import build_synthetic_pe, pe_to_ember_record


def test_feature_registry_integrity():
    """Verify registry ordering, duplication guard, and deterministic schema hashing."""
    reg = FeatureRegistry()
    f1 = reg.register_feature("feat_a", "Description A", unit="bytes")
    reg.register_feature("feat_b", "Description B", unit="count")

    assert reg.feature_names == ["feat_a", "feat_b"]
    assert len(reg) == 2
    assert reg.get("feat_a") == f1

    # Guard against duplicate registration
    with pytest.raises(ValueError, match="already registered"):
        reg.register(f1)

    # Hash should be stable and deterministic
    h1 = reg.schema_hash()
    assert isinstance(h1, str)
    assert len(h1) == 64
    assert h1 == reg.schema_hash()


def test_feature_registry_extensibility():
    """Verify registry can be cleanly extended with new security features."""
    reg = FeatureRegistry()
    for f in default_registry.features:
        reg.register(f)

    initial_count = len(reg)
    new_feat = reg.register_feature(
        name="rich_header_tool_count",
        description="Number of build tools listed in Microsoft Rich Header",
        unit="count",
    )
    assert len(reg) == initial_count + 1
    assert reg.feature_names[-1] == "rich_header_tool_count"
    assert reg.get("rich_header_tool_count") == new_feat


@pytest.mark.parametrize(
    "case_name,sections,imports,timestamp",
    [
        (
            "benign_sample",
            [
                (".text", b"\x90\x55\x89\xe5" * 64),
                (".rdata", b"Hello World string constants\x00" * 8),
            ],
            {"KERNEL32.dll": ["ExitProcess", "GetModuleHandleA", "GetLastError"]},
            1515456000,  # 2018-01-09
        ),
        (
            "suspicious_sample_packed",
            [
                (".text", bytes([(i * 37) % 256 for i in range(1024)])),
                (".data", b"\x00" * 256),
            ],
            {
                "KERNEL32.dll": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
                "USER32.dll": ["MessageBoxA"],
            },
            1546300800,  # 2019-01-01
        ),
        (
            "anomalous_zero_timestamp",
            [
                (".text", b"\xcc" * 512),
            ],
            {"KERNEL32.dll": ["ExitProcess"]},
            0,  # Zero timestamp
        ),
        (
            "no_imports_sample",
            [
                (".code", b"\x90" * 256),
                (".rodata", b"\x11\x22\x33\x44" * 32),
            ],
            {},  # No imports
            1609459200,  # 2021-01-01
        ),
    ],
)
def test_live_extractor_and_ember_mapper_agreement(
    case_name: str,
    sections: list,
    imports: dict,
    timestamp: int,
):
    """Prove that live extractor on raw PE binary and EMBER record mapper produce identical features."""
    pe_bytes = build_synthetic_pe(sections=sections, imports=imports, timestamp=timestamp)
    ember_rec = pe_to_ember_record(pe_bytes)

    config = load_config()
    live_extractor = LivePEFeatureExtractor(config=config)
    ember_mapper = EMBERFeatureMapper(config=config)

    # Reference time fixed to 2022-01-01 to ensure deterministic timestamp anomaly evaluation
    fixed_ref_time = 1640995200.0

    live_features = live_extractor.extract_from_bytes(pe_bytes, reference_time=fixed_ref_time)
    ember_features = ember_mapper.map_record(ember_rec, reference_time=fixed_ref_time)

    # Check identical keys
    assert set(live_features.keys()) == set(ember_features.keys())

    # 1. file_size
    assert live_features["file_size"] == ember_features["file_size"]
    assert live_features["file_size"] == float(len(pe_bytes))

    # 2. section_count
    assert live_features["section_count"] == ember_features["section_count"]

    # 3. max_section_entropy
    assert math.isclose(
        live_features["max_section_entropy"],
        ember_features["max_section_entropy"],
        rel_tol=1e-5,
        abs_tol=1e-5,
    )

    # 4. import_count
    assert live_features["import_count"] == ember_features["import_count"]

    # 5. suspicious_import_count
    assert live_features["suspicious_import_count"] == ember_features["suspicious_import_count"]

    # 6. timestamp_anomaly
    assert live_features["timestamp_anomaly"] == ember_features["timestamp_anomaly"]

    # Vector output check
    live_vec = live_extractor.extract_vector(pe_bytes, reference_time=fixed_ref_time)
    ember_vec = ember_mapper.map_record_to_vector(ember_rec, reference_time=fixed_ref_time)
    assert len(live_vec) == len(ember_vec) == 6
    for v_live, v_ember in zip(live_vec, ember_vec, strict=True):
        assert math.isclose(v_live, v_ember, rel_tol=1e-5, abs_tol=1e-5)


def test_suspicious_imports_case_insensitivity():
    """Suspicious imports matching must be case-insensitive."""
    pe_bytes = build_synthetic_pe(
        sections=[(".text", b"\x90" * 256)],
        imports={"KERNEL32.dll": ["vIrTuAlAlLoC", "SHELLexecuteA"]},
    )
    ember_rec = pe_to_ember_record(pe_bytes)

    extractor = LivePEFeatureExtractor()
    mapper = EMBERFeatureMapper()

    live_feats = extractor.extract_from_bytes(pe_bytes)
    ember_feats = mapper.map_record(ember_rec)

    assert live_feats["suspicious_import_count"] == 2.0
    assert ember_feats["suspicious_import_count"] == 2.0


def test_timestamp_anomaly_detection():
    """Verify anomaly detection rules: zero, historical (< 1990), future, and normal."""
    extractor = LivePEFeatureExtractor()
    ref_time = 1600000000.0  # ~ Sept 2020

    # 1. Zero timestamp
    assert extractor.compute_timestamp_anomaly(0, reference_time=ref_time) == 1

    # 2. Pre-1990 timestamp (e.g. year 1985 = 473385600)
    assert extractor.compute_timestamp_anomaly(473385600, reference_time=ref_time) == 1

    # 3. Future timestamp beyond tolerance (ref_time + 100 days)
    assert (
        extractor.compute_timestamp_anomaly(int(ref_time + 86400 * 100), reference_time=ref_time)
        == 1
    )

    # 4. Legitimate timestamp in range
    assert extractor.compute_timestamp_anomaly(1515456000, reference_time=ref_time) == 0
