"""Unit tests for ClarusAV configuration schema and validation."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from clarusav.config import ClarusConfig, load_config


def test_default_config_loading():
    """Verify default config loads correctly from default file."""
    cfg = load_config()
    assert cfg.version == "0.1.0"
    assert cfg.features.max_file_size_bytes == 104857600
    assert len(cfg.features.suspicious_imports) > 10
    assert "virtualalloc" in cfg.features.suspicious_imports
    assert cfg.gate.tau_high == 0.85
    assert cfg.gate.tau_low == 0.15
    assert cfg.sandbox.backend == "mock"


def test_custom_yaml_config_loading(tmp_path: Path):
    """Verify loading custom YAML config overrides defaults."""
    custom_yaml = tmp_path / "custom.yaml"
    custom_yaml.write_text(
        """
version: "0.2.0"
features:
  max_file_size_bytes: 52428800
  suspicious_imports:
    - "custominject"
gate:
  tau_high: 0.90
  tau_low: 0.10
""",
        encoding="utf-8",
    )

    cfg = load_config(custom_yaml)
    assert cfg.version == "0.2.0"
    assert cfg.features.max_file_size_bytes == 52428800
    assert cfg.features.suspicious_imports == ["custominject"]
    assert cfg.gate.tau_high == 0.90
    assert cfg.gate.tau_low == 0.10


def test_config_validation_constraints():
    """Ensure invalid threshold values are caught by Pydantic validation."""
    with pytest.raises(ValidationError):
        ClarusConfig(gate={"tau_high": 1.5})  # Must be <= 1.0

    with pytest.raises(ValidationError):
        ClarusConfig(gate={"tau_low": -0.1})  # Must be >= 0.0
