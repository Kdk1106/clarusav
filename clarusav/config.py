"""Configuration models and loader for ClarusAV using Pydantic."""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class TimestampConfig(BaseModel):
    min_timestamp: int = Field(
        default=631152000, description="Minimum reasonable PE timestamp (1990-01-01)"
    )
    future_tolerance_seconds: int = Field(
        default=86400, description="Future timestamp tolerance in seconds"
    )


class FeaturesConfig(BaseModel):
    max_file_size_bytes: int = Field(default=104857600, description="100MB maximum file size limit")
    timestamp: TimestampConfig = Field(default_factory=TimestampConfig)
    suspicious_imports: list[str] = Field(
        default_factory=lambda: [
            "virtualalloc",
            "virtualallocex",
            "virtualprotect",
            "virtualprotectex",
            "writeprocessmemory",
            "readprocessmemory",
            "createremotethread",
            "ntcreatethreadex",
            "queueuserapc",
            "setthreadcontext",
            "getthreadcontext",
            "resumethread",
            "loadlibrarya",
            "loadlibraryw",
            "loadlibraryexa",
            "loadlibraryexw",
            "getprocaddress",
            "winexec",
            "shellexecutea",
            "shellexecutew",
            "createprocessa",
            "createprocessw",
            "urldownloadtofilea",
            "urldownloadtofilew",
            "internetopena",
            "internetopenw",
            "httpsendrequesta",
            "regcreatekeyexa",
            "regsetvalueexa",
            "setwindowshookexa",
            "setwindowshookexw",
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
        ]
    )


class GateConfig(BaseModel):
    tau_high: float = Field(default=0.85, ge=0.0, le=1.0)
    tau_low: float = Field(default=0.15, ge=0.0, le=1.0)
    recall_floor: float = Field(default=0.98, ge=0.0, le=1.0)


class TreeModelConfig(BaseModel):
    n_estimators: int = 100
    max_depth: int = 10
    learning_rate: float | None = 0.1
    random_state: int = 42


class ModelsConfig(BaseModel):
    random_seed: int = 42
    selected_model: str = "xgboost"
    calibration: str = "isotonic"
    rf: TreeModelConfig = Field(default_factory=lambda: TreeModelConfig(max_depth=12))
    xgboost: TreeModelConfig = Field(
        default_factory=lambda: TreeModelConfig(max_depth=6, learning_rate=0.1)
    )


class SandboxConfig(BaseModel):
    backend: str = "mock"
    timeout_seconds: int = 60
    memory_limit: str = "512m"
    pids_limit: int = 64
    cpu_quota: int = 100000


class PathsConfig(BaseModel):
    quarantine_dir: str = "/tmp/clarusav/quarantine"
    audit_log_path: str = "/tmp/clarusav/audit.log"
    cache_path: str = "/tmp/clarusav/cache.json"


class ClarusConfig(BaseModel):
    version: str = "0.1.0"
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    gate: GateConfig = Field(default_factory=GateConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)


def load_config(config_path: str | Path | None = None) -> ClarusConfig:
    """Load configuration from YAML file or return defaults."""
    if config_path is None:
        # Check standard default locations
        candidate = Path("configs/default.yaml")
        if candidate.is_file():
            config_path = candidate

    if config_path is not None:
        path = Path(config_path)
        if path.is_file():
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return ClarusConfig(**data)

    return ClarusConfig()
