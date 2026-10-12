"""Disposable sandbox execution backends and behavioral monitoring for ClarusAV."""

from clarusav.sandbox.backends import (
    BaseSandboxBackend,
    MockSandboxBackend,
    WindowsContainerSandboxBackend,
    WineContainerSandboxBackend,
    get_sandbox_backend,
)
from clarusav.sandbox.rules import BehaviorAlert, BehavioralRuleEngine
from clarusav.sandbox.trace import ExecutionTrace, FileEvent, ProcessEvent, SandboxResult

__all__ = [
    "BaseSandboxBackend",
    "MockSandboxBackend",
    "WineContainerSandboxBackend",
    "WindowsContainerSandboxBackend",
    "get_sandbox_backend",
    "BehavioralRuleEngine",
    "BehaviorAlert",
    "ExecutionTrace",
    "ProcessEvent",
    "FileEvent",
    "SandboxResult",
]
