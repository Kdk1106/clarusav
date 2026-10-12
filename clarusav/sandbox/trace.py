"""Structured execution trace and sandbox result dataclasses."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ProcessEvent:
    timestamp: float
    pid: int
    name: str
    cmdline: list[str]
    ppid: int = 0


@dataclass
class FileEvent:
    timestamp: float
    event_type: str  # created, modified, moved, deleted
    src_path: str
    dest_path: str | None = None
    file_size: int = 0


@dataclass
class ExecutionTrace:
    target_sample: str
    start_time: float
    end_time: float = 0.0
    duration_seconds: float = 0.0
    processes: list[ProcessEvent] = field(default_factory=list)
    file_events: list[FileEvent] = field(default_factory=list)
    total_file_writes: int = 0
    mass_renames_detected: int = 0
    extension_changes: dict[str, int] = field(default_factory=dict)
    write_rate_per_sec: float = 0.0
    timed_out: bool = False
    error_message: str | None = None
    container_id: str | None = None
    container_destroyed: bool = False

    def compute_metrics(self) -> None:
        """Calculate derived metrics such as write rate per second."""
        if self.duration_seconds <= 0.0 and self.end_time > self.start_time:
            self.duration_seconds = self.end_time - self.start_time

        dur = max(self.duration_seconds, 0.001)
        self.write_rate_per_sec = float(self.total_file_writes / dur)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SandboxResult:
    target_sample: str
    backend_name: str
    fidelity_label: str
    behavioral_verdict: str  # "MALICIOUS", "BENIGN", "UNRESOLVED - manual review"
    trace: ExecutionTrace
    alerts: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_sample": self.target_sample,
            "backend_name": self.backend_name,
            "fidelity_label": self.fidelity_label,
            "behavioral_verdict": self.behavioral_verdict,
            "trace": self.trace.to_dict(),
            "alerts": self.alerts,
            "summary": self.summary,
        }
