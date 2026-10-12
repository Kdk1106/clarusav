"""In-container behavioral monitoring agent using psutil and watchdog.

Tracks process spawns, file write rates, extension-change bursts, and mass renames.
Outputs structured JSON execution trace for behavioral rule evaluation.
"""

import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


@dataclass
class ProcessEvent:
    timestamp: float
    pid: int
    name: str
    cmdline: list[str]
    ppid: int


@dataclass
class FileEvent:
    timestamp: float
    event_type: str
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
    abnormal_termination: bool = False
    error_message: str | None = None


class SandboxFileEventHandler(FileSystemEventHandler):
    """Watches filesystem events inside sandbox workspace."""

    def __init__(self, trace: ExecutionTrace) -> None:
        super().__init__()
        self.trace = trace

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            size = 0
            try:
                size = os.path.getsize(event.src_path)
            except OSError:
                pass
            self.trace.file_events.append(
                FileEvent(
                    timestamp=time.time(),
                    event_type="created",
                    src_path=event.src_path,
                    file_size=size,
                )
            )
            self.trace.total_file_writes += 1

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            size = 0
            try:
                size = os.path.getsize(event.src_path)
            except OSError:
                pass
            self.trace.file_events.append(
                FileEvent(
                    timestamp=time.time(),
                    event_type="modified",
                    src_path=event.src_path,
                    file_size=size,
                )
            )
            self.trace.total_file_writes += 1

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            dest = getattr(event, "dest_path", None)
            self.trace.file_events.append(
                FileEvent(
                    timestamp=time.time(),
                    event_type="moved",
                    src_path=event.src_path,
                    dest_path=dest,
                )
            )
            self.trace.mass_renames_detected += 1
            if dest:
                src_ext = Path(event.src_path).suffix.lower()
                dest_ext = Path(dest).suffix.lower()
                if src_ext != dest_ext:
                    key = f"{src_ext}->{dest_ext}"
                    self.trace.extension_changes[key] = self.trace.extension_changes.get(key, 0) + 1


def run_monitor(sample_path: str, watch_dir: str, duration: int = 30) -> None:
    """Run in-container monitoring agent."""
    trace = ExecutionTrace(
        target_sample=sample_path,
        start_time=time.time(),
    )

    observer = Observer()
    handler = SandboxFileEventHandler(trace)
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()

    known_pids = set(psutil.pids())

    end_deadline = time.time() + duration
    try:
        while time.time() < end_deadline:
            current_pids = set(psutil.pids())
            new_pids = current_pids - known_pids
            for pid in new_pids:
                try:
                    p = psutil.Process(pid)
                    trace.processes.append(
                        ProcessEvent(
                            timestamp=time.time(),
                            pid=pid,
                            name=p.name(),
                            cmdline=p.cmdline(),
                            ppid=p.ppid(),
                        )
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            known_pids = current_pids
            time.sleep(0.5)
    finally:
        observer.stop()
        observer.join()
        trace.end_time = time.time()
        trace.duration_seconds = trace.end_time - trace.start_time

    # Output trace as JSON to stdout
    print(json.dumps(asdict(trace), indent=2))


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/sample.exe"
    workspace = sys.argv[2] if len(sys.argv) > 2 else "/workspace"
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    run_monitor(target, workspace, timeout)
