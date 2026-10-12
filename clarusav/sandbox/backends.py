"""Pluggable sandbox execution backends with honest fidelity labeling and ephemeral isolation."""

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path

from clarusav.config import ClarusConfig, load_config
from clarusav.sandbox.rules import BehavioralRuleEngine
from clarusav.sandbox.trace import ExecutionTrace, FileEvent, ProcessEvent, SandboxResult


class BaseSandboxBackend(ABC):
    """Abstract base class for ClarusAV disposable sandbox backends."""

    name: str = "base"
    fidelity_label: str = "UNKNOWN_FIDELITY"

    def __init__(self, config: ClarusConfig | None = None) -> None:
        self.config = config or load_config()
        self.rule_engine = BehavioralRuleEngine(self.config.sandbox.rules)

    @abstractmethod
    def execute(self, sample_path: Path, timeout: int | None = None) -> SandboxResult:
        """Execute the sample inside the disposable sandbox and return structured result."""
        pass


class MockSandboxBackend(BaseSandboxBackend):
    """Deterministic mock sandbox backend for unit tests, CI, and local verification without Docker daemon."""

    name: str = "mock"
    fidelity_label: str = "MOCK_FIDELITY - simulated synthetic behavior; no host execution"

    def __init__(
        self,
        config: ClarusConfig | None = None,
        scenario: str = "auto",
    ) -> None:
        super().__init__(config)
        self.scenario = scenario

    def execute(self, sample_path: Path, timeout: int | None = None) -> SandboxResult:
        """Simulate sandbox execution based on filename keywords or configured scenario."""
        timeout_limit = timeout or self.config.sandbox.timeout_seconds
        sample_name = sample_path.name.lower()

        # Determine scenario
        active_scenario = self.scenario
        if active_scenario == "auto":
            if "timeout" in sample_name:
                active_scenario = "timeout"
            elif "bulk" in sample_name or "modify" in sample_name or "rewrite" in sample_name:
                active_scenario = "bulk_modification"
            elif "rename" in sample_name or "ransom" in sample_name:
                active_scenario = "ransomware_mass_rename"
            elif "empty" in sample_name or "silent" in sample_name or "none" in sample_name:
                active_scenario = "silent"
            elif "error" in sample_name:
                active_scenario = "error"
            else:
                active_scenario = "benign"

        start = time.time()
        container_id = f"mock-cnt-{int(start)}"

        if active_scenario == "timeout":
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=start + timeout_limit,
                duration_seconds=float(timeout_limit),
                processes=[
                    ProcessEvent(
                        timestamp=start, pid=101, name="sample.exe", cmdline=["sample.exe"]
                    )
                ],
                timed_out=True,
                container_id=container_id,
                container_destroyed=True,
            )

        elif active_scenario == "error":
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=start + 0.1,
                duration_seconds=0.1,
                error_message="Docker OCI runtime failure: unable to mount scratch tmpfs",
                container_id=container_id,
                container_destroyed=True,
            )

        elif active_scenario == "silent":
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=start + 1.0,
                duration_seconds=1.0,
                processes=[],
                file_events=[],
                container_id=container_id,
                container_destroyed=True,
            )

        elif active_scenario == "bulk_modification":
            # 25 file writes in 2 seconds -> write rate = 12.5/s
            file_events = [
                FileEvent(
                    timestamp=start + 0.05 * i,
                    event_type="modified",
                    src_path=f"/workspace/doc_{i}.dat",
                    file_size=1024,
                )
                for i in range(25)
            ]
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=start + 2.0,
                duration_seconds=2.0,
                processes=[
                    ProcessEvent(
                        timestamp=start, pid=202, name="sample.exe", cmdline=["sample.exe"]
                    ),
                ],
                file_events=file_events,
                total_file_writes=25,
                container_id=container_id,
                container_destroyed=True,
            )

        elif active_scenario == "ransomware_mass_rename":
            # 8 renames with extension shifting from .txt to .locked
            file_events = [
                FileEvent(
                    timestamp=start + 0.1 * i,
                    event_type="moved",
                    src_path=f"/workspace/file_{i}.txt",
                    dest_path=f"/workspace/file_{i}.locked",
                )
                for i in range(8)
            ]
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=start + 1.5,
                duration_seconds=1.5,
                processes=[
                    ProcessEvent(
                        timestamp=start, pid=303, name="ransom.exe", cmdline=["ransom.exe"]
                    ),
                ],
                file_events=file_events,
                mass_renames_detected=8,
                extension_changes={".txt->.locked": 8},
                container_id=container_id,
                container_destroyed=True,
            )

        else:  # benign
            file_events = [
                FileEvent(
                    timestamp=start + 0.2,
                    event_type="created",
                    src_path="/workspace/config.ini",
                    file_size=64,
                ),
                FileEvent(
                    timestamp=start + 0.4,
                    event_type="modified",
                    src_path="/workspace/config.ini",
                    file_size=128,
                ),
            ]
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=start + 1.2,
                duration_seconds=1.2,
                processes=[
                    ProcessEvent(
                        timestamp=start, pid=404, name="benign.exe", cmdline=["benign.exe"]
                    ),
                ],
                file_events=file_events,
                total_file_writes=2,
                container_id=container_id,
                container_destroyed=True,
            )

        verdict, alerts, summary = self.rule_engine.evaluate(trace)

        return SandboxResult(
            target_sample=str(sample_path),
            backend_name=self.name,
            fidelity_label=self.fidelity_label,
            behavioral_verdict=verdict,
            trace=trace,
            alerts=[a.to_dict() for a in alerts],
            summary=summary,
        )


class WineContainerSandboxBackend(BaseSandboxBackend):
    """Ephemeral Docker container backend running Wine emulation with psutil/watchdog monitor."""

    name: str = "wine-container"
    fidelity_label: str = (
        "WINE_CONTAINER_FIDELITY - Linux user-mode Wine emulation; kernel drivers unobserved"
    )

    def execute(self, sample_path: Path, timeout: int | None = None) -> SandboxResult:
        """Run target PE inside hardened ephemeral disposable Docker container."""
        timeout_limit = timeout or self.config.sandbox.timeout_seconds
        start = time.time()
        container = None
        container_destroyed = False
        container_id = None

        try:
            import docker

            client = docker.from_env()
        except Exception as e:
            # Fallback when Docker daemon is unreachable
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=time.time(),
                duration_seconds=time.time() - start,
                error_message=f"Docker daemon connection failed: {e}",
                container_destroyed=True,
            )
            verdict, alerts, summary = self.rule_engine.evaluate(trace)
            return SandboxResult(
                target_sample=str(sample_path),
                backend_name=self.name,
                fidelity_label=self.fidelity_label,
                behavioral_verdict=verdict,
                trace=trace,
                alerts=[a.to_dict() for a in alerts],
                summary=summary,
            )

        # Container isolation parameters (STRICT SECURITY REQUIREMENTS)
        container_params = {
            "image": "clarusav-sandbox:latest",
            "command": [str(sample_path.name), "/workspace", str(timeout_limit)],
            "network_mode": "none",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": self.config.sandbox.pids_limit,
            "mem_limit": self.config.sandbox.memory_limit,
            "cpu_quota": self.config.sandbox.cpu_quota,
            "tmpfs": {
                "/workspace": "rw,noexec,nosuid,size=64m",
                "/tmp": "rw,noexec,nosuid,size=16m",
            },
            "volumes": {
                str(sample_path.resolve()): {"bind": f"/{sample_path.name}", "mode": "ro"},
            },
            "detach": True,
        }

        try:
            container = client.containers.run(**container_params)
            container_id = container.id
            result = container.wait(timeout=timeout_limit)
            logs = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")

            # Parse JSON trace emitted by monitor.py
            trace_dict = {}
            for line in logs.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        trace_dict = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        pass

            if trace_dict:
                trace = ExecutionTrace(
                    target_sample=str(sample_path),
                    start_time=trace_dict.get("start_time", start),
                    end_time=trace_dict.get("end_time", time.time()),
                    duration_seconds=trace_dict.get("duration_seconds", time.time() - start),
                    processes=[ProcessEvent(**p) for p in trace_dict.get("processes", [])],
                    file_events=[FileEvent(**f) for f in trace_dict.get("file_events", [])],
                    total_file_writes=trace_dict.get("total_file_writes", 0),
                    mass_renames_detected=trace_dict.get("mass_renames_detected", 0),
                    extension_changes=trace_dict.get("extension_changes", {}),
                    container_id=container_id,
                )
            else:
                trace = ExecutionTrace(
                    target_sample=str(sample_path),
                    start_time=start,
                    end_time=time.time(),
                    duration_seconds=time.time() - start,
                    error_message=f"No valid JSON trace captured from monitor. Container exit code: {result.get('StatusCode', -1)}",
                    container_id=container_id,
                )

        except Exception as e:
            trace = ExecutionTrace(
                target_sample=str(sample_path),
                start_time=start,
                end_time=time.time(),
                duration_seconds=time.time() - start,
                error_message=f"Container execution error: {e}",
                container_id=container_id,
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                    container_destroyed = True
                except Exception:
                    container_destroyed = False
            else:
                container_destroyed = True

        trace.container_destroyed = container_destroyed
        verdict, alerts, summary = self.rule_engine.evaluate(trace)

        return SandboxResult(
            target_sample=str(sample_path),
            backend_name=self.name,
            fidelity_label=self.fidelity_label,
            behavioral_verdict=verdict,
            trace=trace,
            alerts=[a.to_dict() for a in alerts],
            summary=summary,
        )


class WindowsContainerSandboxBackend(BaseSandboxBackend):
    """Documented stub for native Windows containers requiring Windows host with Container feature."""

    name: str = "windows-container"
    fidelity_label: str = "WINDOWS_CONTAINER_STUB_FIDELITY - native Windows kernel isolation; host requires Windows Server or Windows Pro with Hyper-V"

    def execute(self, sample_path: Path, timeout: int | None = None) -> SandboxResult:
        """Stub execution indicating environmental prerequisite."""
        start = time.time()
        trace = ExecutionTrace(
            target_sample=str(sample_path),
            start_time=start,
            end_time=start + 0.1,
            duration_seconds=0.1,
            error_message="Native Windows container backend is a stub on non-Windows hosts. Deploy on Windows Server 2022+ with Docker Windows Containers.",
            container_destroyed=True,
        )
        verdict, alerts, summary = self.rule_engine.evaluate(trace)
        return SandboxResult(
            target_sample=str(sample_path),
            backend_name=self.name,
            fidelity_label=self.fidelity_label,
            behavioral_verdict=verdict,
            trace=trace,
            alerts=[a.to_dict() for a in alerts],
            summary=summary,
        )


def get_sandbox_backend(
    name: str | None = None,
    config: ClarusConfig | None = None,
) -> BaseSandboxBackend:
    """Factory creating configured sandbox backend instance."""
    cfg = config or load_config()
    backend_choice = (name or cfg.sandbox.backend).lower()

    if backend_choice == "wine-container":
        return WineContainerSandboxBackend(cfg)
    elif backend_choice in ["windows", "windows-container", "windows-stub"]:
        return WindowsContainerSandboxBackend(cfg)
    else:
        return MockSandboxBackend(cfg)
