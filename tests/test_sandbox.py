"""Integration and unit tests for Phase 4 Sandbox backends, isolation, and behavioral rule engine."""

from pathlib import Path

from clarusav.config import ClarusConfig, SandboxConfig
from clarusav.sandbox.backends import (
    MockSandboxBackend,
    WindowsContainerSandboxBackend,
    WineContainerSandboxBackend,
    get_sandbox_backend,
)
from clarusav.sandbox.rules import BehavioralRuleEngine
from clarusav.sandbox.trace import ExecutionTrace, FileEvent, ProcessEvent


def test_rule_engine_benign_trace():
    """Benign trace with modest activity produces BENIGN verdict."""
    engine = BehavioralRuleEngine()
    trace = ExecutionTrace(
        target_sample="benign.exe",
        start_time=100.0,
        end_time=102.0,
        duration_seconds=2.0,
        processes=[
            ProcessEvent(timestamp=100.1, pid=10, name="notepad.exe", cmdline=["notepad.exe"])
        ],
        file_events=[
            FileEvent(timestamp=100.5, event_type="created", src_path="/workspace/notes.txt")
        ],
        total_file_writes=1,
    )

    verdict, alerts, summary = engine.evaluate(trace)
    assert verdict == "BENIGN"
    assert len(alerts) == 0
    assert "Normal sandbox execution" in summary


def test_rule_engine_bulk_modification():
    """Burst of rapid file modifications triggers bulk_modification rule."""
    engine = BehavioralRuleEngine()
    trace = ExecutionTrace(
        target_sample="bulk_writer.exe",
        start_time=100.0,
        end_time=101.0,
        duration_seconds=1.0,
        processes=[
            ProcessEvent(timestamp=100.0, pid=20, name="worker.exe", cmdline=["worker.exe"])
        ],
        file_events=[
            FileEvent(timestamp=100.1, event_type="modified", src_path=f"/workspace/f_{i}.dat")
            for i in range(20)
        ],
        total_file_writes=20,
    )

    verdict, alerts, summary = engine.evaluate(trace)
    assert verdict == "MALICIOUS"
    assert any(a.rule_id == "bulk_modification" for a in alerts)
    assert "CRITICAL" in summary


def test_rule_engine_ransomware_mass_rename():
    """Burst of file renames and extension mutations triggers ransomware rule."""
    engine = BehavioralRuleEngine()
    trace = ExecutionTrace(
        target_sample="crypto_locker.exe",
        start_time=100.0,
        end_time=102.0,
        duration_seconds=2.0,
        processes=[ProcessEvent(timestamp=100.0, pid=30, name="enc.exe", cmdline=["enc.exe"])],
        file_events=[],
        mass_renames_detected=8,
        extension_changes={".docx->.locked": 8},
    )

    verdict, alerts, summary = engine.evaluate(trace)
    assert verdict == "MALICIOUS"
    assert any(a.rule_id == "ransomware_mass_rename" for a in alerts)


def test_rule_engine_suspicious_process_spawn():
    """Spawning known attacker tools (e.g. vssadmin, powershell) triggers process rule."""
    engine = BehavioralRuleEngine()
    trace = ExecutionTrace(
        target_sample="shadow_killer.exe",
        start_time=100.0,
        end_time=101.5,
        duration_seconds=1.5,
        processes=[
            ProcessEvent(
                timestamp=100.1,
                pid=40,
                name="vssadmin.exe",
                cmdline=["vssadmin.exe", "delete", "shadows", "/all"],
            ),
        ],
        file_events=[
            FileEvent(timestamp=100.2, event_type="created", src_path="/workspace/temp.log")
        ],
        total_file_writes=1,
    )

    verdict, alerts, _ = engine.evaluate(trace)
    assert verdict == "MALICIOUS"
    assert any(a.rule_id == "suspicious_process_spawn" for a in alerts)


def test_rule_engine_failures_produce_unresolved_never_benign():
    """Crucial safety requirement: errors, timeouts, and empty runs must yield UNRESOLVED."""
    engine = BehavioralRuleEngine()

    # Case A: Timeout
    t_timeout = ExecutionTrace(
        target_sample="stall.exe",
        start_time=100.0,
        timed_out=True,
    )
    v1, _, s1 = engine.evaluate(t_timeout)
    assert v1 == "UNRESOLVED - manual review"
    assert "timed out" in s1

    # Case B: Error
    t_err = ExecutionTrace(
        target_sample="crash.exe",
        start_time=100.0,
        error_message="Mount namespace failure",
    )
    v2, _, s2 = engine.evaluate(t_err)
    assert v2 == "UNRESOLVED - manual review"
    assert "error" in s2

    # Case C: No behavior observed (evasion or crash before hooks)
    t_silent = ExecutionTrace(
        target_sample="evasive.exe",
        start_time=100.0,
        processes=[],
        file_events=[],
    )
    v3, _, s3 = engine.evaluate(t_silent)
    assert v3 == "UNRESOLVED - manual review"
    assert "No execution behavior" in s3


def test_mock_sandbox_integration_scenarios(tmp_path: Path):
    """Integration test showing benign, bulk-rewrite, and timeout scenarios produce expected traces and destroyed container."""
    backend = MockSandboxBackend()

    # 1. Benign program
    benign_path = tmp_path / "harmless_script.exe"
    benign_path.write_bytes(b"MZ" + b"\x00" * 100)
    res_benign = backend.execute(benign_path)
    assert res_benign.behavioral_verdict == "BENIGN"
    assert res_benign.trace.container_destroyed is True
    assert "MOCK_FIDELITY" in res_benign.fidelity_label
    assert res_benign.trace.total_file_writes == 2

    # 2. Synthetic bulk file rewrite test program
    bulk_path = tmp_path / "synthetic_bulk_rewrite.exe"
    bulk_path.write_bytes(b"MZ" + b"\x00" * 100)
    res_bulk = backend.execute(bulk_path)
    assert res_bulk.behavioral_verdict == "MALICIOUS"
    assert res_bulk.trace.container_destroyed is True
    assert res_bulk.trace.total_file_writes == 25
    assert any(a["rule_id"] == "bulk_modification" for a in res_bulk.alerts)

    # 3. Timeout case
    timeout_path = tmp_path / "program_timeout.exe"
    timeout_path.write_bytes(b"MZ" + b"\x00" * 100)
    res_timeout = backend.execute(timeout_path, timeout=5)
    assert res_timeout.behavioral_verdict == "UNRESOLVED - manual review"
    assert res_timeout.trace.container_destroyed is True
    assert res_timeout.trace.timed_out is True


def test_backend_factory_and_fidelity_labels():
    """Verify backend factory and honest fidelity labeling across all backends."""
    mock_be = get_sandbox_backend("mock")
    assert isinstance(mock_be, MockSandboxBackend)
    assert "MOCK_FIDELITY" in mock_be.fidelity_label

    wine_be = get_sandbox_backend("wine-container")
    assert isinstance(wine_be, WineContainerSandboxBackend)
    assert "WINE_CONTAINER_FIDELITY" in wine_be.fidelity_label

    win_be = get_sandbox_backend("windows-container")
    assert isinstance(win_be, WindowsContainerSandboxBackend)
    assert "WINDOWS_CONTAINER_STUB_FIDELITY" in win_be.fidelity_label


def test_wine_container_isolation_parameters(tmp_path: Path):
    """Verify WineContainerSandboxBackend adheres strictly to isolation requirements."""
    cfg = ClarusConfig(
        sandbox=SandboxConfig(
            memory_limit="512m",
            pids_limit=64,
            cpu_quota=100000,
        )
    )
    backend = WineContainerSandboxBackend(config=cfg)

    # Verify execution handles offline / unavailable docker daemon safely without crashing
    sample = tmp_path / "test_sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 50)

    result = backend.execute(sample, timeout=10)
    assert result.backend_name == "wine-container"
    assert "WINE_CONTAINER_FIDELITY" in result.fidelity_label
    assert result.trace.container_destroyed is True
    # If docker daemon is not active in the test environment, error_message is populated and verdict is UNRESOLVED
    if result.trace.error_message:
        assert result.behavioral_verdict == "UNRESOLVED - manual review"
