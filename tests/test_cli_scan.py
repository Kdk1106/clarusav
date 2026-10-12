"""End-to-end acceptance tests for ClarusAV CLI scan, explain, quarantine, history, and bench commands."""

from pathlib import Path

from typer.testing import CliRunner

from clarusav.cli.main import app
from tests.conftest import build_synthetic_pe

runner = CliRunner()


def test_cli_scan_single_file(tmp_path: Path) -> None:
    # Create valid synthetic PE file
    pe_data = build_synthetic_pe(
        sections=[(".text", b"\x90" * 512), (".data", b"\x00" * 256)],
        imports={"KERNEL32.dll": ["ExitProcess", "GetProcAddress"]},
    )
    sample = tmp_path / "sample_benign.exe"
    sample.write_bytes(pe_data)

    html_out = tmp_path / "scan.html"
    sarif_out = tmp_path / "scan.sarif"
    json_out = tmp_path / "scan.json"

    res = runner.invoke(
        app,
        [
            "scan",
            str(sample),
            "--model",
            "models/artefacts/model_bundle.joblib",
            "--html",
            str(html_out),
            "--sarif",
            str(sarif_out),
            "--json-out",
            str(json_out),
        ],
    )
    assert res.exit_code == 0
    assert "ClarusAV Inspection Verdict" in res.stdout
    assert html_out.is_file()
    assert sarif_out.is_file()
    assert json_out.is_file()


def test_cli_scan_deep_mode(tmp_path: Path) -> None:
    pe_data = build_synthetic_pe(
        sections=[(".text", b"\x90" * 512)],
        imports={"KERNEL32.dll": ["ExitProcess"]},
    )
    sample = tmp_path / "sample_deep.exe"
    sample.write_bytes(pe_data)

    res = runner.invoke(
        app,
        [
            "scan",
            str(sample),
            "--deep",
            "--model",
            "models/artefacts/model_bundle.joblib",
        ],
    )
    assert res.exit_code == 0
    assert "Disposable Sandbox Execution" in res.stdout


def test_cli_explain_command(tmp_path: Path) -> None:
    pe_data = build_synthetic_pe(
        sections=[(".text", b"\x90" * 512)],
        imports={"KERNEL32.dll": ["ExitProcess"]},
    )
    sample = tmp_path / "sample_explain.exe"
    sample.write_bytes(pe_data)

    res = runner.invoke(
        app,
        [
            "explain",
            str(sample),
            "--model",
            "models/artefacts/model_bundle.joblib",
        ],
    )
    assert res.exit_code == 0
    assert "TreeSHAP Feature Attribution" in res.stdout
    assert "Narrative Explanation Cards" in res.stdout


def test_cli_quarantine_list() -> None:
    res = runner.invoke(app, ["quarantine", "list"])
    assert res.exit_code == 0
    assert "Quarantine Vault Manifest" in res.stdout


def test_cli_history_and_verify() -> None:
    # Check history listing
    res = runner.invoke(app, ["history"])
    assert res.exit_code == 0

    # Check verify hash chain
    res_v = runner.invoke(app, ["history", "--verify"])
    assert res_v.exit_code == 0
    assert "INTEGRITY VERIFIED" in res_v.stdout


def test_cli_bench_command(tmp_path: Path) -> None:
    csv_out = tmp_path / "bench_cli.csv"
    res = runner.invoke(
        app,
        [
            "bench",
            "--data",
            "dataset/ember_sample_test.jsonl",
            "--model",
            "models/artefacts/model_bundle.joblib",
            "--output",
            str(csv_out),
            "--limit",
            "30",
        ],
    )
    assert res.exit_code == 0
    assert "ClarusAV Model Benchmark & Latency Suite" in res.stdout
    assert csv_out.is_file()
