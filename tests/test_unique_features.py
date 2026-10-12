"""Tests for ClarusAV unique features: narrative cards, counterfactual hints,

dual-signal uncertainty gating, drift monitoring, entropy heatmap, HTML report,
SARIF 2.1.0 generator, and benchmark suite.
"""

from pathlib import Path

from clarusav.bench.suite import BenchmarkSuite
from clarusav.explain.counterfactual import CounterfactualExplainer, CounterfactualHint
from clarusav.explain.explainer import ExplanationResult, FeatureContribution
from clarusav.explain.narrative import NarrativeExplainer
from clarusav.gate.engine import GateVerdict
from clarusav.gate.uncertainty import DualSignalGate
from clarusav.models.bundle import ModelBundle
from clarusav.report.renderer import (
    DriftMonitor,
    EntropyHeatmap,
    HTMLReportGenerator,
    SectionEntropyInfo,
)
from clarusav.report.sarif import generate_sarif_report
from clarusav.watch.watcher import ScanWorkerPool


def test_narrative_explanation_cards() -> None:
    top_features = [
        FeatureContribution(
            feature_name="max_section_entropy",
            feature_value=7.2,
            shap_value=0.25,
            direction="increases_risk",
            units="probability",
        ),
        FeatureContribution(
            feature_name="suspicious_import_count",
            feature_value=3.0,
            shap_value=0.18,
            direction="increases_risk",
            units="probability",
        ),
        FeatureContribution(
            feature_name="timestamp_anomaly",
            feature_value=1.0,
            shap_value=0.12,
            direction="increases_risk",
            units="probability",
        ),
        FeatureContribution(
            feature_name="import_count",
            feature_value=2.0,
            shap_value=0.08,
            direction="increases_risk",
            units="probability",
        ),
    ]
    explanation = ExplanationResult(
        sample_id="test_pe",
        model_type="rf",
        units="probability",
        base_value=0.5,
        output_value=0.92,
        top_features=top_features,
    )
    cards = NarrativeExplainer.generate_narrative_cards(explanation)
    assert len(cards) == 4
    assert any("packed code or cryptographic encryption" in c for c in cards)
    assert any("watchlist" in c for c in cards)
    assert any("timestamp" in c for c in cards)
    assert any("Sparse import table" in c for c in cards)


def test_counterfactual_explanation_hint() -> None:
    bundle = ModelBundle.load("models/artefacts/model_bundle.joblib")
    top_features = [
        FeatureContribution(
            feature_name="max_section_entropy",
            feature_value=7.5,
            shap_value=0.35,
            direction="increases_risk",
            units="probability",
        ),
        FeatureContribution(
            feature_name="suspicious_import_count",
            feature_value=5.0,
            shap_value=0.25,
            direction="increases_risk",
            units="probability",
        ),
    ]
    explanation = ExplanationResult(
        sample_id="sample_mal",
        model_type="rf",
        units="probability",
        base_value=0.5,
        output_value=0.95,
        top_features=top_features,
    )
    x = [60000.0, 4.0, 7.5, 10.0, 5.0, 1.0]
    hint = CounterfactualExplainer.generate_counterfactual(bundle, x, explanation)
    assert hint is None or isinstance(hint, CounterfactualHint)
    if hint:
        d = hint.to_dict()
        assert "target_band" in d
        assert "message" in d
        assert "disclaimer" in d
        assert d["disclaimer"] == "Model decision boundary explanation, not file intent."


def test_dual_signal_uncertainty_gate() -> None:
    gate = DualSignalGate(tau_high=0.85, tau_low=0.15, disagreement_threshold=0.20)

    # 1. Unambiguous benign
    dec1 = gate.evaluate(rf_score=0.08, xgb_score=0.10, primary_model_type="xgboost")
    assert dec1.verdict == "BENIGN"
    assert dec1.trigger_fired == "NONE"

    # 2. Unambiguous malicious
    dec2 = gate.evaluate(rf_score=0.90, xgb_score=0.92, primary_model_type="xgboost")
    assert dec2.verdict == "MALICIOUS"
    assert dec2.trigger_fired == "NONE"

    # 3. Uncertain band trigger
    dec3 = gate.evaluate(rf_score=0.50, xgb_score=0.52, primary_model_type="xgboost")
    assert dec3.verdict == "ESCALATE"
    assert dec3.trigger_fired == "SCORE_BAND"

    # 4. Disagreement trigger (primary says malicious, but RF disagrees by > 0.20)
    dec4 = gate.evaluate(rf_score=0.60, xgb_score=0.88, primary_model_type="xgboost")
    assert dec4.verdict == "ESCALATE"
    assert dec4.trigger_fired == "MODEL_DISAGREEMENT"


def test_drift_monitor() -> None:
    monitor = DriftMonitor(baseline_mean=0.50)

    # Insufficient observations
    drift, msg, _ = monitor.evaluate_drift(min_samples=5)
    assert not drift
    assert "Insufficient" in msg

    # Stable scores
    for _ in range(10):
        monitor.record_score(0.52)
    drift, msg, stats = monitor.evaluate_drift(min_samples=5)
    assert not drift
    assert stats["mean_shift"] < 0.30

    # Drifting distribution (all high scores)
    for _ in range(30):
        monitor.record_score(0.95)
    drift, msg, stats = monitor.evaluate_drift(min_samples=10)
    assert drift
    assert "DRIFT DETECTED" in msg


def test_entropy_heatmap_and_html_report(tmp_path: Path) -> None:
    sections = [
        SectionEntropyInfo(name=".text", size=4096, entropy=6.12),
        SectionEntropyInfo(name=".rsrc", size=2048, entropy=7.45),
        SectionEntropyInfo(name=".data", size=1024, entropy=3.21),
    ]
    term_table = EntropyHeatmap.render_terminal(sections)
    assert term_table.row_count == 3

    html_file = tmp_path / "report.html"
    scan_res = {
        "file_name": "sample.exe",
        "file_path": "/tmp/sample.exe",
        "sha256": "abc12345",
        "verdict": "MALICIOUS",
        "score": 0.885,
        "band_position": "MALICIOUS_BAND",
        "deciding_stage": "static_gate",
        "sections": [{"name": s.name, "size": s.size, "entropy": s.entropy} for s in sections],
        "narratives": ["Sample exhibited packed sections with entropy > 7.0."],
        "top_features": [
            {
                "name": "max_section_entropy",
                "value": 7.45,
                "shap_value": 0.35,
                "units": "prob",
                "direction": "high",
            }
        ],
    }
    out = HTMLReportGenerator.generate(scan_res, html_file)
    assert out.is_file()
    content = out.read_text(encoding="utf-8")
    assert "ClarusAV Security Report" in content
    assert "sample.exe" in content
    assert "MALICIOUS" in content


def test_sarif_report_generation(tmp_path: Path) -> None:
    sarif_file = tmp_path / "clarusav.sarif"
    scan_items = [
        {
            "file_path": "/path/to/bad.exe",
            "verdict": GateVerdict.MALICIOUS,
            "score": 0.94,
            "stage": "static_gate",
            "sha256": "11223344",
            "top_features": [{"name": "max_section_entropy", "shap_value": 0.3}],
        },
        {
            "file_path": "/path/to/good.exe",
            "verdict": GateVerdict.BENIGN,
            "score": 0.05,
            "stage": "static_gate",
            "sha256": "55667788",
            "top_features": [],
        },
    ]
    sarif = generate_sarif_report(scan_items, output_path=sarif_file)
    assert sarif_file.is_file()
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1  # Only malicious reported per SARIF standard
    assert results[0]["ruleId"] == "CLARUS-001"
    assert results[0]["level"] == "error"


def test_watch_worker_pool(tmp_path: Path) -> None:
    scanned_paths: list[str] = []

    def mock_scan(p: Path) -> dict:
        scanned_paths.append(str(p))
        return {"verdict": "BENIGN", "score": 0.1, "action": "none"}

    pool = ScanWorkerPool(scan_fn=mock_scan, max_workers=2, debounce_seconds=0.01)

    f1 = tmp_path / "test1.exe"
    f1.write_bytes(b"MZ\x00")
    pool.enqueue(f1)

    import time

    time.sleep(0.05)
    pool.process_pending()
    time.sleep(0.05)

    stats = pool.get_stats()
    assert stats["scanned"] == 1
    pool.shutdown()


def test_bench_suite_execution(tmp_path: Path) -> None:
    bundle = ModelBundle.load("models/artefacts/model_bundle.joblib")
    suite = BenchmarkSuite(bundle)

    csv_path = tmp_path / "bench.csv"
    results = suite.run_benchmark(
        data_path="dataset/ember_sample_test.jsonl", output_csv=csv_path, sample_limit=50
    )

    assert csv_path.is_file()
    assert "precision" in results
    assert "recall" in results
    assert "latency_p50_ms" in results
    assert results["sample_count"] > 0
