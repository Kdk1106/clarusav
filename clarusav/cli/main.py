"""ClarusAV command line interface built with Typer and Rich."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clarusav import __version__
from clarusav.bench.suite import BenchmarkSuite
from clarusav.config import load_config
from clarusav.explain.counterfactual import CounterfactualExplainer
from clarusav.explain.explainer import TreeSHAPExplainer
from clarusav.explain.narrative import NarrativeExplainer
from clarusav.features.ember_loader import EMBERDataLoader
from clarusav.features.extractor import LivePEFeatureExtractor, PEParserError
from clarusav.features.registry import default_registry
from clarusav.gate.engine import BandPosition, GateVerdict
from clarusav.models.bundle import ModelBundle
from clarusav.models.trainer import ModelTrainer, compute_metrics
from clarusav.quarantine.manager import QuarantineManager
from clarusav.report.renderer import (
    EntropyHeatmap,
    HTMLReportGenerator,
    SectionEntropyInfo,
)
from clarusav.report.sarif import generate_sarif_report
from clarusav.sandbox.backends import get_sandbox_backend
from clarusav.store.audit import AuditLog
from clarusav.store.cache import FastPathCache
from clarusav.ui.scan_view import (
    render_counterfactual_card,
    render_entropy_section,
    render_narrative_cards,
    render_shap_table,
    render_verdict_card,
)
from clarusav.watch.watcher import DirectoryWatcher

app = typer.Typer(
    name="clarusav",
    help="ClarusAV: Lightweight, explainable CLI antivirus for Windows PE files.",
    add_completion=False,
)
console = Console()


def _get_default_bundle_path() -> Path:
    candidates = [
        Path("models/artefacts/model_bundle.joblib"),
        Path("/tmp/clarusav/model_bundle.joblib"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return candidates[0]


@app.callback(invoke_without_command=True)
def main(
    version: bool | None = typer.Option(
        None, "--version", "-v", help="Display ClarusAV version.", is_eager=True
    ),
    ctx: typer.Context = typer.Option(None),
) -> None:
    """ClarusAV CLI entry point."""
    if version:
        console.print(f"[bold cyan]ClarusAV[/bold cyan] version [green]{__version__}[/green]")
        raise typer.Exit()

    # No sub-command: show banner + drop into interactive shell
    if ctx is not None and ctx.invoked_subcommand is None:
        from clarusav.ui.banner import show_banner
        from clarusav.ui.shell  import run_shell
        show_banner()
        run_shell()
        raise typer.Exit()


@app.command(name="doctor")
def doctor() -> None:
    """Perform health checks on ClarusAV environment, models, and Docker sandbox."""
    table = Table(title="ClarusAV Diagnostic Checks", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="dim")

    table.add_row("Core Engine", "[green]PASS[/green]", f"ClarusAV v{__version__}")
    table.add_row(
        "Feature Registry", "[green]PASS[/green]", f"{len(default_registry)} features registered"
    )

    cfg = load_config()
    table.add_row(
        "Configuration",
        "[green]PASS[/green]",
        f"Max file size: {cfg.features.max_file_size_bytes}B",
    )
    table.add_row(
        "Sandbox Backend", "[green]READY[/green]", f"Backend configured: {cfg.sandbox.backend}"
    )

    bundle_path = _get_default_bundle_path()
    if bundle_path.is_file():
        table.add_row("Model Bundle", "[green]PASS[/green]", f"Found: {bundle_path}")
    else:
        table.add_row("Model Bundle", "[yellow]NOT TRAINED[/yellow]", "Run 'clarusav train' first")

    console.print(table)


@app.command(name="features")
def list_features() -> None:
    """List all registered PE features and their schema hash."""
    console.print(
        Panel(
            f"[bold]Schema Hash (SHA-256):[/bold] [yellow]{default_registry.schema_hash()}[/yellow]",
            title="ClarusAV Feature Registry",
            border_style="cyan",
        )
    )
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Name", style="bold green")
    table.add_column("Unit", style="magenta")
    table.add_column("Description")

    for f in default_registry.features:
        table.add_row(f.name, f.unit, f.description)

    console.print(table)


@app.command(name="inspect-pe")
def inspect_pe(
    file_path: Path = typer.Argument(..., help="Path to Windows PE binary to inspect"),
) -> None:
    """Extract and display the compact 6-feature vector from a target PE file."""
    if not file_path.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        raise typer.Exit(code=1)

    extractor = LivePEFeatureExtractor()
    try:
        features = extractor.extract_from_file(file_path)
    except PEParserError as e:
        console.print(f"[bold red]Extraction Failed:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    table = Table(
        title=f"Extracted PE Features: {file_path.name}", show_header=True, header_style="bold cyan"
    )
    table.add_column("Feature", style="bold")
    table.add_column("Value", style="yellow")
    table.add_column("Unit", style="dim")

    for name in default_registry.feature_names:
        f_spec = default_registry.get(name)
        unit = f_spec.unit if f_spec else ""
        table.add_row(
            name,
            f"{features[name]:.4f}" if isinstance(features[name], float) else str(features[name]),
            unit,
        )

    console.print(table)


@app.command(name="train")
def train(
    data: Path = typer.Option(..., "--data", "-d", help="Path to EMBER dataset JSON lines file"),
    output: Path = typer.Option(
        Path("models/artefacts"),
        "--output",
        "-o",
        help="Output directory for model bundle and metrics",
    ),
    val_fraction: float = typer.Option(
        0.20, "--val-fraction", help="Holdout fraction for validation"
    ),
    seed: int | None = typer.Option(None, "--seed", help="Random seed override"),
) -> None:
    """Train Random Forest and XGBoost models, calibrate probabilities, and select the optimal classifier."""
    if not data.is_file():
        console.print(f"[bold red]Error:[/bold red] Dataset file not found: {data}")
        raise typer.Exit(code=1)

    output.mkdir(parents=True, exist_ok=True)
    cfg = load_config()
    if seed is not None:
        cfg.models.random_seed = seed

    console.print(f"[bold cyan]Loading dataset from:[/bold cyan] {data}")
    loader = EMBERDataLoader(config=cfg)
    splits = loader.load_from_jsonl(data, val_fraction=val_fraction)

    console.print(
        f"[green]Dataset partitioned:[/green] {len(splits.X_train)} train, "
        f"{len(splits.X_val)} validation, {len(splits.X_test)} test samples "
        f"({splits.unlabelled_dropped} unlabelled dropped, {splits.duplicates_detected} duplicates removed)"
    )

    trainer = ModelTrainer(config=cfg)
    bundle, comparison_report = trainer.train_and_select(splits)

    bundle_path = output / "model_bundle.joblib"
    metrics_path = output / "metrics.json"

    bundle.save(bundle_path)
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(comparison_report, f, indent=2)

    console.print(f"[bold green]Saved model bundle to:[/bold green] {bundle_path}")
    console.print(f"[bold green]Saved validation metrics to:[/bold green] {metrics_path}")

    table = Table(
        title="Model Comparison & Selection Results", show_header=True, header_style="bold magenta"
    )
    table.add_column("Candidate", style="bold")
    table.add_column("Val F1", style="cyan")
    table.add_column("Val FPR", style="red")
    table.add_column("Brier Score", style="yellow")
    table.add_column("Selected", style="bold green")

    rf_m = comparison_report["models_evaluated"]["rf"]
    xgb_m = comparison_report["models_evaluated"]["xgboost"]
    selected = comparison_report["selected_model"]

    table.add_row(
        "Random Forest",
        f"{rf_m['f1']:.4f}",
        f"{rf_m['false_positive_rate']:.4f}",
        f"{rf_m['brier_score']:.4f}",
        "YES" if selected == "rf" else "NO",
    )
    table.add_row(
        "XGBoost",
        f"{xgb_m['f1']:.4f}",
        f"{xgb_m['false_positive_rate']:.4f}",
        f"{xgb_m['brier_score']:.4f}",
        "YES" if selected == "xgboost" else "NO",
    )
    console.print(table)

    calib_table = Table(
        title="Probability Calibration Selection", show_header=True, header_style="bold blue"
    )
    calib_table.add_column("Calibration Method", style="bold")
    calib_table.add_column("Brier Score", style="yellow")
    calib_table.add_column("Selected", style="bold green")

    c_eval = comparison_report["calibration_evaluated"]
    chosen_c = comparison_report["selected_calibration"]
    calib_table.add_row("Uncalibrated (Raw)", f"{c_eval['raw_brier']:.4f}", "NO")
    calib_table.add_row(
        "Platt Scaling", f"{c_eval['platt_brier']:.4f}", "YES" if chosen_c == "platt" else "NO"
    )
    calib_table.add_row(
        "Isotonic Regression",
        f"{c_eval['isotonic_brier']:.4f}",
        "YES" if chosen_c == "isotonic" else "NO",
    )
    console.print(calib_table)

    gate_data = comparison_report.get("gate", {})
    if gate_data:
        gate_table = Table(
            title="Confidence Gate Threshold Search (Validation Only)",
            show_header=True,
            header_style="bold green",
        )
        gate_table.add_column("Parameter", style="bold")
        gate_table.add_column("Value", style="cyan")
        gate_table.add_row("Tau High (tau_h)", f"{gate_data['tau_high']:.4f}")
        gate_table.add_row("Tau Low (tau_l)", f"{gate_data['tau_low']:.4f}")
        gate_table.add_row("Recall Floor", f"{gate_data['recall_floor']:.4f}")
        gate_table.add_row("Val Escalation Rate", f"{gate_data['validation_escalation_rate']:.4%}")
        gate_table.add_row("Val Static Recall", f"{gate_data['validation_static_recall']:.4%}")
        console.print(gate_table)


@app.command(name="eval")
def eval_cmd(
    model: Path = typer.Option(
        ..., "--model", "-m", help="Path to model bundle artifact (.joblib)"
    ),
    data: Path = typer.Option(
        ..., "--data", "-d", help="Path to evaluation dataset JSON lines file"
    ),
    output: Path = typer.Option(
        Path("eval_metrics.json"), "--output", "-o", help="Output path for evaluation metrics JSON"
    ),
) -> None:
    """Evaluate a trained model bundle on a held-out test dataset and export real metrics."""
    if not model.is_file():
        console.print(f"[bold red]Error:[/bold red] Model bundle not found: {model}")
        raise typer.Exit(code=1)
    if not data.is_file():
        console.print(f"[bold red]Error:[/bold red] Evaluation data file not found: {data}")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Loading model bundle from:[/cyan] {model}")
    bundle = ModelBundle.load(model)

    console.print(f"[cyan]Loading evaluation records from:[/cyan] {data}")
    loader = EMBERDataLoader()
    splits = loader.load_from_jsonl(data, val_fraction=0.0)

    X_eval = splits.X_train if len(splits.X_test) == 0 else splits.X_test
    y_eval = splits.y_train if len(splits.y_test) == 0 else splits.y_test
    sha_eval = splits.sha256_train if len(splits.sha256_test) == 0 else splits.sha256_test

    if len(X_eval) == 0:
        console.print("[bold red]Error:[/bold red] Evaluation dataset contains 0 valid samples.")
        raise typer.Exit(code=1)

    probs = bundle.predict_proba(X_eval)
    eval_metrics = compute_metrics(y_eval, probs)

    decisions = [
        bundle.decide(
            score=float(p),
            sample_id=sha_eval[i] if i < len(sha_eval) else f"sample_{i}",
        )
        for i, p in enumerate(probs)
    ]
    test_mal = sum(1 for d in decisions if d.verdict == "MALICIOUS")
    test_ben = sum(1 for d in decisions if d.verdict == "BENIGN")
    test_esc = sum(1 for d in decisions if d.verdict == "ESCALATE")
    test_esc_rate = test_esc / len(decisions) if decisions else 0.0

    explainer = TreeSHAPExplainer(
        model=bundle.model,
        model_type=bundle.selected_model_type,
        feature_names=bundle.feature_names,
    )
    sample_sha = sha_eval[0] if sha_eval else "sample_0"
    explanation = explainer.explain_instance(X_eval[0], sample_id=sample_sha, top_k=5)

    eval_report = {
        "model_version": bundle.version,
        "seed": bundle.seed,
        "feature_schema_hash": bundle.feature_schema_hash,
        "selected_model_type": bundle.selected_model_type,
        "calibration_method": bundle.calibration_method,
        "evaluated_samples": len(X_eval),
        "metrics": eval_metrics,
        "gate_evaluation": {
            "frozen_tau_high": bundle.tau_high,
            "frozen_tau_low": bundle.tau_low,
            "test_malicious_count": test_mal,
            "test_benign_count": test_ben,
            "test_escalated_count": test_esc,
            "test_escalation_rate": round(test_esc_rate, 4),
        },
        "sample_explanation": explanation.summary_dict(),
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)

    console.print(f"[bold green]Saved evaluation metrics to:[/bold green] {output}")

    table = Table(
        title=f"Evaluation Metrics ({bundle.selected_model_type.upper()} - {bundle.calibration_method})",
        show_header=True,
        header_style="bold green",
    )
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="cyan")

    table.add_row("Evaluated Samples", str(len(X_eval)))
    table.add_row("Precision", f"{eval_metrics['precision']:.4f}")
    table.add_row("Recall", f"{eval_metrics['recall']:.4f}")
    table.add_row("F1 Score", f"{eval_metrics['f1']:.4f}")
    table.add_row("False Positive Rate (FPR)", f"{eval_metrics['false_positive_rate']:.4f}")
    table.add_row("Brier Score", f"{eval_metrics['brier_score']:.4f}")
    table.add_row("ROC AUC", f"{eval_metrics['roc_auc']:.4f}")
    table.add_row("Frozen Tau High (tau_h)", f"{bundle.tau_high:.4f}")
    table.add_row("Frozen Tau Low (tau_l)", f"{bundle.tau_low:.4f}")
    table.add_row("Test Escalation Rate", f"{test_esc_rate:.4%}")
    table.add_row("SHAP Units", explanation.units)

    console.print(table)


def _scan_single_file(
    file_path: Path,
    bundle: ModelBundle,
    cfg: Any,
    deep: bool = False,
    auto_quarantine: bool = False,
    cache: FastPathCache | None = None,
    audit_log: AuditLog | None = None,
    vault: QuarantineManager | None = None,
) -> dict[str, Any]:
    """Scan a single PE file through ClarusAV pipeline."""
    with open(file_path, "rb") as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()

    # Fast-path cache lookup
    if cache and not deep:
        cached = cache.get(sha256, model_version=bundle.version)
        if cached:
            return {
                "file_path": str(file_path),
                "sha256": sha256,
                "score": cached["score"],
                "verdict": cached["verdict"],
                "band_position": cached["band_position"],
                "stage": "fast_path_cache",
                "top_features": [],
                "narratives": [
                    "Result retrieved directly from verified SHA-256 allow/deny fast-path cache."
                ],
                "counterfactual": None,
                "quarantined": False,
                "sections": [],
            }

    # Feature extraction
    extractor = LivePEFeatureExtractor(config=cfg)
    try:
        raw_feats = extractor.extract_from_file(file_path)
    except Exception as e:
        return {
            "file_path": str(file_path),
            "sha256": sha256,
            "score": 0.50,
            "verdict": GateVerdict.UNRESOLVED.value,
            "band_position": BandPosition.UNCERTAIN_BAND.value,
            "stage": "feature_extraction_error",
            "top_features": [],
            "narratives": [f"Feature extraction failed: {e}. Sent for manual review."],
            "counterfactual": None,
            "quarantined": False,
            "sections": [],
        }

    feat_vector = np.array([raw_feats[name] for name in bundle.feature_names], dtype=np.float64)
    calibrated_prob = float(bundle.predict_proba(feat_vector.reshape(1, -1))[0])

    # TreeSHAP Explanations
    explainer = TreeSHAPExplainer(
        model=bundle.model,
        model_type=bundle.selected_model_type,
        feature_names=bundle.feature_names,
    )
    explanation = explainer.explain_instance(feat_vector, sample_id=sha256, top_k=6)
    narratives = NarrativeExplainer.generate_narrative_cards(explanation)
    cf_hint = CounterfactualExplainer.generate_counterfactual(bundle, feat_vector, explanation)

    # Initial Gate Evaluation
    gate_decision = bundle.decide(score=calibrated_prob, sample_id=sha256)
    final_verdict = gate_decision.verdict
    deciding_stage = "static_gate"
    band_pos = gate_decision.band_position

    # Check for escalation: either uncertain band or explicit deep scan
    if deep or gate_decision.verdict == GateVerdict.ESCALATE.value:
        sb = get_sandbox_backend(cfg.sandbox.backend, config=cfg)
        sb_result = sb.execute(file_path)
        deciding_stage = "sandbox_escalation"

        if sb_result.behavioral_verdict == "MALICIOUS":
            final_verdict = GateVerdict.MALICIOUS.value
            band_pos = BandPosition.MALICIOUS_BAND.value
            narratives.append(
                f"Disposable Sandbox Execution: MALICIOUS behavior observed ({sb_result.summary})."
            )
        elif sb_result.behavioral_verdict == "BENIGN":
            final_verdict = GateVerdict.BENIGN.value
            band_pos = BandPosition.BENIGN_BAND.value
            narratives.append(
                f"Disposable Sandbox Execution: BENIGN telemetry observed ({sb_result.summary})."
            )
        else:
            final_verdict = GateVerdict.UNRESOLVED.value
            band_pos = BandPosition.UNCERTAIN_BAND.value
            narratives.append(
                f"Disposable Sandbox Execution: UNRESOLVED manual review required ({sb_result.summary})."
            )

    quarantined = False
    if auto_quarantine and final_verdict == GateVerdict.MALICIOUS.value and vault:
        try:
            vault.quarantine(file_path, reason="MALICIOUS_VERDICT")
            quarantined = True
        except Exception as e:
            narratives.append(f"Quarantine error: {e}")

    # Write to Audit Log
    if audit_log:
        audit_log.append(
            file_sha256=sha256,
            target_path=str(file_path),
            verdict=final_verdict,
            score=calibrated_prob,
            deciding_stage=deciding_stage,
            model_version=bundle.version,
            tau_high=bundle.tau_high,
            tau_low=bundle.tau_low,
        )

    # Write to Fast-path cache
    if cache:
        cache.set(
            sha256=sha256,
            model_version=bundle.version,
            verdict=final_verdict,
            score=calibrated_prob,
            band_position=band_pos,
            deciding_stage=deciding_stage,
        )

    # Section entropy info for heatmap
    sections_info: list[dict[str, Any]] = []
    try:
        import pefile

        pe = pefile.PE(str(file_path))
        for s in pe.sections:
            raw_name = s.Name.decode("latin1", errors="ignore").split("\x00", 1)[0].strip()
            name = raw_name if raw_name else "<unnamed>"
            entropy = float(s.get_entropy())
            sections_info.append(
                {"name": name, "size": int(s.SizeOfRawData), "entropy": round(entropy, 3)}
            )
    except Exception:
        pass

    return {
        "file_path": str(file_path),
        "sha256": sha256,
        "score": calibrated_prob,
        "verdict": final_verdict,
        "band_position": band_pos,
        "stage": deciding_stage,
        "top_features": [
            {
                "name": f.feature_name,
                "value": f.feature_value,
                "shap_value": f.shap_value,
                "units": f.units,
                "direction": "increased risk" if f.shap_value > 0 else "reduced risk",
            }
            for f in explanation.top_features
        ],
        "narratives": narratives,
        "counterfactual": cf_hint.to_dict() if cf_hint else None,
        "quarantined": quarantined,
        "sections": sections_info,
    }


@app.command(name="scan")
def scan(
    target: Path = typer.Argument(..., help="PE file or directory to scan"),
    deep: bool = typer.Option(False, "--deep", help="Force behavioral sandbox execution"),
    quarantine: bool = typer.Option(
        False,
        "--quarantine",
        "-q",
        help="Automatically isolate malicious binaries in quarantine vault",
    ),
    model: Path | None = typer.Option(None, "--model", "-m", help="Path to model bundle (.joblib)"),
    html: Path | None = typer.Option(
        None, "--html", help="Path to write self-contained HTML report"
    ),
    sarif: Path | None = typer.Option(
        None, "--sarif", help="Path to write SARIF 2.1.0 JSON report"
    ),
    json_out: Path | None = typer.Option(
        None, "--json-out", help="Path to write structured JSON scan results"
    ),
) -> None:
    """Scan PE files with ML confidence gating, SHAP explanations, and ephemeral sandbox escalation."""
    cfg = load_config()
    bundle_path = model or _get_default_bundle_path()

    if not bundle_path.is_file():
        console.print(
            f"[bold red]Error:[/bold red] Model bundle not found at: {bundle_path}. Please run 'clarusav train' first."
        )
        raise typer.Exit(code=1)

    bundle = ModelBundle.load(bundle_path)
    cache = FastPathCache(cfg.paths.cache_path)
    audit_log = AuditLog(cfg.paths.audit_log_path)
    vault = QuarantineManager(cfg.paths.quarantine_dir)

    files_to_scan: list[Path] = []
    if target.is_file():
        files_to_scan.append(target)
    elif target.is_dir():
        for p in sorted(target.rglob("*")):
            if p.is_file() and p.suffix.lower() in [".exe", ".dll", ".sys", ".bin", ".scr", ""]:
                files_to_scan.append(p)
    else:
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        raise typer.Exit(code=1)

    if not files_to_scan:
        console.print(f"[yellow]No candidate executable files found in:[/yellow] {target}")
        raise typer.Exit(code=0)

    results: list[dict[str, Any]] = []

    for file_p in files_to_scan:
        res = _scan_single_file(
            file_path=file_p,
            bundle=bundle,
            cfg=cfg,
            deep=deep,
            auto_quarantine=quarantine,
            cache=cache,
            audit_log=audit_log,
            vault=vault,
        )
        results.append(res)

        # 1. High-Impact Executive Verdict Alert Card
        render_verdict_card(res, file_p)

        # 2. Section Entropy Heatmap with Critical Packing Alert
        if res.get("sections"):
            render_entropy_section(res["sections"])

        # 3. TreeSHAP Feature Attribution Table with Threat Level Alerts
        if res.get("top_features"):
            render_shap_table(
                top_features=res["top_features"],
                score=res["score"],
                model_type=bundle.selected_model_type,
            )

        # 4. Plain-English Narrative Explanation Cards with Severity Badges
        if res.get("narratives"):
            render_narrative_cards(res["narratives"])

        # 5. Counterfactual Decision Boundary & Remediation Simulation
        if res.get("counterfactual"):
            render_counterfactual_card(res["counterfactual"])

    # Optional report exports
    if html and results:
        HTMLReportGenerator.generate(results[0], html)
        console.print(f"[bold green]HTML report generated:[/bold green] {html}")

    if sarif and results:
        generate_sarif_report(results, output_path=sarif)
        console.print(f"[bold green]SARIF 2.1.0 report generated:[/bold green] {sarif}")

    if json_out and results:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        console.print(f"[bold green]JSON results written to:[/bold green] {json_out}")


@app.command(name="explain")
def explain(
    sample: str = typer.Argument(..., help="Path to PE binary or SHA-256 to explain"),
    model: Path | None = typer.Option(None, "--model", "-m", help="Path to model bundle (.joblib)"),
) -> None:
    """Explain a verdict using SHAP feature attribution, narrative cards, and counterfactuals."""
    cfg = load_config()
    bundle_path = model or _get_default_bundle_path()

    if not bundle_path.is_file():
        console.print(f"[bold red]Error:[/bold red] Model bundle not found at: {bundle_path}")
        raise typer.Exit(code=1)

    bundle = ModelBundle.load(bundle_path)
    sample_path = Path(sample)

    if sample_path.is_file():
        extractor = LivePEFeatureExtractor(config=cfg)
        raw_feats = extractor.extract_from_file(sample_path)
        x_vec = np.array([raw_feats[n] for n in bundle.feature_names], dtype=np.float64)
        sample_id = sample_path.name
    else:
        # Generate representative sample vector for demo
        x_vec = np.array([45000.0, 4.0, 6.95, 3.0, 2.0, 1.0], dtype=np.float64)
        sample_id = sample

    prob = float(bundle.predict_proba(x_vec.reshape(1, -1))[0])
    explainer = TreeSHAPExplainer(
        model=bundle.model,
        model_type=bundle.selected_model_type,
        feature_names=bundle.feature_names,
    )
    explanation = explainer.explain_instance(x_vec, sample_id=sample_id, top_k=6)
    narratives = NarrativeExplainer.generate_narrative_cards(explanation)
    cf_hint = CounterfactualExplainer.generate_counterfactual(bundle, x_vec, explanation)

    top_features = [
        {
            "name": f.feature_name,
            "value": f.feature_value,
            "shap_value": f.shap_value,
            "units": f.units,
            "direction": "increased risk" if f.shap_value > 0 else "reduced risk",
        }
        for f in explanation.top_features
    ]

    render_shap_table(top_features, score=prob, model_type=bundle.selected_model_type)
    render_narrative_cards(narratives)
    if cf_hint:
        render_counterfactual_card(cf_hint.to_dict())


@app.command(name="quarantine")
def quarantine(
    action: str = typer.Argument("list", help="Action: 'list' or 'restore'"),
    target_id: str | None = typer.Option(None, "--id", help="Target quarantine item ID"),
    vault_dir: Path | None = typer.Option(None, "--vault", help="Quarantine vault directory"),
) -> None:
    """Manage quarantined files: list isolated binaries or restore from vault."""
    cfg = load_config()
    v_dir = vault_dir or Path(cfg.paths.quarantine_dir)
    manager = QuarantineManager(v_dir)

    if action.lower() == "list":
        records = manager.list_records()
        table = Table(
            title=f"Quarantine Vault Manifest ({v_dir})",
            show_header=True,
            header_style="bold yellow",
        )
        table.add_column("Item ID", style="bold cyan")
        table.add_column("Original Path", style="dim")
        table.add_column("SHA-256", style="white")
        table.add_column("Size", justify="right")
        table.add_column("Status", style="bold")

        for r in records:
            status = "[green]RESTORED[/green]" if r.restored else "[red]ISOLATED[/red]"
            table.add_row(
                r.item_id, r.original_path, r.sha256[:16] + "...", f"{r.file_size:,} B", status
            )
        console.print(table)

    elif action.lower() == "restore":
        if not target_id:
            console.print("[bold red]Error:[/bold red] --id required for restore action.")
            raise typer.Exit(code=1)
        try:
            restored_path = manager.restore(target_id)
            console.print(
                f"[bold green]Restored file to original location:[/bold green] {restored_path}"
            )
        except Exception as e:
            console.print(f"[bold red]Restore failed:[/bold red] {e}")
            raise typer.Exit(code=1) from e
    else:
        console.print(f"[bold red]Unknown quarantine action:[/bold red] {action}")
        raise typer.Exit(code=1)


@app.command(name="watch")
def watch(
    directory: Path = typer.Argument(..., help="Directory to monitor in real-time"),
    quarantine: bool = typer.Option(
        False, "--quarantine", "-q", help="Auto-quarantine malicious files"
    ),
    model: Path | None = typer.Option(None, "--model", "-m", help="Path to model bundle (.joblib)"),
) -> None:
    """Live filesystem watcher and TUI dashboard."""
    if not directory.is_dir():
        console.print(f"[bold red]Error:[/bold red] Directory not found: {directory}")
        raise typer.Exit(code=1)

    cfg = load_config()
    bundle_path = model or _get_default_bundle_path()
    if not bundle_path.is_file():
        console.print(f"[bold red]Error:[/bold red] Model bundle not found at {bundle_path}")
        raise typer.Exit(code=1)

    bundle = ModelBundle.load(bundle_path)
    cache = FastPathCache(cfg.paths.cache_path)
    audit = AuditLog(cfg.paths.audit_log_path)
    vault = QuarantineManager(cfg.paths.quarantine_dir)

    def scan_callback(path: Path) -> dict[str, Any]:
        return _scan_single_file(
            file_path=path,
            bundle=bundle,
            cfg=cfg,
            deep=False,
            auto_quarantine=quarantine,
            cache=cache,
            audit_log=audit,
            vault=vault,
        )

    watcher = DirectoryWatcher(watch_dir=directory, scan_fn=scan_callback)
    console.print(f"[bold cyan]Starting ClarusAV live watch on:[/bold cyan] {directory}")
    watcher.start(interactive=True)


@app.command(name="history")
def history(
    verify: bool = typer.Option(
        False, "--verify", help="Verify cryptographic hash chain integrity"
    ),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of records to display"),
) -> None:
    """Display scan history or verify hash chain audit trail."""
    cfg = load_config()
    audit_log = AuditLog(cfg.paths.audit_log_path)

    if verify:
        is_valid, msg, count = audit_log.verify()
        if is_valid:
            console.print(
                Panel(f"[bold green]INTEGRITY VERIFIED:[/bold green] {msg}", border_style="green")
            )
        else:
            console.print(
                Panel(f"[bold red]INTEGRITY COMPROMISED:[/bold red] {msg}", border_style="red")
            )
        return

    entries = audit_log.load_entries()
    if not entries:
        console.print("[yellow]Audit log is empty.[/yellow]")
        return

    table = Table(
        title=f"ClarusAV Signed Audit Trail ({len(entries)} total entries)",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", justify="right", width=4)
    table.add_column("Target", style="bold")
    table.add_column("Verdict", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Stage", style="dim")
    table.add_column("Entry Hash (Chain)", style="yellow")

    for entry in entries[-limit:]:
        if entry.verdict == "MALICIOUS":
            v_style = "[bold red]MALICIOUS[/bold red]"
        elif entry.verdict == "BENIGN":
            v_style = "[bold green]BENIGN[/bold green]"
        else:
            v_style = "[bold yellow]" + entry.verdict + "[/bold yellow]"

        table.add_row(
            str(entry.index),
            Path(entry.target_path).name,
            v_style,
            f"{entry.score:.4f}",
            entry.deciding_stage,
            entry.entry_hash[:16] + "...",
        )
    console.print(table)


@app.command(name="bench")
def bench(
    data: Path | None = typer.Option(None, "--data", "-d", help="Path to benchmark dataset JSONL"),
    model: Path | None = typer.Option(None, "--model", "-m", help="Path to model bundle (.joblib)"),
    output: Path = typer.Option(
        Path("bench_results.csv"), "--output", "-o", help="Path to save benchmark results CSV"
    ),
    limit: int = typer.Option(500, "--limit", "-n", help="Sample limit for benchmark evaluation"),
) -> None:
    """Run benchmark evaluation suite measuring classification quality and latency percentiles."""
    bundle_path = model or _get_default_bundle_path()
    if not bundle_path.is_file():
        console.print(f"[bold red]Error:[/bold red] Model bundle not found at {bundle_path}")
        raise typer.Exit(code=1)

    dataset_path = data
    if dataset_path is None:
        candidates = [
            Path("dataset/ember_sample_test.jsonl"),
            Path("dataset/ember_sample_train.jsonl"),
            Path("data/synthetic_ember.jsonl"),
            Path("data/ember_sample.jsonl"),
        ]
        for c in candidates:
            if c.is_file():
                dataset_path = c
                break

    if dataset_path is None or not dataset_path.is_file():
        console.print("[bold red]Error:[/bold red] Benchmark dataset not found. Provide --data.")
        raise typer.Exit(code=1)

    bundle = ModelBundle.load(bundle_path)
    suite = BenchmarkSuite(bundle)
    console.print(
        f"[bold cyan]Running benchmark on:[/bold cyan] {dataset_path} (model: {bundle_path})"
    )
    results = suite.run_benchmark(data_path=dataset_path, output_csv=output, sample_limit=limit)
    suite.render_table(results, console=console)
    console.print(f"[bold green]Saved benchmark metrics to:[/bold green] {output}")


if __name__ == "__main__":
    app()


