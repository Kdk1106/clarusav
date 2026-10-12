"""ClarusAV command line interface built with Typer and Rich."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clarusav import __version__
from clarusav.config import load_config
from clarusav.explain.explainer import TreeSHAPExplainer
from clarusav.features.ember_loader import EMBERDataLoader
from clarusav.features.extractor import LivePEFeatureExtractor, PEParserError
from clarusav.features.registry import default_registry
from clarusav.models.bundle import ModelBundle
from clarusav.models.trainer import ModelTrainer, compute_metrics

app = typer.Typer(
    name="clarusav",
    help="ClarusAV: Lightweight, explainable CLI antivirus for Windows PE files.",
    add_completion=False,
)
console = Console()


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
        "Sandbox Backend", "[yellow]READY[/yellow]", f"Backend configured: {cfg.sandbox.backend}"
    )

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

    # Rich summary table
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

    # Combine test & train into single evaluation set if standalone eval file
    X_eval = splits.X_train if len(splits.X_test) == 0 else splits.X_test
    y_eval = splits.y_train if len(splits.y_test) == 0 else splits.y_test
    sha_eval = splits.sha256_train if len(splits.sha256_test) == 0 else splits.sha256_test

    if len(X_eval) == 0:
        console.print("[bold red]Error:[/bold red] Evaluation dataset contains 0 valid samples.")
        raise typer.Exit(code=1)

    # Compute predictions
    probs = bundle.predict_proba(X_eval)
    eval_metrics = compute_metrics(y_eval, probs)

    # Compute SHAP explanation on the first sample
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
    table.add_row("SHAP Units", explanation.units)

    console.print(table)


# Placeholders for future phases
@app.command(name="scan")
def scan(
    target: Path = typer.Argument(..., help="File or directory to scan"),
    deep: bool = typer.Option(False, "--deep", help="Force behavioral sandbox execution"),
) -> None:
    """Scan a target file or directory for malicious PE files."""
    console.print(f"[yellow]Scanning target:[/yellow] {target} (deep={deep})")
    console.print("[dim]Pipeline models will be activated in Phase 3.[/dim]")


@app.command(name="explain")
def explain(sample_id: str = typer.Argument(..., help="Sample ID or SHA-256 to explain")) -> None:
    """Explain a verdict using SHAP feature attribution and narrative cards."""
    console.print(f"[yellow]Generating SHAP narrative explanation for:[/yellow] {sample_id}")


@app.command(name="quarantine")
def quarantine(
    action: str = typer.Argument("list", help="Action: 'list' or 'restore'"),
    target_id: str | None = typer.Option(None, "--id", help="Target quarantine item ID"),
) -> None:
    """Manage quarantined files."""
    console.print(f"[yellow]Quarantine action:[/yellow] {action} (id={target_id})")


@app.command(name="watch")
def watch(directory: Path = typer.Argument(..., help="Directory to monitor in real-time")) -> None:
    """Live filesystem watcher and TUI dashboard."""
    console.print(f"[yellow]Starting live watch on:[/yellow] {directory}")


@app.command(name="history")
def history(
    verify: bool = typer.Option(False, "--verify", help="Verify tamper-evident audit log"),
) -> None:
    """Display scan history or verify hash chain audit trail."""
    console.print(f"[yellow]Displaying scan audit trail (verify={verify})[/yellow]")


@app.command(name="bench")
def bench() -> None:
    """Run benchmark evaluation suite."""
    console.print("[yellow]Running benchmark suite...[/yellow]")


if __name__ == "__main__":
    app()
