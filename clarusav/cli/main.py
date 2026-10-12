"""ClarusAV command line interface built with Typer and Rich."""

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clarusav import __version__
from clarusav.config import load_config
from clarusav.features.extractor import LivePEFeatureExtractor, PEParserError
from clarusav.features.registry import default_registry

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


# Placeholders for future phases to satisfy full CLI layout
@app.command(name="scan")
def scan(
    target: Path = typer.Argument(..., help="File or directory to scan"),
    deep: bool = typer.Option(False, "--deep", help="Force behavioral sandbox execution"),
) -> None:
    """Scan a target file or directory for malicious PE files."""
    console.print(f"[yellow]Scanning target:[/yellow] {target} (deep={deep})")
    console.print("[dim]Pipeline models will be activated in Phase 2 & 3.[/dim]")


@app.command(name="explain")
def explain(sample_id: str = typer.Argument(..., help="Sample ID or SHA-256 to explain")) -> None:
    """Explain a verdict using SHAP feature attribution and narrative cards."""
    console.print(f"[yellow]Generating SHAP narrative explanation for:[/yellow] {sample_id}")
    console.print("[dim]Explainability engine will be activated in Phase 2.[/dim]")


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
