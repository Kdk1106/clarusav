#!/usr/bin/env python3
"""
Train ClarusAV directly from the EMBER parquet dataset.

Steps performed:
1️⃣ Download the EMBER v2 features dataset via kagglehub.
2️⃣ Convert the Parquet files to JSON‑Lines (the format the CLI trainer expects).
3️⃣ Load the data, train the models, calibrate, select the best one, and write out
   model_bundle.joblib and metrics.json.

Usage:
    python scripts/train_parquet.py [--output PATH] [--val-fraction FLOAT] [--seed INT]

Resulting files are written to <output>/model_bundle.joblib and <output>/metrics.json.
"""

import json
import sys
import tempfile
from pathlib import Path

import kagglehub
import pyarrow.parquet as pq
import typer
from rich.console import Console

# Add the project root to PYTHONPATH so we can import the package when this script runs.
sys.path.append(str(Path(__file__).resolve().parents[1]))
from clarusav.config import load_config
from clarusav.features.ember_loader import EMBERDataLoader
from clarusav.models.trainer import ModelTrainer

console = Console()

def _parquet_to_jsonl(parquet_path: Path, jsonl_path: Path) -> None:
    """Read a Parquet file and write each row as a JSON line."""
    table = pq.read_table(parquet_path)
    with jsonl_path.open("w", encoding="utf-8") as out_f:
        for row in table.to_pylist():
            out_f.write(json.dumps(row) + "\n")

def main(
    output: Path = typer.Option(
        Path("models/artefacts"), "--output", "-o", help="Directory for model bundle and metrics"
    ),
    val_fraction: float = typer.Option(0.20, "--val-fraction", help="Hold‑out fraction for validation"),
    seed: int | None = typer.Option(None, "--seed", help="Random seed override (optional)"),
) -> None:
    console.print("[bold cyan]Downloading EMBER parquet dataset…[/bold cyan]")
    dataset_root = kagglehub.dataset_download("dhoogla/ember-2018-v2-features")
    root = Path(dataset_root)

    train_parquet = root / "train_ember_2018_v2_features.parquet"
    test_parquet = root / "test_ember_2018_v2_features.parquet"

    if not train_parquet.is_file() or not test_parquet.is_file():
        console.print(f"[bold red]Error:[/bold red] Parquet files not found in {root}")
        raise typer.Exit(code=1)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        train_jsonl = tmp_path / "train.jsonl"
        test_jsonl = tmp_path / "test.jsonl"

        console.print("[bold cyan]Converting train split…[/bold cyan]")
        _parquet_to_jsonl(train_parquet, train_jsonl)
        console.print("[bold cyan]Converting test split…[/bold cyan]")
        _parquet_to_jsonl(test_parquet, test_jsonl)

        console.print("[bold cyan]Loading dataset…[/bold cyan]")
        cfg = load_config()
        if seed is not None:
            cfg.models.random_seed = seed
        loader = EMBERDataLoader(config=cfg)
        splits = loader.load_from_jsonl(train_jsonl, val_fraction=val_fraction)

        console.print("[bold cyan]Training models…[/bold cyan]")
        trainer = ModelTrainer(config=cfg)
        bundle, report = trainer.train_and_select(splits)

        output.mkdir(parents=True, exist_ok=True)
        bundle_path = output / "model_bundle.joblib"
        metrics_path = output / "metrics.json"
        bundle.save(bundle_path)
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"[bold green]Saved model bundle to:[/bold green] {bundle_path}")
        console.print(f"[bold green]Saved validation metrics to:[/bold green] {metrics_path}")

if __name__ == "__main__":
    typer.run(main)
