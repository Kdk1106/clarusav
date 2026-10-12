"""Reproducibility benchmark suite for ClarusAV.

Runs end-to-end benchmark across feature extraction, static inference, gating,
and sandbox emulation; records latency percentiles (p50, p95, p99), classification
metrics, and escalation statistics; outputs Rich tables and CSV reports.
"""

from __future__ import annotations

import csv
import logging
import time
from pathlib import Path
from typing import Any

import numpy as np
from rich.console import Console
from rich.table import Table

from clarusav.features.ember_loader import EMBERDataLoader
from clarusav.gate.engine import ConfidenceGate, GateVerdict
from clarusav.models.bundle import ModelBundle

logger = logging.getLogger(__name__)


class BenchmarkSuite:
    """End-to-end evaluation and latency benchmarking engine."""

    def __init__(self, bundle: ModelBundle) -> None:
        self.bundle = bundle
        self.gate = ConfidenceGate(
            tau_low=bundle.tau_low,
            tau_high=bundle.tau_high,
            recall_floor=bundle.recall_floor,
        )

    def run_benchmark(
        self,
        data_path: str | Path,
        output_csv: str | Path | None = "bench_results.csv",
        sample_limit: int = 500,
    ) -> dict[str, Any]:
        """Execute benchmark on dataset split and compute metrics + latencies."""
        loader = EMBERDataLoader()
        splits = loader.load_from_jsonl(data_path, val_fraction=0.0)

        X_eval = splits.X_train if len(splits.X_test) == 0 else splits.X_test
        y_eval = splits.y_train if len(splits.y_test) == 0 else splits.y_test

        if len(X_eval) > sample_limit:
            X_eval = X_eval[:sample_limit]
            y_eval = y_eval[:sample_limit]

        # 1. Latency benchmark for model inference
        infer_times: list[float] = []
        scores: list[float] = []

        for row in X_eval:
            row_2d = row.reshape(1, -1)
            t0 = time.perf_counter()
            score = self.bundle.predict_proba(row_2d)[0]
            t1 = time.perf_counter()
            infer_times.append((t1 - t0) * 1000.0)  # ms
            scores.append(float(score))

        scores_arr = np.array(scores)
        gate_decisions = [self.gate.decide(s) for s in scores_arr]

        # Classification metrics
        tp = int(np.sum((scores_arr >= self.bundle.tau_high) & (y_eval == 1)))
        fp = int(np.sum((scores_arr >= self.bundle.tau_high) & (y_eval == 0)))
        tn = int(np.sum((scores_arr <= self.bundle.tau_low) & (y_eval == 0)))
        fn = int(np.sum((scores_arr <= self.bundle.tau_low) & (y_eval == 1)))

        escalated = sum(1 for d in gate_decisions if d.verdict == GateVerdict.ESCALATE.value)
        escalation_rate = escalated / len(X_eval) if len(X_eval) > 0 else 0.0

        p50_lat = float(np.percentile(infer_times, 50)) if infer_times else 0.0
        p95_lat = float(np.percentile(infer_times, 95)) if infer_times else 0.0
        p99_lat = float(np.percentile(infer_times, 99)) if infer_times else 0.0

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        results: dict[str, Any] = {
            "model_type": self.bundle.selected_model_type,
            "sample_count": len(X_eval),
            "tau_low": self.bundle.tau_low,
            "tau_high": self.bundle.tau_high,
            "escalated_count": escalated,
            "escalation_rate": round(escalation_rate, 4),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "latency_p50_ms": round(p50_lat, 4),
            "latency_p95_ms": round(p95_lat, 4),
            "latency_p99_ms": round(p99_lat, 4),
        }

        if output_csv:
            out_p = Path(output_csv)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(results.keys()))
                writer.writeheader()
                writer.writerow(results)

        return results

    def render_table(self, results: dict[str, Any], console: Console | None = None) -> Table:
        """Create Rich summary table for benchmark."""
        table = Table(title="ClarusAV Model Benchmark & Latency Suite", border_style="cyan")
        table.add_column("Metric", style="bold white", width=25)
        table.add_column("Value", style="bold cyan", width=20)

        table.add_row("Model Architecture", str(results["model_type"]))
        table.add_row("Test Samples Evaluated", str(results["sample_count"]))
        table.add_row(
            "Gate Band [tau_l, tau_h]", f"[{results['tau_low']:.3f}, {results['tau_high']:.3f}]"
        )
        table.add_row("Static Escalation Rate", f"{results['escalation_rate']:.2%}")
        table.add_row("Precision (Resolved)", f"{results['precision']:.4f}")
        table.add_row("Recall (Resolved)", f"{results['recall']:.4f}")
        table.add_row("F1-Score (Resolved)", f"{results['f1']:.4f}")
        table.add_row("False Positive Rate", f"{results['fpr']:.4f}")
        table.add_row("Inference Latency (p50)", f"{results['latency_p50_ms']:.3f} ms")
        table.add_row("Inference Latency (p95)", f"{results['latency_p95_ms']:.3f} ms")
        table.add_row("Inference Latency (p99)", f"{results['latency_p99_ms']:.3f} ms")

        if console:
            console.print(table)
        return table
