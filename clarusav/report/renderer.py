"""Report generators: Rich terminal entropy heatmap, drift monitor, and self-contained HTML export."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from rich.table import Table


@dataclass
class SectionEntropyInfo:
    name: str
    size: int
    entropy: float

    @property
    def bar(self) -> str:
        """Colored text bar representing entropy in [0.0, 8.0]."""
        filled = int(round((self.entropy / 8.0) * 10))
        empty = 10 - filled
        return "█" * filled + "░" * empty

    @property
    def style(self) -> str:
        if self.entropy >= 6.8:
            return "bold red"
        elif self.entropy >= 5.5:
            return "yellow"
        else:
            return "green"


class EntropyHeatmap:
    """Renders per-section entropy bars in terminal (Rich) and in HTML."""

    @staticmethod
    def render_terminal(sections: list[SectionEntropyInfo]) -> Table:
        table = Table(
            title="PE Section Entropy Heatmap (Theoretical Max: 8.0 bits)",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Section", style="bold")
        table.add_column("Raw Size", justify="right")
        table.add_column("Entropy (bits)", justify="right")
        table.add_column("Distribution Bar", style="bold")
        table.add_column("Packing Assessment")

        for sec in sections:
            assessment = (
                "[red]SUSPICIOUS (Likely Packed/Encrypted)[/red]"
                if sec.entropy >= 6.8
                else (
                    "[yellow]MODERATE[/yellow]"
                    if sec.entropy >= 5.5
                    else "[green]NORMAL CODE/DATA[/green]"
                )
            )
            table.add_row(
                sec.name,
                f"{sec.size:,} B",
                f"[{sec.style}]{sec.entropy:.3f}[/{sec.style}]",
                f"[{sec.style}]{sec.bar}[/{sec.style}]",
                assessment,
            )
        return table


class DriftMonitor:
    """Tracks score distribution across scans and flags distributional shift from training."""

    def __init__(self, baseline_mean: float = 0.50, baseline_std: float = 0.35) -> None:
        self.baseline_mean = baseline_mean
        self.baseline_std = baseline_std
        self.observed_scores: list[float] = []

    def record_score(self, score: float) -> None:
        self.observed_scores.append(float(score))

    def evaluate_drift(self, min_samples: int = 10) -> tuple[bool, str, dict[str, float]]:
        """Compute drift statistics using population mean shift test."""
        if len(self.observed_scores) < min_samples:
            return (
                False,
                f"Insufficient observations for drift test ({len(self.observed_scores)}/{min_samples})",
                {},
            )

        arr = np.array(self.observed_scores, dtype=np.float64)
        curr_mean = float(np.mean(arr))
        curr_std = float(np.std(arr)) if len(arr) > 1 else 0.0

        shift = abs(curr_mean - self.baseline_mean)
        is_drift = shift > 0.30

        stats = {
            "baseline_mean": round(self.baseline_mean, 4),
            "observed_mean": round(curr_mean, 4),
            "observed_std": round(curr_std, 4),
            "mean_shift": round(shift, 4),
            "observed_samples": len(self.observed_scores),
        }

        if is_drift:
            msg = f"DRIFT DETECTED: Observed scan score mean ({curr_mean:.3f}) shifted significantly from baseline ({self.baseline_mean:.3f}). Model retraining advised."
        else:
            msg = f"No significant drift detected (mean shift: {shift:.3f} within tolerance)."

        return is_drift, msg, stats


class HTMLReportGenerator:
    """Generates self-contained, modern dark-themed HTML scan reports with CSS glassmorphism."""

    @staticmethod
    def generate(
        scan_result: dict[str, Any],
        output_path: Path | str,
    ) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        sections = scan_result.get("sections", [])
        narratives = scan_result.get("narratives", [])
        counterfactual = scan_result.get("counterfactual")
        top_features = scan_result.get("top_features", [])

        verdict = scan_result.get("verdict", "UNRESOLVED")
        badge_color = (
            "#ef4444"
            if verdict == "MALICIOUS"
            else ("#10b981" if verdict == "BENIGN" else "#f59e0b")
        )

        section_rows = ""
        for s in sections:
            ent = s.get("entropy", 0.0)
            pct = min(100, int((ent / 8.0) * 100))
            color = "#ef4444" if ent >= 6.8 else ("#f59e0b" if ent >= 5.5 else "#10b981")
            section_rows += f"""
            <tr>
              <td><code>{s.get("name", "N/A")}</code></td>
              <td>{s.get("size", 0):,} B</td>
              <td><b>{ent:.3f}</b> bits</td>
              <td>
                <div style="background:#334155;border-radius:6px;overflow:hidden;height:12px;width:160px;">
                  <div style="background:{color};width:{pct}%;height:100%;"></div>
                </div>
              </td>
            </tr>
            """

        narrative_items = "".join(f"<li>{n}</li>" for n in narratives)
        top_shap_items = "".join(
            f"<li><b>{f.get('name')}</b> ({f.get('value')}): {f.get('shap_value'):+.4f} {f.get('units')} ({f.get('direction')})</li>"
            for f in top_features
        )

        cf_html = ""
        if counterfactual:
            cf_html = f"""
            <div class="card" style="border-left:4px solid #3b82f6;">
              <h3 style="margin-top:0;color:#60a5fa;">Counterfactual Decision Hint</h3>
              <p>{counterfactual.get("message")}</p>
              <small style="color:#94a3b8;"><em>{counterfactual.get("disclaimer")}</em></small>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ClarusAV Scan Report - {scan_result.get("file_name", "Binary")}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      margin: 0;
      padding: 30px;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid #334155;
    }}
    .badge {{
      background: {badge_color};
      color: #ffffff;
      padding: 8px 16px;
      border-radius: 9999px;
      font-weight: bold;
      font-size: 1.1rem;
      letter-spacing: 0.05em;
    }}
    .card {{
      background: rgba(30, 41, 59, 0.7);
      backdrop-filter: blur(10px);
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 20px;
      margin-top: 20px;
    }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #1e293b; }}
    th {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin:0 0 6px 0;">ClarusAV Security Report</h1>
        <div style="color:#94a3b8;font-size:0.9rem;">Target: <code>{scan_result.get("file_path", "unknown")}</code> | SHA-256: <code>{scan_result.get("sha256", "unknown")}</code></div>
      </div>
      <div class="badge">{verdict}</div>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#38bdf8;">Verdict Summary & Confidence Gating</h3>
      <p><b>Calibrated Score:</b> {scan_result.get("score", 0.0):.4f} | <b>Band Position:</b> {scan_result.get("band_position", "N/A")} | <b>Deciding Stage:</b> {scan_result.get("deciding_stage", "N/A")}</p>
      <p><b>Model Version:</b> {scan_result.get("model_version", "0.1.0")} | <b>Gate Thresholds:</b> &tau;<sub>low</sub> = {scan_result.get("tau_low", 0.15):.2f}, &tau;<sub>high</sub> = {scan_result.get("tau_high", 0.85):.2f}</p>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#a855f7;">Section Entropy Heatmap</h3>
      <table>
        <thead>
          <tr><th>Section</th><th>Size</th><th>Entropy</th><th>Visual Bar</th></tr>
        </thead>
        <tbody>
          {section_rows}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#22c55e;">Plain-English Narrative Explanations</h3>
      <ul style="line-height:1.6;">
        {narrative_items}
      </ul>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#f97316;">Top SHAP Attributions</h3>
      <ul style="line-height:1.6;">
        {top_shap_items}
      </ul>
    </div>

    {cf_html}
  </div>
</body>
</html>
"""
        with open(out, "w", encoding="utf-8") as f:
            f.write(html_content)

        return out
