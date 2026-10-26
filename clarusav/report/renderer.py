"""Report generators: Rich terminal entropy heatmap, drift monitor, and self-contained HTML export."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from rich import box
from rich.table import Table


@dataclass
class SectionEntropyInfo:
    name: str
    size: int
    entropy: float

    @property
    def bar(self) -> str:
        """Colored text bar representing entropy in [0.0, 8.0]."""
        filled = max(0, min(10, int(round((self.entropy / 8.0) * 10))))
        empty = 10 - filled
        if self.entropy >= 6.8:
            return f"[bold bright_red]{'█' * filled}[/bold bright_red][dim]{'░' * empty}[/dim]"
        elif self.entropy >= 5.5:
            return f"[bold bright_yellow]{'█' * filled}[/bold bright_yellow][dim]{'░' * empty}[/dim]"
        else:
            return f"[bold bright_green]{'█' * filled}[/bold bright_green][dim]{'░' * empty}[/dim]"

    @property
    def style(self) -> str:
        if self.entropy >= 6.8:
            return "bold bright_red"
        elif self.entropy >= 5.5:
            return "bold bright_yellow"
        else:
            return "bold bright_green"


class EntropyHeatmap:
    """Renders per-section entropy bars in terminal (Rich) and in HTML."""

    @staticmethod
    def render_terminal(sections: list[SectionEntropyInfo]) -> Table:
        table = Table(
            title="PE Section Entropy Heatmap (Theoretical Max: 8.0 bits)",
            show_header=True,
            header_style="bold bright_cyan",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
        table.add_column("Section", style="bold bright_cyan", min_width=12, no_wrap=True)
        table.add_column("Raw Size", justify="right", style="cyan", min_width=12)
        table.add_column("Entropy (bits)", justify="right", min_width=14)
        table.add_column("Distribution Bar", style="bold", justify="center", min_width=16)
        table.add_column("Packing Assessment", min_width=28)

        for sec in sections:
            # Clean section name of null characters and whitespace
            clean_name = sec.name.split("\x00", 1)[0].strip() or "<unnamed>"

            if sec.entropy >= 6.8:
                assessment = "[bold white on red] 🚨 CRITICAL: PACKED / ENCRYPTED [/bold white on red]"
            elif sec.entropy >= 5.5:
                assessment = "[bold black on yellow] ⚠️ SUSPICIOUS: HIGH DENSITY [/bold black on yellow]"
            elif sec.entropy <= 1.0:
                assessment = "[bold cyan] ℹ️ SPARSE / UNMAPPED [/bold cyan]"
            else:
                assessment = "[bold white on green]  ✓ NORMAL CODE/DATA [/bold white on green]"

            table.add_row(
                clean_name,
                f"{sec.size:,} B",
                f"[{sec.style}]{sec.entropy:.3f}[/{sec.style}]",
                sec.bar,
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
        quarantined = scan_result.get("quarantined", False)

        verdict = scan_result.get("verdict", "UNRESOLVED")
        badge_color = (
            "#ef4444"
            if verdict == "MALICIOUS"
            else ("#10b981" if verdict == "BENIGN" else "#f59e0b")
        )

        quarantine_badge = ""
        if quarantined:
            quarantine_badge = '<span style="background:#dc2626;color:#ffffff;padding:4px 10px;border-radius:6px;font-size:0.8rem;margin-left:12px;font-weight:bold;">🔒 QUARANTINED</span>'

        section_rows = ""
        has_critical_entropy = False
        for s in sections:
            clean_name = s.get("name", "N/A").split("\x00", 1)[0].strip() or "<unnamed>"
            ent = s.get("entropy", 0.0)
            pct = min(100, int((ent / 8.0) * 100))
            if ent >= 6.8:
                has_critical_entropy = True
                color = "#ef4444"
                pack_badge = '<span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;">🚨 CRITICAL: PACKED / ENCRYPTED</span>'
            elif ent >= 5.5:
                color = "#f59e0b"
                pack_badge = '<span style="background:#d97706;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;">⚠️ ELEVATED: HIGH DENSITY</span>'
            else:
                color = "#10b981"
                pack_badge = '<span style="background:#059669;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;">✓ NORMAL CODE/DATA</span>'

            section_rows += f"""
            <tr>
              <td><code>{clean_name}</code></td>
              <td>{s.get("size", 0):,} B</td>
              <td><b>{ent:.3f}</b> bits</td>
              <td>
                <div style="background:#334155;border-radius:6px;overflow:hidden;height:12px;width:140px;">
                  <div style="background:{color};width:{pct}%;height:100%;"></div>
                </div>
              </td>
              <td>{pack_badge}</td>
            </tr>
            """

        entropy_alert_html = ""
        if has_critical_entropy:
            entropy_alert_html = """
            <div style="background:rgba(239,68,68,0.15);border:1px solid #ef4444;border-radius:8px;padding:12px;margin-bottom:14px;color:#fca5a5;">
              <b>🚨 CRITICAL ENTROPY ALERT:</b> Section entropy above 6.8 bits indicates cryptographic encryption (ransomware) or runtime binary packing (UPX, VMProtect).
            </div>
            """

        narrative_rows = ""
        for n in narratives:
            n_lower = n.lower()
            if any(w in n_lower for w in ["high entropy", "packed code", "cryptographic encryption", "malicious behavior", "watchlist (process"]):
                badge = '<span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;margin-right:8px;">🚨 CRITICAL</span>'
            elif any(w in n_lower for w in ["zero high-risk", "low section entropy", "clean telemetry", "within standard", "standard historical epoch"]):
                badge = '<span style="background:#059669;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;margin-right:8px;">ℹ️ BENIGN</span>'
            elif any(w in n_lower for w in ["anomalous", "sparse import", "unresolved", "manual review", "raised"]):
                badge = '<span style="background:#d97706;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;margin-right:8px;">⚠️ WARNING</span>'
            else:
                badge = '<span style="background:#0284c7;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;margin-right:8px;">ℹ️ INFO</span>'
            narrative_rows += f'<li style="margin-bottom:8px;list-style:none;">{badge} {n}</li>'

        shap_rows = ""
        for f in top_features:
            shap = f.get("shap_value", 0.0)
            if shap >= 0.15:
                s_badge = '<span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;">🚨 CRITICAL</span>'
                shift = '<span style="color:#ef4444;font-weight:bold;">▲ Pushes MALICIOUS</span>'
            elif shap >= 0.05:
                s_badge = '<span style="background:#ea580c;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;">⚠️ HIGH RISK</span>'
                shift = '<span style="color:#ef4444;font-weight:bold;">▲ Pushes MALICIOUS</span>'
            elif shap > 0.0:
                s_badge = '<span style="background:#d97706;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;">⚡ ELEVATED</span>'
                shift = '<span style="color:#f59e0b;font-weight:bold;">▲ Pushes MALICIOUS</span>'
            elif shap == 0.0:
                s_badge = '<span style="background:#475569;color:#cbd5e1;padding:2px 8px;border-radius:4px;font-size:0.75rem;">— NEUTRAL</span>'
                shift = '<span style="color:#94a3b8;">Neutral</span>'
            else:
                s_badge = '<span style="background:#059669;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;">✓ BENIGN</span>'
                shift = '<span style="color:#10b981;font-weight:bold;">▼ Pushes BENIGN</span>'

            shap_rows += f"""
            <tr>
              <td>{s_badge}</td>
              <td><b>{f.get('name')}</b></td>
              <td>{f.get('value')}</td>
              <td><code>{shap:+.4f} {f.get('units')}</code></td>
              <td>{shift}</td>
            </tr>
            """

        cf_html = ""
        if counterfactual:
            cf_html = f"""
            <div class="card" style="border-left:4px solid #3b82f6;">
              <h3 style="margin-top:0;color:#60a5fa;">💡 Counterfactual Decision Boundary Hint</h3>
              <p>{counterfactual.get("message")}</p>
              <small style="color:#94a3b8;"><em>{counterfactual.get("disclaimer")}</em></small>
            </div>
            """

        score_val = scan_result.get("score", 0.0)
        score_pct = int(round(score_val * 100))

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ClarusAV Security Report - {scan_result.get("file_name", "Binary")}</title>
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
      padding: 8px 18px;
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
        <h1 style="margin:0 0 6px 0;">🛡️ ClarusAV Security Report</h1>
        <div style="color:#94a3b8;font-size:0.9rem;">Target: <code>{scan_result.get("file_path", "unknown")}</code> | SHA-256: <code>{scan_result.get("sha256", "unknown")}</code></div>
      </div>
      <div style="display:flex;align-items:center;">
        <div class="badge">{verdict}</div>
        {quarantine_badge}
      </div>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#38bdf8;">Verdict Summary & Confidence Gating</h3>
      <p><b>Calibrated Score:</b> <span style="font-size:1.15rem;color:{badge_color};font-weight:bold;">{score_val:.4f}</span> ({score_pct}%) | <b>Band Position:</b> {scan_result.get("band_position", "N/A")} | <b>Deciding Stage:</b> {scan_result.get("deciding_stage", "N/A")}</p>
      <div style="background:#334155;border-radius:6px;overflow:hidden;height:14px;width:100%;margin-bottom:12px;">
        <div style="background:{badge_color};width:{score_pct}%;height:100%;"></div>
      </div>
      <p style="margin:0;font-size:0.85rem;color:#94a3b8;"><b>Gate Thresholds:</b> &tau;<sub>low</sub> = {scan_result.get("tau_low", 0.15):.2f} (Benign) │ &tau;<sub>high</sub> = {scan_result.get("tau_high", 0.85):.2f} (Malicious)</p>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#a855f7;">PE Section Entropy Heatmap</h3>
      {entropy_alert_html}
      <table>
        <thead>
          <tr><th>Section</th><th>Raw Size</th><th>Entropy</th><th>Distribution Bar</th><th>Packing Assessment</th></tr>
        </thead>
        <tbody>
          {section_rows}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#f97316;">🧠 TreeSHAP Feature Attribution & Threat Drivers</h3>
      <table>
        <thead>
          <tr><th>Alert</th><th>Feature</th><th>Observed</th><th>SHAP Impact</th><th>Threat Direction</th></tr>
        </thead>
        <tbody>
          {shap_rows}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin-top:0;color:#22c55e;">📋 Plain-English Narrative Explanations</h3>
      <ul style="padding-left:0;margin:0;">
        {narrative_rows}
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
