"""
clarusav/ui/scan_view.py
────────────────────────
High-visibility, colorful Rich UI renderers for ClarusAV scans:
- Executive Verdict Alert Cards
- Calibrated Probability Threat Score Gauges
- PE Section Entropy Heatmap with Packing Alerts
- TreeSHAP Feature Attribution Tables with Risk Alerts & Direction Meters
- Categorized Plain-English Narrative Alert Cards
- Counterfactual Decision Boundary & Remediation Panels
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clarusav.report.renderer import EntropyHeatmap, SectionEntropyInfo

console = Console()

# Human-readable feature metadata, units, and security context
FEATURE_METADATA: dict[str, dict[str, Any]] = {
    "max_section_entropy": {
        "label": "Max Section Entropy",
        "description": "Peak byte randomness across PE sections",
        "format": lambda v: f"{v:.3f} bits",
        "detail": lambda v, s: (
            "Packed code or encrypted shellcode (near theoretical max 8.0 bits)"
            if v >= 6.8
            else ("Uncompressed, plain executable code" if v <= 4.0 else "Normal code/data density")
        ),
    },
    "suspicious_import_count": {
        "label": "Watchlist Security APIs",
        "description": "Imports matching injection/evasion watchlist",
        "format": lambda v: f"{int(v)} APIs",
        "detail": lambda v, s: (
            f"Detected {int(v)} watchlist APIs (process injection / memory hooking)"
            if v > 0
            else "Zero high-risk watchlist APIs detected"
        ),
    },
    "timestamp_anomaly": {
        "label": "Compile Timestamp",
        "description": "PE header compilation time validity",
        "format": lambda v: "Anomalous (1.0)" if v == 1.0 else "Valid (0.0)",
        "detail": lambda v, s: (
            "Manipulated or zeroed compile timestamp (anti-forensics evasion)"
            if v == 1.0
            else "Standard historical epoch compile timestamp"
        ),
    },
    "import_count": {
        "label": "Total API Imports",
        "description": "Count of statically imported functions",
        "format": lambda v: f"{int(v)} functions",
        "detail": lambda v, s: (
            "Sparse import table suggests dynamic API unpacking / runtime resolution"
            if v < 5
            else "Standard Win32 library dependency structure"
        ),
    },
    "section_count": {
        "label": "PE Section Count",
        "description": "Number of defined section headers",
        "format": lambda v: f"{int(v)} sections",
        "detail": lambda v, s: (
            "Anomalous section header count"
            if v > 8 or v < 2
            else "Standard PE structural section count"
        ),
    },
    "file_size": {
        "label": "Binary File Size",
        "description": "Total on-disk executable size",
        "format": lambda v: f"{int(v):,} bytes",
        "detail": lambda v, s: (
            "Unusually compact binary payload"
            if v < 10000
            else "Standard executable size footprint"
        ),
    },
}


def _get_feature_info(name: str) -> dict[str, Any]:
    return FEATURE_METADATA.get(
        name,
        {
            "label": name.replace("_", " ").title(),
            "description": f"Extracted PE feature: {name}",
            "format": lambda v: f"{v:.2f}",
            "detail": lambda v, s: (
                "Pushes model score towards malicious"
                if s > 0
                else "Reduces suspicion towards benign"
            ),
        },
    )


def render_verdict_card(res: dict[str, Any], file_path: Path) -> None:
    """Render high-contrast, executive-level inspection verdict card."""
    verdict = res.get("verdict", "UNRESOLVED")
    score = float(res.get("score", 0.5))
    stage = res.get("stage", "static_gate")
    band_pos = res.get("band_position", "UNCERTAIN_BAND")
    sha256 = res.get("sha256", "N/A")
    quarantined = res.get("quarantined", False)

    # 1. Status header banner and border color
    if verdict == "MALICIOUS":
        border_style = "bright_red"
        badge = "[bold white on red] 🚨 MALICIOUS THREAT DETECTED [/bold white on red]"
        headline = "[bold bright_red]THREAT CONFIRMED: High-confidence malware signature or behavioral match[/bold bright_red]"
        score_color = "bright_red"
    elif verdict == "BENIGN":
        border_style = "bright_green"
        badge = "[bold white on green] 🛡️ CLEAN / BENIGN FILE [/bold white on green]"
        headline = "[bold bright_green]CLEAN: No malicious telemetry, packing, or security violations detected[/bold bright_green]"
        score_color = "bright_green"
    else:
        border_style = "bright_yellow"
        badge = "[bold black on yellow] ⚠️ UNRESOLVED - MANUAL REVIEW [/bold black on yellow]"
        headline = "[bold bright_yellow]UNCERTAIN: Moderate anomaly score; escalation or manual triage advised[/bold bright_yellow]"
        score_color = "bright_yellow"

    # 2. Score gauge meter (24 blocks)
    meter_len = 24
    filled = max(0, min(meter_len, int(round(score * meter_len))))
    empty = meter_len - filled
    gauge_bar = f"[{score_color}]{'█' * filled}[/{score_color}][dim]{'░' * empty}[/dim]"

    # 3. Formatted metadata table
    meta_table = Table.grid(padding=(0, 2))
    meta_table.add_column("Key", style="bold cyan", justify="right", width=18)
    meta_table.add_column("Value", style="white")

    meta_table.add_row("Target Binary:", f"[bold white]{file_path.name}[/bold white] [dim]({file_path})[/dim]")
    meta_table.add_row("SHA-256 Hash:", f"[dim cyan]{sha256}[/dim cyan]")
    meta_table.add_row(
        "Calibrated Risk:",
        f"[{score_color} bold]{score:.4f}[/{score_color} bold] / 1.0000  [{gauge_bar}] [{score_color} bold]{score * 100:.1f}%[/{score_color} bold]",
    )
    meta_table.add_row(
        "Decision Band:",
        f"[yellow bold]{band_pos}[/yellow bold]  [dim](Thresholds: Benign < 0.150 │ Review: 0.150–0.850 │ Malicious ≥ 0.850)[/dim]",
    )
    meta_table.add_row("Detection Stage:", f"[cyan bold]{stage.replace('_', ' ').title()}[/cyan bold]")

    if quarantined:
        meta_table.add_row("Isolation Status:", "[bold white on red] 🔒 QUARANTINED IN SECURE VAULT [/bold white on red]")
    else:
        meta_table.add_row("Isolation Status:", "[dim green]✓ Not Isolated (Sandbox/Read-only mode)[/dim green]")

    card_content = Table.grid(padding=(0, 0))
    card_content.add_column()
    card_content.add_row(f"{badge}  {headline}\n")
    card_content.add_row(meta_table)

    console.print()
    console.print(
        Panel(
            card_content,
            title="[bold white]ClarusAV Inspection Verdict[/bold white]",
            subtitle=f"[{border_style}]Security Confidence Assessment[/{border_style}]",
            border_style=border_style,
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def render_entropy_section(sections: list[dict[str, Any]]) -> None:
    """Render section entropy table with prominent alerts if packing is detected."""
    if not sections:
        return

    sec_objs = [
        SectionEntropyInfo(
            name=s.get("name", "").strip("\x00") or "<unnamed>",
            size=int(s.get("size", 0)),
            entropy=float(s.get("entropy", 0.0)),
        )
        for s in sections
    ]

    # Check for critical entropy alert (entropy >= 6.8)
    critical_secs = [s for s in sec_objs if s.entropy >= 6.8]
    if critical_secs:
        crit_names = ", ".join(f"[bold yellow]{s.name}[/bold yellow] ({s.entropy:.3f} bits)" for s in critical_secs)
        alert_box = (
            f"[bold red]🚨 CRITICAL PACKING ALERT:[/bold red] High Shannon entropy detected in {crit_names}!\n"
            f"[dim]Theoretical limit is 8.0 bits. Entropy above 6.8 indicates cryptographic encryption (ransomware payloads) "
            f"or binary obfuscation (UPX, Themida, VMProtect).[/dim]"
        )
        console.print(
            Panel(
                alert_box,
                border_style="bright_red",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    console.print(EntropyHeatmap.render_terminal(sec_objs))


def render_shap_table(
    top_features: list[dict[str, Any]],
    score: float,
    model_type: str = "xgboost",
) -> None:
    """Render colorful TreeSHAP feature attribution table with severity alert badges."""
    if not top_features:
        return

    table = Table(
        title=f"🧠 TreeSHAP Feature Attribution & Threat Drivers (Calibrated Probability: {score:.4f})",
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_blue",
        box=box.ROUNDED,
    )
    table.add_column("Alert", justify="center", no_wrap=True)
    table.add_column("Feature / Metric", style="bold white", min_width=24)
    table.add_column("Observed", justify="right", style="bright_yellow", min_width=12)
    table.add_column("SHAP Impact", justify="right", min_width=14)
    table.add_column("Threat Shift", justify="center", min_width=18)
    table.add_column("Magnitude Meter", justify="center", min_width=12)
    table.add_column("Analyst Interpretation & Context", style="white")

    critical_drivers: list[str] = []
    benign_drivers: list[str] = []

    for f in top_features:
        raw_name = f.get("name", "unknown")
        val = float(f.get("value", 0.0))
        shap = float(f.get("shap_value", 0.0))
        units = f.get("units", "log-odds")

        info = _get_feature_info(raw_name)
        fmt_val = info["format"](val)
        detail = info["detail"](val, shap)

        # 1. Alert severity badge
        if shap >= 0.15:
            alert_badge = "[bold white on red] 🚨 CRITICAL [/bold white on red]"
            shap_style = "bold bright_red"
            shift = "[bold bright_red]▲ Pushes MALICIOUS[/bold bright_red]"
            critical_drivers.append(f"[bold red]{info['label']}[/bold red] ({shap:+.3f})")
        elif shap >= 0.05:
            alert_badge = "[bold white on dark_orange] ⚠️ HIGH RISK [/bold white on dark_orange]"
            shap_style = "bold red"
            shift = "[bold red]▲ Pushes MALICIOUS[/bold red]"
            critical_drivers.append(f"[yellow]{info['label']}[/yellow] ({shap:+.3f})")
        elif shap > 0.00:
            alert_badge = "[bold black on yellow] ⚡ ELEVATED [/bold black on yellow]"
            shap_style = "yellow"
            shift = "[yellow]▲ Pushes MALICIOUS[/yellow]"
        elif shap == 0.00:
            alert_badge = "[dim]  NEUTRAL  [/dim]"
            shap_style = "dim"
            shift = "[dim]— Neutral[/dim]"
        else:  # shap < 0
            alert_badge = "[bold white on green]  ✓ BENIGN  [/bold white on green]"
            shap_style = "bold bright_green"
            shift = "[bold bright_green]▼ Pushes BENIGN[/bold bright_green]"
            benign_drivers.append(f"[green]{info['label']}[/green] ({shap:+.3f})")

        # 2. Visual magnitude meter (10 bars)
        mag = min(10, max(1, int(round(abs(shap) * 20))))
        empty = 10 - mag
        if shap > 0:
            meter = f"[bright_red]{'█' * mag}[/bright_red][dim]{'░' * empty}[/dim]"
        elif shap < 0:
            meter = f"[dim]{'░' * empty}[/dim][bright_green]{'█' * mag}[/bright_green]"
        else:
            meter = "[dim]░░░░░░░░░░[/dim]"

        table.add_row(
            alert_badge,
            f"{info['label']}\n[dim]({raw_name})[/dim]",
            fmt_val,
            f"[{shap_style}]{shap:+.4f}[/{shap_style}]\n[dim]{units}[/dim]",
            shift,
            meter,
            detail,
        )

    console.print(table)

    # Summary Threat Takeaway
    if critical_drivers:
        summary_text = (
            f"[bold red]🚨 SHAP THREAT ALERT:[/bold red] Key attributes driving the malicious classification: "
            + ", ".join(critical_drivers)
            + "."
        )
        console.print(Panel(summary_text, border_style="red", box=box.ROUNDED, padding=(0, 1)))
    elif benign_drivers:
        summary_text = (
            f"[bold green]🛡️ SHAP BENIGN CONFIRMATION:[/bold green] Key attributes driving benign confidence: "
            + ", ".join(benign_drivers)
            + "."
        )
        console.print(Panel(summary_text, border_style="green", box=box.ROUNDED, padding=(0, 1)))


def render_narrative_cards(narratives: list[str]) -> None:
    """Render categorized plain-English narrative explanation cards with alert badges."""
    if not narratives:
        return

    n_table = Table(
        title="📋 Plain-English Narrative Explanation Cards & Findings",
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_blue",
        box=box.ROUNDED,
    )
    n_table.add_column("Severity Alert", justify="center", no_wrap=True, width=16)
    n_table.add_column("Security Finding & Narrative Context", style="white")

    for n in narratives:
        n_lower = n.lower()
        if any(w in n_lower for w in ["high entropy", "packed code", "cryptographic encryption", "malicious behavior", "watchlist (process"]):
            badge = "[bold white on red] 🚨 CRITICAL [/bold white on red]"
            content = f"[bold white]{n}[/bold white]"
        elif any(w in n_lower for w in ["zero high-risk", "low section entropy", "clean telemetry", "within standard", "standard historical epoch"]):
            badge = "[bold white on green] ℹ️ BENIGN   [/bold white on green]"
            content = f"[green]{n}[/green]"
        elif any(w in n_lower for w in ["anomalous", "sparse import", "unresolved", "manual review", "raised"]):
            badge = "[bold black on yellow] ⚠️ WARNING  [/bold black on yellow]"
            content = f"[yellow]{n}[/yellow]"
        elif any(w in n_lower for w in ["lowered", "reduced suspicion", "benign"]):
            badge = "[bold white on green] ℹ️ BENIGN   [/bold white on green]"
            content = f"[green]{n}[/green]"
        else:
            badge = "[bold cyan] ℹ️ INFO     [/bold cyan]"
            content = n

        n_table.add_row(badge, content)

    console.print(n_table)


def render_counterfactual_card(cf: dict[str, Any] | None) -> None:
    """Render SHAP counterfactual decision boundary and remediation simulation card."""
    if not cf:
        return

    msg = cf.get("message", "")
    disclaimer = cf.get("disclaimer", "Model decision boundary explanation, not file intent.")
    feat_name = cf.get("feature_name", "N/A")
    orig_val = cf.get("original_value", 0.0)
    cf_val = cf.get("counterfactual_value", 0.0)
    target_band = cf.get("target_band", "UNCERTAIN_BAND")

    sim_box = Table.grid(padding=(0, 2))
    sim_box.add_column(justify="right", style="bold cyan")
    sim_box.add_column(style="white")

    if feat_name != "none":
        sim_box.add_row("Pivotal Feature:", f"[bold yellow]{feat_name}[/bold yellow]")
        sim_box.add_row("Observed Value:", f"[bold red]{orig_val}[/bold red]")
        sim_box.add_row("Target Boundary Value:", f"[bold green]{cf_val}[/bold green]")
        sim_box.add_row("Target Decision Band:", f"[bold cyan]{target_band}[/bold cyan]")
        sim_box.add_row("Simulation Finding:", f"[italic white]{msg}[/italic white]")
    else:
        sim_box.add_row("Simulation Status:", f"[bold green]{msg}[/bold green]")

    content = Table.grid(padding=(0, 0))
    content.add_column()
    content.add_row("[bold black on bright_cyan] 💡 DECISION BOUNDARY SIMULATION [/bold black on bright_cyan]\n")
    content.add_row(sim_box)
    content.add_row(f"\n[dim italic]ℹ️ Disclaimer: {disclaimer}[/dim italic]")

    console.print(
        Panel(
            content,
            title="[bold bright_cyan]💡 SHAP Counterfactual Decision Boundary Hint[/bold bright_cyan]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )
