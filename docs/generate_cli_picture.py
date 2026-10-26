"""
Generate high-resolution picture of the ClarusAV CLI (SVG & PNG).
Captures the startup banner, interactive shell prompt, and live scan triage.
"""
import os
import io
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table

from clarusav.ui.banner import (
    _render_init_lines, _render_shield, _render_wordmark, _render_tagline, _render_stats
)
from clarusav.cli.main import app
from typer.testing import CliRunner

DOCS_DIR = Path(__file__).parent.resolve()
SVG_OUT = DOCS_DIR / "clarusav_cli.svg"
PNG_OUT = DOCS_DIR / "clarusav_cli.png"

def get_font(size, bold=False):
    for f_path in [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFNSMono.ttf",
        "/Library/Fonts/Courier New.ttf",
    ]:
        if os.path.exists(f_path):
            try:
                return ImageFont.truetype(f_path, size, index=1 if (bold and "ttc" in f_path) else 0)
            except Exception:
                continue
    return ImageFont.load_default()

def generate_svg():
    """Generate authentic Rich vector SVG terminal capture."""
    rec_console = Console(record=True, width=105, highlight=False)
    
    # Terminal initial prompt
    rec_console.print(Text("devakrishna@MacBook-Pro:~/final $ clarusav", style="bold green"))
    rec_console.print()
    
    # Startup banner
    _render_init_lines(rec_console)
    rec_console.print()
    _render_shield(rec_console)
    _render_wordmark(rec_console)
    _render_tagline(rec_console)
    _render_stats(rec_console)
    rec_console.print()
    
    # User runs scan command in interactive shell
    prompt_line = Text()
    prompt_line.append("clarus > ", style="bold bright_blue")
    prompt_line.append("scan samples/malware_ransom.exe", style="bold white")
    rec_console.print(prompt_line)
    rec_console.print()
    
    # Run the actual scan command using Typer runner
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "samples/malware_ransom.exe"])
    rec_console.print(result.stdout)
    
    # End prompt
    end_prompt = Text()
    end_prompt.append("clarus > ", style="bold bright_blue")
    end_prompt.append("█", style="bold cyan")
    rec_console.print(end_prompt)
    
    svg = rec_console.export_svg(title="ClarusAV CLI Terminal — Live Threat Triage")
    with open(SVG_OUT, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"✅ Generated SVG: {SVG_OUT}")

def generate_png():
    """Generate high-resolution PNG image mimicking macOS terminal window."""
    w, h = 1600, 1550
    im = Image.new("RGBA", (w, h), (15, 23, 42, 255))  # Deep Slate-900 background
    draw = ImageDraw.Draw(im)

    # 1. Window Header / Titlebar
    draw.rectangle([(0, 0), (w, 54)], fill=(30, 41, 59, 255))
    draw.line([(0, 54), (w, 54)], fill=(51, 65, 85, 255), width=1)

    # Traffic light buttons (Close, Minimize, Expand)
    draw.ellipse([(20, 20), (34, 34)], fill=(239, 68, 68, 255))
    draw.ellipse([(44, 20), (58, 34)], fill=(245, 158, 11, 255))
    draw.ellipse([(68, 20), (82, 34)], fill=(34, 197, 94, 255))

    f_title = get_font(15, bold=True)
    draw.text((115, 18), "devakrishna@MacBook-Pro: ~/final — clarusav (zsh) — 110x55", font=f_title, fill=(148, 163, 184, 255))

    f_mono = get_font(14, bold=False)
    f_mono_b = get_font(14, bold=True)
    f_shield = get_font(10, bold=True)

    y = 75
    left_m = 40

    # Shell prompt
    draw.text((left_m, y), "devakrishna@MacBook-Pro:~/final $ ", font=f_mono_b, fill=(74, 222, 128, 255))
    draw.text((left_m + 325, y), "clarusav", font=f_mono_b, fill=(255, 255, 255, 255))
    y += 28

    # Init status lines
    inits = [
        ("[*] Loading model bundle", ".........", "rf+xgb v0.1.0"),
        ("[*] Verifying schema hash", "........", "ok"),
        ("[*] Checking sandbox backend", ".....", "docker ready"),
        ("[*] Opening audit log", "............", "chain ok"),
    ]
    for prefix, dots, stat in inits:
        draw.text((left_m, y), prefix, font=f_mono_b, fill=(56, 189, 248, 255))
        draw.text((left_m + 250, y), dots, font=f_mono, fill=(100, 116, 139, 255))
        draw.text((left_m + 340, y), stat, font=f_mono_b, fill=(74, 222, 128, 255))
        y += 20

    y += 10

    # ASCII Shield lines
    shield_lines = [
        "                        .#.",
        "                    .#########.",
        "                ...#########`....`#######...",
        "           ##########`....##########....`##########",
        "           ##/.....#######################.....\\##",
        "           ##|####################################|##",
        "           ##|#######.....############.....#######|##",
        "           ##|#####/###//  ..#####.  \\\\..#########|##",
        "           ##|######  //  ###   ###  \\\\   ######|##",
        "           ##|####.   ||  ###   ###  /|    .####|##",
        "           ##|.####.. ||\\. #######  ./|  ..####  |##",
        "            ##  ####.##.\\\\....\"\"....//..####### |#",
        "            ##| ########.###....######\\.#####  |##",
        "             ##\\#####/////#/.......#.\\##\\.###/##",
        "              ##\\##################..\\##\\.#./##",
        "               ##\\##################..\\#/./##",
        "                ##\\..#################### /#",
        "                 ##....################..##",
        "                  ##/...###########/../#",
        "                   ##/....###/..../##",
        "                    ##/....##",
        "                      ###",
    ]
    for sl in shield_lines:
        draw.text((left_m + 160, y), sl, font=f_shield, fill=(248, 113, 113, 255))
        y += 13

    y += 10
    # ClarusAV ASCII wordmark & tagline
    wm_lines = [
        "   ___  _                    ___  _   __",
        "  / __|| | __ _  _ _ _  _ __/_\\ \\  / /",
        " | (__ | |/ _` || '_| || (_)___ \\ \\/ / ",
        "  \\___||_|\\__,_||_|  \\_,_|_|___/ /_/  ",
    ]
    for wml in wm_lines:
        draw.text((left_m + 190, y), wml, font=f_shield, fill=(56, 189, 248, 255))
        y += 13

    draw.text((left_m + 230, y), "Clarus", font=f_mono_b, fill=(56, 189, 248, 255))
    draw.text((left_m + 288, y), "AV", font=f_mono_b, fill=(96, 165, 250, 255))
    y += 18
    draw.text((left_m + 140, y), "Clarity in every scan. Confidence in every decision.", font=f_mono, fill=(148, 163, 184, 255))
    y += 24

    stats = [
        "+ -- =[ ClarusAV v0.1.0",
        "   -- =[ 2 engines (rf + xgb)  ·  1 model bundle",
        "   -- =[ sandbox: docker | audit log: enabled",
        "   -- =[ https://github.com/your-org/clarusav",
    ]
    for st in stats:
        draw.text((left_m, y), st, font=f_mono_b, fill=(74, 222, 128, 255))
        y += 18

    y += 16
    draw.line([(left_m, y), (w - left_m, y)], fill=(51, 65, 85, 255), width=1)
    y += 16

    # Clarus interactive prompt & command
    draw.text((left_m, y), "clarus > ", font=f_mono_b, fill=(96, 165, 250, 255))
    draw.text((left_m + 95, y), "scan samples/malware_ransom.exe", font=f_mono_b, fill=(255, 255, 255, 255))
    y += 30

    # Scan Output: Threat Banner
    draw.rounded_rectangle([left_m, y, w - left_m, y + 80], radius=6, fill=(69, 10, 10, 255), outline=(220, 38, 38, 255), width=2)
    draw.text((left_m + 20, y + 12), "[ 🚨 MALICIOUS THREAT DETECTED ]", font=f_mono_b, fill=(248, 113, 113, 255))
    draw.text((left_m + 650, y + 12), "Target: samples/malware_ransom.exe", font=f_mono, fill=(255, 255, 255, 255))
    draw.text((left_m + 20, y + 36), "Calibrated Confidence Score: 0.9710 (97.10%)", font=f_mono_b, fill=(252, 165, 165, 255))
    draw.text((left_m + 650, y + 36), "Deciding Stage: static_gate", font=f_mono, fill=(203, 213, 225, 255))
    draw.text((left_m + 20, y + 56), "Threat Band: MALICIOUS_BAND", font=f_mono, fill=(248, 113, 113, 255))
    draw.text((left_m + 650, y + 56), "SHA-256: 8d3f87717d819d637d9fce3ae997f198114... (Vault Logged)", font=f_mono, fill=(148, 163, 184, 255))
    y += 98

    # Section Entropy Header & Table
    draw.text((left_m, y), "📊 PE SECTION ENTROPY DISTRIBUTION & PACKING ASSESSMENT", font=f_mono_b, fill=(56, 189, 248, 255))
    y += 22
    tbl1 = [
        "+---------+----------+----------------+--------------------+--------------------------------------+",
        "| Section | Raw Size | Entropy (bits) | Distribution Bar   | Packing Assessment                   |",
        "+---------+----------+----------------+--------------------+--------------------------------------+",
        "| .text   |  1,024 B |          0.958 | [##........]        | NORMAL CODE / UNPACKED DATA          |",
        "| .data   | 33,524 B |          7.942 | [##########]       | SUSPICIOUS — Likely Packed/Encrypted |",
        "+---------+----------+----------------+--------------------+--------------------------------------+",
    ]
    for row in tbl1:
        color = (253, 164, 175, 255) if "SUSPICIOUS" in row else (203, 213, 225, 255)
        draw.text((left_m, y), row, font=f_mono, fill=color)
        y += 18

    y += 14
    # TreeSHAP Header & Table
    draw.text((left_m, y), "🌳 TREESHAP FEATURE ATTRIBUTION (XGBoost – Margin Log-Odds)", font=f_mono_b, fill=(192, 132, 252, 255))
    y += 22
    tbl2 = [
        "+----------+--------------------------+---------------+----------+----------------------------+",
        "| Alert    | Feature / Metric         |      Observed | SHAP Δp  | Security Finding           |",
        "+----------+--------------------------+---------------+----------+----------------------------+",
        "| CRITICAL | Binary File Size         |  66,024 bytes |  +3.2251 | Drives malicious score     |",
        "| NEUTRAL  | PE Section Count         |    2 sections |  +0.0000 | Standard header structure  |",
        "| NEUTRAL  | Max Section Entropy      |    7.994 bits |  +0.0000 | High byte entropy packing  |",
        "| NEUTRAL  | Total API Imports        |   0 functions |  +0.0000 | Sparse dynamic resolution  |",
        "| NEUTRAL  | Watchlist Security APIs  |        0 APIs |  +0.0000 | Zero injection APIs        |",
        "| NEUTRAL  | Compile Timestamp        |   Valid (0.0) |  +0.0000 | Normal historical epoch    |",
        "+----------+--------------------------+---------------+----------+----------------------------+",
    ]
    for row in tbl2:
        color = (248, 113, 113, 255) if "CRITICAL" in row else (203, 213, 225, 255)
        draw.text((left_m, y), row, font=f_mono, fill=color)
        y += 18

    draw.text((left_m, y), "[ 🚨 SHAP THREAT ALERT ] Key attribute driving conviction: Binary File Size (+3.225)", font=f_mono_b, fill=(248, 113, 113, 255))
    y += 28

    # Narrative Cards
    draw.text((left_m, y), "📋 PLAIN-ENGLISH NARRATIVE EXPLANATION CARDS (Deterministic Automata)", font=f_mono_b, fill=(251, 191, 36, 255))
    y += 22
    tbl3 = [
        "+-------------+---------------------------------------------------------------------------------+",
        "| Severity    | Security Finding & Narrative Context                                            |",
        "+-------------+---------------------------------------------------------------------------------+",
        "| ⚠ WARNING   | Binary file size of 66,024 bytes raised the malicious threat score.             |",
        "| 🚨 CRITICAL | High entropy (7.99 bits) across sections indicates packed code/payload.        |",
        "| ⚠ WARNING   | Sparse import table (0 functions) suggests dynamic API runtime resolution.      |",
        "| ℹ BENIGN    | Compile timestamp falls within standard historical epoch range.                 |",
        "+-------------+---------------------------------------------------------------------------------+",
    ]
    for row in tbl3:
        color = (252, 165, 165, 255) if "CRITICAL" in row else ((253, 224, 71, 255) if "WARNING" in row else (203, 213, 225, 255))
        draw.text((left_m, y), row, font=f_mono, fill=color)
        y += 18

    y += 14
    # Counterfactual Box
    draw.rounded_rectangle([left_m, y, w - left_m, y + 65], radius=6, fill=(30, 41, 59, 255), outline=(56, 189, 248, 255), width=1)
    draw.text((left_m + 20, y + 10), "💡 SHAP COUNTERFACTUAL DECISION BOUNDARY SIMULATION", font=f_mono_b, fill=(56, 189, 248, 255))
    draw.text((left_m + 20, y + 32), "Pivotal Feature : file_size      | Observed: 66,024 bytes | Target Boundary: 6,602.4 bytes", font=f_mono, fill=(226, 232, 240, 255))
    draw.text((left_m + 20, y + 48), "Target Band     : UNCERTAIN_BAND | Finding: Verdict shifts to UNCERTAIN if size drops to 6,602.4 B.", font=f_mono, fill=(148, 163, 184, 255))
    y += 82

    # Closing prompt
    draw.text((left_m, y), "clarus > ", font=f_mono_b, fill=(96, 165, 250, 255))
    draw.text((left_m + 95, y), "█", font=f_mono_b, fill=(56, 189, 248, 255))

    im.save(PNG_OUT, dpi=(200, 200))
    print(f"✅ Generated PNG: {PNG_OUT}")

if __name__ == "__main__":
    generate_svg()
    generate_png()
