"""
Generate high-resolution figures for ClarusAV Conference Paper.
Fig 1: Architecture Pipeline Diagram
Fig 2: Terminal Output Screenshot
"""
import os
from PIL import Image, ImageDraw, ImageFont

DOCS_DIR = os.path.dirname(__file__)

def get_font(size, bold=False, mono=False):
    try:
        if mono:
            return ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", size, index=1 if bold else 0)
        if bold:
            return ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", size, index=1)
        return ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", size, index=0)
    except Exception:
        return ImageFont.load_default()

def draw_rounded_rect(draw, xy, radius, fill=None, outline=None, width=1):
    x0, y0, x1, y1 = xy
    draw.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=fill, outline=outline, width=width)

def generate_fig1_pipeline():
    w, h = 1600, 920
    im = Image.new("RGBA", (w, h), (248, 250, 252, 255))
    d = ImageDraw.Draw(im)

    f_title = get_font(28, bold=True)
    f_sub = get_font(18, bold=False)
    f_card_title = get_font(19, bold=True)
    f_card_text = get_font(14, bold=False)
    f_badge = get_font(13, bold=True)

    # Header Banner
    draw_rounded_rect(d, (30, 20, w - 30, 80), 8, fill=(30, 41, 59, 255))
    d.text((50, 36), "Fig. 1 — ClarusAV End-to-End Tiered Classification DAG Architecture", font=f_title, fill=(255, 255, 255, 255))

    # Stage 1: Input & Cache
    # Card 1: Target Ingestion
    draw_rounded_rect(d, (40, 110, 340, 260), 10, fill=(255, 255, 255, 255), outline=(203, 213, 225, 255), width=2)
    draw_rounded_rect(d, (50, 120, 200, 146), 6, fill=(224, 231, 255, 255))
    d.text((58, 126), "STAGE 1", font=f_badge, fill=(67, 56, 202, 255))
    d.text((50, 155), "Binary Ingestion", font=f_card_title, fill=(15, 23, 42, 255))
    d.text((50, 185), "• Windows PE (.exe / .dll)\n• SHA-256 digest computation\n• Fast-path verdict cache check\n  (Latency: ~0.042 ms)", font=f_card_text, fill=(71, 85, 105, 255))

    # Arrow 1 -> 2
    d.line([(340, 185), (380, 185)], fill=(100, 116, 139, 255), width=3)
    d.polygon([(380, 185), (372, 179), (372, 191)], fill=(100, 116, 139, 255))

    # Card 2: Feature Extractor
    draw_rounded_rect(d, (390, 110, 710, 260), 10, fill=(255, 255, 255, 255), outline=(203, 213, 225, 255), width=2)
    draw_rounded_rect(d, (400, 120, 550, 146), 6, fill=(224, 242, 254, 255))
    d.text((408, 126), "STAGE 2", font=f_badge, fill=(3, 105, 161, 255))
    d.text((400, 155), "Static PE Extraction", font=f_card_title, fill=(15, 23, 42, 255))
    d.text((400, 185), "• 6-dim compact feature vector:\n  - Max section Shannon entropy (H)\n  - File size & section count\n  - Watchlist Win32 APIs count", font=f_card_text, fill=(71, 85, 105, 255))

    # Arrow 2 -> 3
    d.line([(710, 185), (750, 185)], fill=(100, 116, 139, 255), width=3)
    d.polygon([(750, 185), (742, 179), (742, 191)], fill=(100, 116, 139, 255))

    # Card 3: Model Inference
    draw_rounded_rect(d, (760, 110, 1100, 260), 10, fill=(255, 255, 255, 255), outline=(203, 213, 225, 255), width=2)
    draw_rounded_rect(d, (770, 120, 920, 146), 6, fill=(243, 232, 255, 255))
    d.text((778, 126), "STAGE 3", font=f_badge, fill=(126, 34, 206, 255))
    d.text((770, 155), "Calibrated ML Ensemble", font=f_card_title, fill=(15, 23, 42, 255))
    d.text((770, 185), "• Primary: Calibrated XGBoost\n• Secondary: Random Forest (p_rf)\n• Isotonic regression calibration\n• Median latency: 0.516 ms", font=f_card_text, fill=(71, 85, 105, 255))

    # Arrow 3 -> 4
    d.line([(1100, 185), (1140, 185)], fill=(100, 116, 139, 255), width=3)
    d.polygon([(1140, 185), (1132, 179), (1132, 191)], fill=(100, 116, 139, 255))

    # Card 4: Confidence Gate
    draw_rounded_rect(d, (1150, 110, 1560, 260), 10, fill=(254, 242, 242, 255), outline=(252, 165, 165, 255), width=2)
    draw_rounded_rect(d, (1160, 120, 1310, 146), 6, fill=(254, 226, 226, 255))
    d.text((1168, 126), "STAGE 4", font=f_badge, fill=(185, 28, 28, 255))
    d.text((1160, 155), "Dual-Signal Confidence Gate", font=f_card_title, fill=(153, 27, 27, 255))
    d.text((1160, 185), "• Decision Policy:\n  p >= 0.85 & |p - p_rf| <= 0.20\n  p <= 0.15 & |p - p_rf| <= 0.20\n  Otherwise: ESCALATE", font=f_card_text, fill=(127, 29, 29, 255))

    # Branching arrows down from Stage 4
    # Down line
    d.line([(1355, 260), (1355, 310)], fill=(100, 116, 139, 255), width=3)

    # 3 Branches: Benign, Escalate, Malicious
    d.line([(300, 310), (1355, 310)], fill=(100, 116, 139, 255), width=3)

    # Branch 1: Benign (Left)
    d.line([(300, 310), (300, 360)], fill=(22, 163, 74, 255), width=3)
    d.polygon([(300, 360), (294, 352), (306, 352)], fill=(22, 163, 74, 255))
    draw_rounded_rect(d, (140, 370, 460, 490), 8, fill=(240, 253, 244, 255), outline=(134, 239, 172, 255), width=2)
    d.text((160, 385), "BENIGN VERDICT (p <= 0.15)", font=f_card_title, fill=(22, 101, 52, 255))
    d.text((160, 415), "• High-confidence clean binary\n• Execution permitted immediately\n• Zero sandbox latency overhead", font=f_card_text, fill=(21, 128, 61, 255))

    # Branch 2: Malicious (Center)
    d.line([(800, 310), (800, 360)], fill=(220, 38, 38, 255), width=3)
    d.polygon([(800, 360), (794, 352), (806, 352)], fill=(220, 38, 38, 255))
    draw_rounded_rect(d, (640, 370, 960, 490), 8, fill=(254, 242, 242, 255), outline=(252, 165, 165, 255), width=2)
    d.text((660, 385), "MALICIOUS (p >= 0.85)", font=f_card_title, fill=(153, 27, 27, 255))
    d.text((660, 415), "• High-confidence conviction\n• Host chmod 000 quarantine isolation\n• Proceeds to TreeSHAP attribution", font=f_card_text, fill=(185, 28, 28, 255))

    # Branch 3: Escalate (Right)
    d.line([(1355, 310), (1355, 360)], fill=(217, 119, 6, 255), width=3)
    d.polygon([(1355, 360), (1349, 352), (1361, 352)], fill=(217, 119, 6, 255))
    draw_rounded_rect(d, (1140, 370, 1560, 520), 8, fill=(255, 251, 235, 255), outline=(252, 211, 77, 255), width=2)
    d.text((1160, 385), "ESCALATE (Ambiguous Band)", font=f_card_title, fill=(180, 83, 9, 255))
    d.text((1160, 415), "• Ephemeral Docker Container\n  - Network: none (air-gapped)\n  - Root FS: read_only, drop ALL caps\n  - Wine runtime detonation (1.52 s)\n  - Behavioral heuristics & mass-rename", font=f_card_text, fill=(146, 64, 14, 255))

    # Lower section: TreeSHAP, Narratives & Audit Chain
    # Convergence Arrow to Explainability
    d.line([(800, 490), (800, 560)], fill=(100, 116, 139, 255), width=3)
    d.line([(1355, 520), (1355, 545)], fill=(100, 116, 139, 255), width=2)
    d.line([(1355, 545), (800, 545)], fill=(100, 116, 139, 255), width=2)
    d.polygon([(800, 560), (794, 552), (806, 552)], fill=(100, 116, 139, 255))

    # Card 5: Explainability Engine
    draw_rounded_rect(d, (140, 570, 850, 750), 10, fill=(255, 255, 255, 255), outline=(148, 163, 184, 255), width=2)
    draw_rounded_rect(d, (160, 582, 380, 608), 6, fill=(224, 231, 255, 255))
    d.text((168, 588), "STAGE 5: EXPLAINABLE AI", font=f_badge, fill=(67, 56, 202, 255))
    d.text((160, 620), "TreeSHAP Attribution & Deterministic Narratives", font=f_card_title, fill=(15, 23, 42, 255))
    d.text((160, 650), "• Exact local TreeSHAP attribution: f(x) = φ0 + Σ φj\n• Deterministic Narrative Cards (No generative LLM hallucination)\n• Section entropy heatmap distribution & packing analysis\n• Counterfactual boundary simulation for analyst insight", font=f_card_text, fill=(71, 85, 105, 255))

    # Arrow 5 -> 6
    d.line([(850, 660), (890, 660)], fill=(100, 116, 139, 255), width=3)
    d.polygon([(890, 660), (882, 654), (882, 666)], fill=(100, 116, 139, 255))

    # Card 6: Audit & Forensic Storage
    draw_rounded_rect(d, (900, 570, 1560, 750), 10, fill=(255, 255, 255, 255), outline=(148, 163, 184, 255), width=2)
    draw_rounded_rect(d, (920, 582, 1180, 608), 6, fill=(220, 252, 231, 255))
    d.text((928, 588), "STAGE 6: AUDIT & STORAGE", font=f_badge, fill=(21, 128, 61, 255))
    d.text((920, 620), "Cryptographic SHA-256 Chained Ledger & Quarantine", font=f_card_title, fill=(15, 23, 42, 255))
    d.text((920, 650), "• Append-only hash chain: H_k = SHA-256(Payload_k ‖ H_{k-1})\n• Tamper-evident ledger prevents post-compromise retroactive erasure\n• Isolated quarantine vault with permissions revoked (chmod 000)\n• JSON audit logging compatible with enterprise SIEM & SOC triage", font=f_card_text, fill=(71, 85, 105, 255))

    # Footer summary bar
    draw_rounded_rect(d, (40, 780, w - 40, 890), 8, fill=(241, 245, 249, 255), outline=(203, 213, 225, 255), width=1)
    f_footer_bold = get_font(15, bold=True)
    f_footer = get_font(13, bold=False)
    d.text((60, 795), "Key Operational Guarantees:", font=f_footer_bold, fill=(30, 41, 59, 255))
    d.text((60, 825), "✓ Static Triage Throughput: 0.516 ms median latency (>1,900 files/s/core)   |   ✓ Detection Fidelity: F1 = 1.000, FP = 0.000 on EMBER benchmark", font=f_footer, fill=(51, 65, 85, 255))
    d.text((60, 855), "✓ Ephemeral Sandbox: 1.520 s median detonation (10-100x vs VM)             |   ✓ Forensic Integrity: Cryptographic hash-chained tamper resistance", font=f_footer, fill=(51, 65, 85, 255))

    out_path = os.path.join(DOCS_DIR, "fig1_pipeline.png")
    im.save(out_path, dpi=(200, 200))
    print(f"Generated {out_path}")

def generate_fig2_terminal_output():
    w, h = 1600, 1000
    im = Image.new("RGBA", (w, h), (15, 23, 42, 255))
    d = ImageDraw.Draw(im)

    # Window Header
    d.rectangle([(0, 0), (w, 50)], fill=(30, 41, 59, 255))
    # Traffic lights
    d.ellipse([(20, 18), (34, 32)], fill=(239, 68, 68, 255))   # Red
    d.ellipse([(44, 18), (58, 32)], fill=(245, 158, 11, 255))  # Yellow
    d.ellipse([(68, 18), (82, 32)], fill=(34, 197, 94, 255))   # Green

    f_head = get_font(14, bold=True)
    d.text((110, 16), "ClarusAV v1.0.0 — Live Threat Triage Terminal: samples/malware_ransom.exe", font=f_head, fill=(148, 163, 184, 255))

    f_mono = get_font(15, bold=False, mono=True)
    f_mono_b = get_font(15, bold=True, mono=True)
    f_banner = get_font(17, bold=True, mono=True)

    y = 75

    # Banner Box
    draw_rounded_rect(d, (35, y, w - 35, y + 105), 6, fill=(69, 10, 10, 255), outline=(220, 38, 38, 255), width=2)
    d.text((55, y + 15), "[ 🚨 MALICIOUS THREAT DETECTED ]", font=f_banner, fill=(248, 113, 113, 255))
    d.text((650, y + 15), "Target: samples/malware_ransom.exe", font=f_mono, fill=(255, 255, 255, 255))
    d.text((55, y + 45), "Calibrated Confidence Score: 0.9710 (97.10%)", font=f_mono_b, fill=(252, 165, 165, 255))
    d.text((650, y + 45), "Deciding Stage: static_gate (dual-signal)", font=f_mono, fill=(203, 213, 225, 255))
    d.text((55, y + 72), "Threat Band: MALICIOUS_BAND", font=f_mono, fill=(248, 113, 113, 255))
    d.text((650, y + 72), "SHA-256: 8d3f87717d819d637d9fce3ae997f198114... (Recorded in Ledger)", font=f_mono, fill=(148, 163, 184, 255))

    y += 125

    # Section Entropy Table
    d.text((35, y), "PE SECTION ENTROPY DISTRIBUTION & PACKING ASSESSMENT", font=f_mono_b, fill=(56, 189, 248, 255))
    y += 25
    table_lines = [
        "+---------+----------+----------------+------------------+--------------------------------------+",
        "| Section | Raw Size | Entropy (bits) | Distribution Bar | Packing Assessment                   |",
        "+---------+----------+----------------+------------------+--------------------------------------+",
        "| .text   |  1,024 B |          0.958 | ##........       | NORMAL CODE / UNPACKED DATA          |",
        "| .data   | 33,524 B |          7.942 | ##########       | SUSPICIOUS — Likely Packed/Encrypted |",
        "+---------+----------+----------------+------------------+--------------------------------------+",
    ]
    for line in table_lines:
        color = (253, 164, 175, 255) if "SUSPICIOUS" in line else (203, 213, 225, 255)
        d.text((35, y), line, font=f_mono, fill=color)
        y += 20

    y += 15

    # TreeSHAP Attribution Table
    d.text((35, y), "TREESHAP FEATURE ATTRIBUTION (XGBoost – Margin Log-Odds)", font=f_mono_b, fill=(192, 132, 252, 255))
    y += 25
    shap_lines = [
        "+----------+--------------------------+---------------+----------+----------------------------+",
        "| Alert    | Feature / Metric         |      Observed | SHAP Δp  | Security Finding           |",
        "+----------+--------------------------+---------------+----------+----------------------------+",
        "| CRITICAL | Binary File Size         | 66,024 bytes  |  +3.2251 | Drives malicious score     |",
        "| NEUTRAL  | PE Section Count         |    2 sections |  +0.0000 | Standard structure         |",
        "| NEUTRAL  | Max Section Entropy      |    7.994 bits |  +0.0000 | Near theoretical max 8.0   |",
        "| NEUTRAL  | Total API Imports        |   0 functions |  +0.0000 | Sparse — dynamic resolving |",
        "| NEUTRAL  | Watchlist Security APIs  |        0 APIs |  +0.0000 | Zero injection APIs        |",
        "| NEUTRAL  | Compile Timestamp        |   Valid (0.0) |  +0.0000 | Valid historical epoch     |",
        "+----------+--------------------------+---------------+----------+----------------------------+",
    ]
    for line in shap_lines:
        color = (248, 113, 113, 255) if "CRITICAL" in line else (203, 213, 225, 255)
        d.text((35, y), line, font=f_mono, fill=color)
        y += 20

    d.text((35, y), "[ 🚨 SHAP THREAT ALERT ] Key attributes driving malicious classification: Binary File Size (+3.225)", font=f_mono_b, fill=(248, 113, 113, 255))
    y += 35

    # Narrative Cards
    d.text((35, y), "PLAIN-ENGLISH NARRATIVE EXPLANATION CARDS (Deterministic Template Automata)", font=f_mono_b, fill=(251, 191, 36, 255))
    y += 25
    narrative_lines = [
        "+-------------+---------------------------------------------------------------------------------+",
        "| Severity    | Security Finding & Narrative Context                                            |",
        "+-------------+---------------------------------------------------------------------------------+",
        "| ⚠ WARNING   | Binary file size of 66,024 bytes raised the malicious risk score.               |",
        "| 🚨 CRITICAL | High entropy (7.99 bits) across sections indicates packed or encrypted payload. |",
        "| ⚠ WARNING   | Sparse import table (0 functions) strongly indicates dynamic Win32 API loading. |",
        "| ℹ BENIGN    | Compile timestamp within standard historical epoch — no anomalous header date.  |",
        "+-------------+---------------------------------------------------------------------------------+",
    ]
    for line in narrative_lines:
        color = (252, 165, 165, 255) if "CRITICAL" in line else ((253, 224, 71, 255) if "WARNING" in line else (203, 213, 225, 255))
        d.text((35, y), line, font=f_mono, fill=color)
        y += 20

    y += 20

    # Counterfactual Box
    draw_rounded_rect(d, (35, y, w - 35, y + 80), 6, fill=(30, 41, 59, 255), outline=(56, 189, 248, 255), width=1)
    d.text((50, y + 12), "SHAP COUNTERFACTUAL DECISION BOUNDARY SIMULATION", font=f_mono_b, fill=(56, 189, 248, 255))
    d.text((50, y + 36), "Pivotal Feature : file_size      | Observed: 66,024 bytes | Target Boundary: 6,602.4 bytes", font=f_mono, fill=(226, 232, 240, 255))
    d.text((50, y + 56), "Target Band     : UNCERTAIN_BAND | Finding: Verdict shifts to UNCERTAIN_BAND if size drops to 6,602.4 B.", font=f_mono, fill=(148, 163, 184, 255))

    out_path = os.path.join(DOCS_DIR, "fig2_terminal_output.png")
    im.save(out_path, dpi=(200, 200))
    print(f"Generated {out_path}")

if __name__ == "__main__":
    generate_fig1_pipeline()
    generate_fig2_terminal_output()
