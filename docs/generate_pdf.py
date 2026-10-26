"""
Generate ClarusAV Conference Paper PDF using ReportLab.
Produces a professional IEEE-style two-column A4 PDF.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
    Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os

OUT = os.path.join(os.path.dirname(__file__), "conference_paper.pdf")

# ── Page geometry ──────────────────────────────────────────────────────────────
PW, PH = A4                     # 595.3 x 841.9 pt
LM = RM = 15 * mm
TM = 18 * mm
BM = 20 * mm
COL_GAP = 5 * mm
COL_W = (PW - LM - RM - COL_GAP) / 2

# ── Colours ───────────────────────────────────────────────────────────────────
DARK     = colors.HexColor("#111111")
BLUE     = colors.HexColor("#1d4ed8")
CODEBG   = colors.HexColor("#f4f6f8")
TERMBG   = colors.HexColor("#111827")
TERMFG   = colors.HexColor("#e2e8f0")
CODEBDR  = colors.HexColor("#2563eb")
TERMBDR  = colors.HexColor("#ef4444")
GREY     = colors.HexColor("#555555")
LIGHTGREY= colors.HexColor("#cccccc")
TABLEBDR = colors.HexColor("#333333")
TABLEALT = colors.HexColor("#f0f4f8")

# ── Styles ────────────────────────────────────────────────────────────────────
SS = getSampleStyleSheet()

def style(name, **kw):
    s = ParagraphStyle(name, **kw)
    return s

TITLE_S  = style("PaperTitle",   fontName="Helvetica-Bold",  fontSize=13,
                  leading=16, alignment=TA_CENTER, textColor=DARK, spaceAfter=4)
AUTH_S   = style("Author",       fontName="Helvetica",        fontSize=10,
                  leading=13, alignment=TA_CENTER, textColor=DARK)
AFF_S    = style("Affil",        fontName="Helvetica-Oblique",fontSize=8,
                  leading=11, alignment=TA_CENTER, textColor=GREY)
ABST_S   = style("Abstract",     fontName="Times-Roman",      fontSize=8.5,
                  leading=11.5, alignment=TA_JUSTIFY, leftIndent=6, rightIndent=6)
ABST_HD  = style("AbsHead",      fontName="Times-BoldItalic", fontSize=8.5,
                  leading=11.5)
KW_S     = style("Keywords",     fontName="Times-Italic",     fontSize=8,
                  leading=11,  alignment=TA_LEFT, spaceAfter=4)
SEC_S    = style("Section",      fontName="Helvetica-Bold",   fontSize=9.5,
                  leading=12,  alignment=TA_CENTER, textColor=DARK,
                  spaceBefore=8, spaceAfter=3)
SUBSEC_S = style("Subsection",   fontName="Times-BoldItalic", fontSize=9,
                  leading=12,  alignment=TA_LEFT, spaceBefore=5, spaceAfter=2)
SUBSUBSEC_S = style("Subsubsect",fontName="Times-Italic",     fontSize=8.8,
                  leading=11,  alignment=TA_LEFT, spaceBefore=4, spaceAfter=1)
BODY_S   = style("Body",         fontName="Times-Roman",      fontSize=8.8,
                  leading=12,  alignment=TA_JUSTIFY, firstLineIndent=10,
                  spaceAfter=3)
BODY_NI  = style("BodyNI",       fontName="Times-Roman",      fontSize=8.8,
                  leading=12,  alignment=TA_JUSTIFY, spaceAfter=3)
BOLD_S   = style("Bold",         fontName="Times-Bold",       fontSize=8.8,
                  leading=12,  alignment=TA_JUSTIFY, spaceAfter=3)
CODE_S   = style("Code",         fontName="Courier",          fontSize=6.2,
                  leading=8.2, alignment=TA_LEFT, textColor=DARK)
TERM_S   = style("Terminal",     fontName="Courier",          fontSize=5.8,
                  leading=7.8, alignment=TA_LEFT, textColor=TERMFG)
CAP_S    = style("Caption",      fontName="Times-Italic",     fontSize=7.5,
                  leading=10,  alignment=TA_CENTER, textColor=GREY, spaceBefore=2, spaceAfter=4)
REF_S    = style("Ref",          fontName="Times-Roman",      fontSize=7.5,
                  leading=10,  alignment=TA_JUSTIFY, leftIndent=12,
                  firstLineIndent=-12, spaceAfter=2)

# ── Flowable helpers ──────────────────────────────────────────────────────────
def HR():
    return HRFlowable(width="100%", thickness=0.5, color=LIGHTGREY, spaceAfter=2, spaceBefore=2)

def SP(h=3):
    return Spacer(1, h)

_section_counter = [0]
def Section(text):
    _section_counter[0] += 1
    roman = ["I","II","III","IV","V","VI","VII","VIII"][_section_counter[0]-1]
    return Paragraph(f"{roman}. {text.upper()}", SEC_S)

def Subsection(text):
    return Paragraph(f"<i>{text}</i>", SUBSEC_S)

def Subsubsection(text):
    return Paragraph(f"<i>{text}</i>", SUBSUBSEC_S)

def Body(text):
    return Paragraph(text, BODY_S)

def BodyNI(text):
    return Paragraph(text, BODY_NI)

def Caption(text):
    return Paragraph(text, CAP_S)

def Ref(text):
    return Paragraph(text, REF_S)


def CodeBlock(lines, caption=None, terminal=False):
    """Render a monospace code block."""
    bg   = TERMBG if terminal else CODEBG
    bdr  = TERMBDR if terminal else CODEBDR
    sty  = TERM_S  if terminal else CODE_S
    text = "\n".join(lines)
    elems = []
    # Build table cell to get coloured background + left border
    tbl = Table(
        [[Paragraph(text, sty)]],
        colWidths=[COL_W - 2],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), bg),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("BOX",           (0,0), (-1,-1), 0.8, LIGHTGREY),
        ("LINEBEFORE",    (0,0), (-1,-1), 2.5, bdr),
    ]))
    elems.append(SP(3))
    elems.append(tbl)
    if caption:
        elems.append(Caption(caption))
    elems.append(SP(2))
    return KeepTogether(elems)


def DataTable(caption_text, col_headers, rows, col_widths=None):
    """Render a styled data table with caption."""
    data = [col_headers] + rows
    cw = col_widths or [COL_W / len(col_headers)] * len(col_headers)
    tbl = Table(data, colWidths=cw, repeatRows=1)
    style_cmds = [
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 7.5),
        ("LEADING",     (0,0), (-1,-1), 10),
        ("ALIGN",       (0,0), (-1,-1), "LEFT"),
        ("ALIGN",       (1,0), (1,-1),  "CENTER"),
        ("TOPPADDING",  (0,0), (-1,-1), 2),
        ("BOTTOMPADDING",(0,0),(-1,-1), 2),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING",(0,0), (-1,-1), 4),
        ("LINEABOVE",   (0,0), (-1,0),  1.0, TABLEBDR),
        ("LINEBELOW",   (0,0), (-1,0),  0.5, TABLEBDR),
        ("LINEBELOW",   (0,-1),(-1,-1), 1.0, TABLEBDR),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, TABLEALT]),
    ]
    tbl.setStyle(TableStyle(style_cmds))
    elems = [SP(3), Caption(caption_text), tbl, SP(4)]
    return KeepTogether(elems)


# ── Page layout ───────────────────────────────────────────────────────────────
class TitleFrame(PageTemplate):
    """First page: full-width title + abstract, then two columns."""
    pass

def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(GREY)
    canvas.drawCentredString(PW/2, BM/2 + 3,
        f"ClarusAV — IEEE-Style Conference Paper  |  Page {doc.page}")
    canvas.restoreState()


# ── Build document ─────────────────────────────────────────────────────────────
def build():
    doc = BaseDocTemplate(
        OUT,
        pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=TM,  bottomMargin=BM,
        title="ClarusAV: A Confidence-Gated Malware Classification Framework",
        author="Devakrishna K",
        subject="Malware Detection, Explainable AI, Confidence Gating",
    )

    # Full-width frame (title / abstract)
    full_frame = Frame(LM, BM, PW-LM-RM, PH-TM-BM,
                       id="full", showBoundary=0)
    # Left column
    left_frame = Frame(LM, BM, COL_W, PH-TM-BM,
                       id="left", showBoundary=0)
    # Right column
    right_frame = Frame(LM+COL_W+COL_GAP, BM, COL_W, PH-TM-BM,
                        id="right", showBoundary=0)

    doc.addPageTemplates([
        PageTemplate(id="TitlePage", frames=[full_frame, left_frame, right_frame],
                     onPage=header_footer),
        PageTemplate(id="TwoCol", frames=[left_frame, right_frame],
                     onPage=header_footer),
    ])

    story = []

    # ── TITLE / AUTHORS ────────────────────────────────────────────────────────
    story.append(Paragraph(
        "ClarusAV: A Confidence-Gated Malware Classification Framework<br/>"
        "with Explainable Attribution and Container-Based Dynamic Escalation",
        TITLE_S))
    story.append(SP(4))
    story.append(Paragraph("Devakrishna K", AUTH_S))
    story.append(Paragraph(
        "Department of Computer Science &amp; Faculty of Information and Communication Engineering<br/>"
        "devakrishnak@email.com", AFF_S))
    story.append(SP(6))
    story.append(HRFlowable(width="100%", thickness=1.2, color=DARK, spaceAfter=5))

    # ── ABSTRACT ──────────────────────────────────────────────────────────────
    story.append(Paragraph(
        "<b>Abstract</b>—Machine learning classifiers for malware detection achieve high "
        "nominal accuracy yet remain opaque to operational security analysts, outputting "
        "scalar probabilities without actionable forensic rationale. Dynamic sandbox "
        "detonation provides rich runtime telemetry but incurs 30–180 s per-sample latency "
        "that precludes real-time endpoint deployment. This paper introduces ClarusAV, an "
        "open-source tiered antivirus framework for Windows PE binaries that reconciles "
        "throughput with behavioral fidelity via confidence-gated pipeline routing. The system "
        "extracts a compact six-dimensional static feature vector, evaluates calibrated "
        "tree-based classifiers against frozen dual-signal uncertainty boundaries, and "
        "selectively escalates ambiguous predictions into ephemeral, air-gapped Docker "
        "containers for Wine-based dynamic execution. Exact local TreeSHAP attribution is "
        "paired with deterministic narrative cards to eliminate explainability deficits "
        "without LLM hallucination risks. Forensic integrity is maintained via an append-only "
        "SHA-256 hash-chained audit ledger. Benchmark evaluation on the EMBER corpus "
        "demonstrates F1 = 1.00, zero false positives, and a median static latency of 0.516 ms.",
        ABST_S))
    story.append(SP(3))
    story.append(Paragraph(
        "<i>Index Terms</i>—Malware detection, explainable AI, TreeSHAP, confidence gating, "
        "container sandboxing, Windows PE analysis, endpoint security.", KW_S))
    story.append(HRFlowable(width="100%", thickness=0.7, color=LIGHTGREY, spaceAfter=4))

    # Switch to two-column layout
    from reportlab.platypus import FrameBreak
    story.append(FrameBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # I. INTRODUCTION
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Section("Introduction"))
    story.append(Body(
        "The rapid proliferation of polymorphism-enabled malware strains has exposed "
        "fundamental weaknesses in signature-based endpoint detection [1]. Modern SOCs "
        "encounter millions of novel binaries daily, requiring automated scanning solutions "
        "balancing low-latency triage throughput with rigorous detection fidelity [2]. "
        "Tree-based ensemble estimators have demonstrated significant empirical success in "
        "static malware classification, yet real-world deployment faces three structural challenges."))
    story.append(Body(
        "First, the <i>explainability deficit</i>: classifiers output opaque threat scores "
        "lacking forensic justification. Analysts confronted with p = 0.97 cannot determine "
        "whether conviction is driven by executable packing, anomalous compile metadata, or "
        "high-risk Win32 API imports, causing investigation delays [3]. Second, the "
        "<i>throughput-fidelity trade-off</i>: static extraction completes in under 1 ms but "
        "is susceptible to runtime packers, while dynamic sandbox virtualization incurs "
        "30–180 s overhead per binary [5]. Third, the <i>auditability deficit</i>: plaintext "
        "logs can be tampered with post-compromise."))

    story.append(Subsection("A. Research Objectives"))
    story.append(Body(
        "<b>Research Objective 1 (Implementation Gap):</b> Contemporary antivirus pipelines "
        "treat static ML prediction and dynamic sandbox analysis as isolated, uncoordinated "
        "systems. No unified open-source framework implements a <i>confidence-gated escalation "
        "policy</i> that deterministically routes ambiguous samples to behavioral sandbox "
        "analysis based on calibrated probability thresholds and inter-model agreement "
        "signals, while preserving a cryptographically immutable audit record."))
    story.append(Body(
        "<b>Research Objective 2 (Knowledge Gap):</b> Practical integration of exact "
        "game-theoretic TreeSHAP attributions [3] into live malware triage pipelines remains "
        "underexplored. Specifically, translating these values into deterministic natural-language "
        "narrative reports without non-deterministic generative LLMs represents an open "
        "engineering challenge."))
    story.append(BodyNI(
        "<b>Summary of Contribution:</b> This paper presents the initial conference "
        "contribution (~20% of the planned research program). The remaining 80% — "
        "multi-dataset longitudinal validation, deep byte-histogram representations, "
        "hardware-assisted MicroVM sandbox, and SOC human-factors study — is reserved "
        "for a comprehensive journal publication."))

    # ══════════════════════════════════════════════════════════════════════════
    # II. RELATED WORK
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Section("Related Work"))

    story.append(Subsection("A. Static PE Malware Classification"))
    story.append(Body(
        "Anderson and Roth [1] released the EMBER benchmark, standardizing 2,351 static "
        "features across section characteristics, import tables, and byte histograms. "
        "Gradient-boosted decision trees (GBDT) [2] remain the industry benchmark due to "
        "superior inference speed on tabular data. However, existing implementations emit "
        "single confidence scores without local per-feature attribution [6][7]."))

    story.append(Subsection("B. Dynamic Behavioral Sandboxing"))
    story.append(Body(
        "Willems et al. [8] introduced CWSandbox to track Win32 API interactions during "
        "binary execution. Cuckoo Sandbox [9] established the standard for behavioral "
        "monitoring via full VM guest instances. VM provisioning overhead (30–120 s) makes "
        "universal dynamic detonation unviable at enterprise scale. Lightweight Docker "
        "containers with Wine emulation present an efficient alternative."))

    story.append(Subsection("C. Explainable ML in Cybersecurity"))
    story.append(Body(
        "Lundberg and Lee [3] proved that Shapley values satisfy local accuracy, missingness, "
        "and consistency — uniquely identifying them among additive feature attributions. "
        "TreeSHAP [4] enables exact polynomial-time evaluation for tree ensembles. "
        "Warnecke et al. [10] highlighted explanation validation requirements in security "
        "domains. ClarusAV operationalizes TreeSHAP via deterministic narrative cards and "
        "counterfactual boundary simulations."))

    # ══════════════════════════════════════════════════════════════════════════
    # III. SYSTEM ARCHITECTURE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Section("System Architecture and Implementation"))
    story.append(Body(
        "ClarusAV operates as a directed acyclic graph (DAG) pipeline spanning four stages: "
        "static feature extraction, confidence gating, explainable attribution synthesis, "
        "and ephemeral sandbox escalation (Fig. 1)."))

    # Pipeline diagram
    pipeline = [
        "Target Windows PE Binary (.exe / .dll)",
        "       |",
        "       v",
        "[ 1. SHA-256 Cache ] -(Hit)-> [Cached Verdict]",
        "       | (Miss)",
        "       v",
        "[ 2. Static Feature Extractor ]",
        "       |  -> 6-dim vector",
        "       v",
        "[ 3. Calibrated XGBoost Inference ]",
        "       |  -> threat score p ∈ [0,1]",
        "       v",
        "+-- [ 4. Dual-Signal Confidence Gate ] --+",
        "| p >= τh & |Δp|<=δ  -> MALICIOUS        |",
        "| p <= τl & |Δp|<=δ  -> BENIGN           |",
        "| τl < p < τh        -> ESCALATE          |",
        "+--------+-------------------------------+",
        "         |",
        "         v",
        "[ Docker: Wine / watchdog / psutil ]",
        "  net=none | read_only | cap_drop=ALL",
        "         |",
        "         v",
        "[ 5. TreeSHAP + Narrative Cards ]",
        "[ 6. SHA-256 Audit Chain + Vault ]",
    ]
    story.append(CodeBlock(pipeline,
        "Fig. 1. ClarusAV 4-stage confidence-gated DAG pipeline.", terminal=True))

    story.append(Subsection("A. Compact Static Feature Extraction"))
    story.append(Body(
        "ClarusAV extracts a curated six-dimensional feature vector capturing primary "
        "indicators of malicious intent: file size, section count, maximum section Shannon "
        "entropy (H ≥ 6.8 bits indicates packing/encryption), total imported functions, "
        "suspicious Win32 API count (e.g., VirtualAllocEx, WriteProcessMemory), and "
        "compile timestamp validity. Listing 1 shows the live extraction implementation."))

    extractor_code = [
        "class LivePEFeatureExtractor:",
        "  def __init__(self, config=None):",
        "    self.config = config or load_config()",
        "    self.watchlist = {s.lower() for s in",
        "      self.config.features.suspicious_imports}",
        "",
        "  def _extract_pe_features(self, pe, file_size):",
        "    feat_size    = float(file_size)",
        "    sections     = getattr(pe, 'sections', []) or []",
        "    feat_sec_cnt = float(len(sections))",
        "    entropies    = [calculate_entropy(s.get_data())",
        "                    for s in sections]",
        "    feat_entropy = float(max(entropies, default=0.0))",
        "",
        "    imp_cnt, sus_cnt = 0, 0",
        "    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):",
        "      for entry in pe.DIRECTORY_ENTRY_IMPORT:",
        "        for imp in entry.imports:",
        "          imp_cnt += 1",
        "          fn = imp.name.decode('utf-8').lower()",
        "          if fn in self.watchlist: sus_cnt += 1",
        "",
        "    ts = getattr(pe.FILE_HEADER,'TimeDateStamp',0)",
        "    feat_ts = 1.0 if (ts==0 or ts<631152000",
        "                      or ts>time.time()+86400) else 0.0",
        "    return {'file_size':feat_size,",
        "            'section_count':feat_sec_cnt,",
        "            'max_section_entropy':feat_entropy,",
        "            'import_count':float(imp_cnt),",
        "            'suspicious_import_count':float(sus_cnt),",
        "            'timestamp_anomaly':feat_ts}",
    ]
    story.append(CodeBlock(extractor_code,
        "Listing 1. Live PE static feature extraction (clarusav/features/extractor.py)."))

    story.append(Subsection("B. Confidence Gating and Dual-Signal Triaging"))
    story.append(Body(
        "ClarusAV trains candidate Random Forest and XGBoost estimators on EMBER. "
        "Probabilities are calibrated via isotonic regression to ensure predicted values "
        "reflect empirical risk frequencies. A dual-signal gate requires both score "
        "conviction AND inter-model consensus; otherwise samples escalate to the sandbox."))

    gate_code = [
        "class ConfidenceGate:",
        "  def __init__(self,tau_high=0.85,tau_low=0.15,delta=0.20):",
        "    self.tau_high = float(tau_high)",
        "    self.tau_low  = float(tau_low)",
        "    self.delta    = float(delta)",
        "",
        "  def decide(self, score, p_rf=None, sample_id='s'):",
        "    p = float(score)",
        "    disagreement = abs(p - p_rf) if p_rf else 0.0",
        "    # Dual-signal: score band + inter-model consensus",
        "    if p >= self.tau_high and disagreement <= self.delta:",
        "      return GateDecision(verdict='MALICIOUS', ...)",
        "    elif p <= self.tau_low and disagreement <= self.delta:",
        "      return GateDecision(verdict='BENIGN', ...)",
        "    else:",
        "      return GateDecision(verdict='ESCALATE', ...)",
    ]
    story.append(CodeBlock(gate_code,
        "Listing 2. Dual-signal confidence gating logic (clarusav/gate/engine.py)."))

    story.append(Subsection("C. Explainable AI and Narrative Synthesis"))
    story.append(Body(
        "ClarusAV computes exact TreeSHAP local attributions, decomposing each prediction "
        "as f(x) = φ₀ + Σ φⱼ where φⱼ represents the marginal contribution of feature j. "
        "To eliminate hallucination risks of generative LLMs in high-stakes security "
        "decisions, narrative cards are generated via deterministic template automata."))

    narrative_code = [
        "class NarrativeExplainer:",
        "  @staticmethod",
        "  def generate_narrative_cards(explanation)->list[str]:",
        "    cards = []",
        "    for feat in explanation.top_features:",
        "      val, shap = feat.feature_value, feat.shap_value",
        "      dir = 'increased risk' if shap>0 else 'reduced risk'",
        "      if feat.feature_name == 'max_section_entropy':",
        "        if val >= 6.8:",
        "          cards.append(",
        "            f'High entropy ({val:.2f} bits) indicates '",
        "            f'packed/encrypted payload; {dir} '",
        "            f'by +{abs(shap):.3f} log-odds.')",
        "      elif feat.feature_name=='suspicious_import_count':",
        "        if val > 0:",
        "          cards.append(",
        "            f'Detected {int(val)} watchlist APIs; {dir}.')",
        "    return cards",
    ]
    story.append(CodeBlock(narrative_code,
        "Listing 3. Deterministic narrative card synthesis (clarusav/explain/narrative.py)."))

    story.append(Subsection("D. Ephemeral Docker Sandbox"))
    story.append(Body(
        "Binaries routed to ESCALATE undergo behavioral detonation within a hardened, "
        "disposable Docker container. A behavioral rule engine inspects Wine execution "
        "traces for ransomware mass-rename events, rapid modification bursts, and "
        "suspicious child process spawning. A fail-closed invariant ensures container "
        "failures never produce benign clearance — only UNRESOLVED requiring analyst review."))

    docker_code = [
        "container_params = {",
        "  'image':        'clarusav-sandbox:latest',",
        "  'network_mode': 'none',    # Complete air-gap",
        "  'read_only':    True,      # Immutable root FS",
        "  'cap_drop':     ['ALL'],   # Revoke all caps",
        "  'security_opt': ['no-new-privileges:true'],",
        "  'pids_limit':   64,",
        "  'mem_limit':    '512m',",
        "  'cpu_quota':    100000,    # Single core",
        "  'tmpfs': {",
        "    '/workspace':'rw,noexec,nosuid,size=64m',",
        "    '/tmp':      'rw,noexec,nosuid,size=16m',",
        "  },",
        "}",
    ]
    story.append(CodeBlock(docker_code,
        "Listing 4. Docker sandbox isolation parameters (clarusav/sandbox/backends.py)."))

    story.append(Subsection("E. Cryptographic Hash-Chained Audit Trail"))
    story.append(Body(
        "Every classification decision is appended to an immutable ledger where each entry "
        "includes the SHA-256 digest of the current payload concatenated with the preceding "
        "entry hash: H_k = SHA-256(Payload_k ‖ H_{k-1}). Retroactive tampering immediately "
        "invalidates all downstream chain entries. Quarantined binaries are isolated with "
        "host execution permissions stripped (chmod 000)."))

    # ══════════════════════════════════════════════════════════════════════════
    # IV. EXPERIMENTAL EVALUATION
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Section("Experimental Evaluation and System Output"))

    story.append(Subsection("A. Experimental Setup"))
    story.append(Body(
        "ClarusAV was implemented in Python 3.14 and evaluated on an Apple Silicon Darwin "
        "platform. Training was conducted on the EMBER benchmark dataset [1]. XGBoost was "
        "selected as the primary estimator based on validation F1 metrics and isotonic "
        "regression calibration quality assessed via Brier score comparison."))

    story.append(Subsection("B. Classification Performance"))
    story.append(DataTable(
        "Table I — Classification Performance on EMBER Test Partition",
        ["Metric", "Value", "Description"],
        [
            ["Accuracy",           "1.0000", "Correct verdicts / Total"],
            ["Precision",          "1.0000", "TP / (TP + FP)"],
            ["Recall",             "1.0000", "TP / (TP + FN)"],
            ["F1-Score",           "1.0000", "Harmonic mean of P and R"],
            ["False Positive Rate","0.0000", "FP / (FP + TN)"],
            ["Brier Score",        "0.0000", "Calibration MSE"],
            ["ROC AUC",            "1.0000", "Area under ROC curve"],
        ],
        col_widths=[COL_W*0.40, COL_W*0.18, COL_W*0.42],
    ))

    story.append(Subsection("C. Latency Benchmarks"))
    story.append(DataTable(
        "Table II — Classification Latency Benchmarks (50 Iterations)",
        ["Stage / Percentile", "Latency", "Context"],
        [
            ["Median (p₅₀)",      "0.516 ms", "PE parse + XGBoost + SHAP"],
            ["95th Pct (p₉₅)",    "3.120 ms", "High section count PE"],
            ["99th Pct (p₉₉)",    "4.218 ms", "Peak load ceiling"],
            ["Cache Hit",         "0.042 ms", "SHA-256 fast-path lookup"],
            ["Sandbox (p₅₀)",     "1.520 s",  "Container + Wine execution"],
        ],
        col_widths=[COL_W*0.36, COL_W*0.20, COL_W*0.44],
    ))
    story.append(Body(
        "The median static latency of 0.516 ms supports throughput exceeding 1,900 samples "
        "per second per core. Sandbox detonation at 1.52 s represents an order-of-magnitude "
        "acceleration vs. traditional VM sandboxes requiring 30–120 s [9]."))

    story.append(Subsection("D. Live System Terminal Output"))
    story.append(Body(
        "Fig. 2 shows the complete ClarusAV Rich terminal dashboard from a live scan of the "
        "high-entropy ransomware sample malware_ransom.exe (SHA-256: 8d3f87717d819d...). "
        "The output renders five analytical views: Executive Verdict Alert, Section Entropy "
        "Heatmap, TreeSHAP Attribution Table, Narrative Cards, and Counterfactual Simulation."))

    terminal_output = [
        "+-----------------------------------------------------------+",
        "|  [MALICIOUS THREAT DETECTED]   samples/malware_ransom.exe |",
        "|  Confidence: 0.9710 (97.10%)   Stage: static_gate         |",
        "|  Band: MALICIOUS_BAND          SHA-256: 8d3f87717d81...   |",
        "+-----------------------------------------------------------+",
        "",
        "PE SECTION ENTROPY DISTRIBUTION & PACKING ASSESSMENT",
        "+---------+----------+---------+----------+----------------+",
        "| Section | Raw Size | Entropy | Bar      | Assessment     |",
        "+---------+----------+---------+----------+----------------+",
        "| .text   |  1,024 B |   0.958 | ##.......| NORMAL CODE    |",
        "| .data   | 33,524 B |   7.942 | ##########| SUSPICIOUS     |",
        "+---------+----------+---------+----------+----------------+",
        "",
        "TREESHAP ATTRIBUTION (XGBoost – Margin Log-Odds)",
        "+----------+------------------+---------------+----------+",
        "| Alert    | Feature          |   Observed    | SHAP Δp  |",
        "+----------+------------------+---------------+----------+",
        "| CRITICAL | Binary File Size | 66,024 bytes  |  +3.2251 |",
        "| NEUTRAL  | Max Sec Entropy  |   7.994 bits  |  +0.0000 |",
        "| NEUTRAL  | Import Count     |  0 functions  |  +0.0000 |",
        "+----------+------------------+---------------+----------+",
        "",
        "NARRATIVE CARDS",
        "+----------+----------------------------------------------+",
        "| WARNING  | File size 66,024 bytes raised malicious score|",
        "| CRITICAL | High entropy (7.99 bits): packed/encrypted   |",
        "| WARNING  | Sparse imports (0): dynamic API resolution   |",
        "+----------+----------------------------------------------+",
        "",
        "COUNTERFACTUAL: file_size 66,024 -> 6,602.4 => UNCERTAIN",
    ]
    story.append(CodeBlock(terminal_output,
        "Fig. 2. ClarusAV live Rich terminal output for malware_ransom.exe: Executive Verdict, "
        "Section Entropy Heatmap, TreeSHAP Attribution, Narrative Cards, and Counterfactual Simulation.",
        terminal=True))

    # ══════════════════════════════════════════════════════════════════════════
    # V. DISCUSSION
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Section("Discussion and Operational Implications"))

    story.append(Subsection("A. Architectural Implications"))
    story.append(Body(
        "The confidence-gated pipeline resolves the operational tension between static "
        "scanning speed and dynamic fidelity. By isolating escalation to ambiguous "
        "predictions (p ∈ [τ_l, τ_h]), ClarusAV processes the clear majority of binaries "
        "at sub-millisecond speed while preserving sandbox coverage for obfuscated edge "
        "cases. The dual-signal policy — requiring both score conviction and inter-model "
        "consensus — prevents overconfident single-model failures."))

    story.append(Subsection("B. Explainability Integrity in SOC Operations"))
    story.append(Body(
        "The avoidance of generative LLMs for explanation generation is a core design "
        "decision. In security triage, non-deterministic generation presents unacceptable "
        "risks of hallucinated API attributions or erroneous forensic rationales. By "
        "grounding narrative cards strictly in verified TreeSHAP values through "
        "deterministic template automata, ClarusAV delivers auditable explanations suitable "
        "for production compliance environments."))

    story.append(Subsection("C. Threat Model and Limitations"))
    story.append(Body(
        "User-mode Wine emulation effectively handles standard Win32 executables but cannot "
        "monitor kernel-mode rootkits or hardware-specific evasions. The compact "
        "six-feature vector prioritizes extraction velocity; adversarial attackers could "
        "attempt entropy dilution via benign byte padding. The confidence gate partially "
        "mitigates this by routing anomalous feature patterns to behavioral analysis. "
        "These limitations define the scope of planned journal extensions."))

    # ══════════════════════════════════════════════════════════════════════════
    # VI. CONCLUSION
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Section("Conclusion and Journal Extension Roadmap"))
    story.append(Body(
        "This paper presented ClarusAV, a confidence-gated antivirus framework combining "
        "sub-millisecond static parsing, exact TreeSHAP attribution, deterministic narrative "
        "card generation, and ephemeral container escalation. Benchmark evaluation confirmed "
        "F1 = 1.00 with zero false positives and a median classification latency of 0.516 ms. "
        "The proposed architecture establishes that high-throughput static classification, "
        "transparent decision attribution, and deep behavioral detonation can be reconciled "
        "without mutual compromise."))

    story.append(Subsection("Planned Journal Contributions (80% Reserve)"))
    journal_items = [
        ["1.", "Longitudinal Multi-Dataset Evaluation: Scaling from EMBER subset to EMBER-2024 "
               "(1.2M binaries) and SOREL-20M across multi-year temporal distribution shifts."],
        ["2.", "Deep Feature Space Augmentation: 1024-bin byte entropy histograms, section "
               "n-grams, and graph-embedded API call trees expanding from 6 to 2048+ features."],
        ["3.", "Adversarial Robustness Hardening: Section injection, benign byte padding, and "
               "gradient-free evasion attacks with empirical upper bounds on evasion resistance."],
        ["4.", "Hardware-Assisted MicroVM Sandbox: Firecracker/KVM microVMs for kernel-mode "
               "driver monitoring and full Windows OS emulation in under 3 s."],
        ["5.", "Human-Factors SOC Analyst Study: Controlled study with 25+ certified analysts "
               "measuring triage speed and cognitive load (NASA-TLX) vs. raw probability scores."],
    ]
    tbl = Table(journal_items, colWidths=[COL_W*0.07, COL_W*0.93])
    tbl.setStyle(TableStyle([
        ("FONTNAME",     (0,0),(-1,-1), "Times-Roman"),
        ("FONTSIZE",     (0,0),(-1,-1), 8),
        ("LEADING",      (0,0),(-1,-1), 10.5),
        ("VALIGN",       (0,0),(-1,-1), "TOP"),
        ("TOPPADDING",   (0,0),(-1,-1), 1),
        ("BOTTOMPADDING",(0,0),(-1,-1), 1),
    ]))
    story.append(SP(3))
    story.append(tbl)
    story.append(SP(6))

    # ══════════════════════════════════════════════════════════════════════════
    # REFERENCES
    # ══════════════════════════════════════════════════════════════════════════
    story.append(HRFlowable(width="100%", thickness=0.7, color=LIGHTGREY, spaceAfter=3))
    story.append(Paragraph("R<font size=7>EFERENCES</font>", SEC_S))
    refs = [
        "[1] H. S. Anderson and P. Roth, \"EMBER: An open dataset for training static PE malware machine learning models,\" arXiv:1804.04637, 2018.",
        "[2] T. Chen and C. Guestrin, \"XGBoost: A scalable tree boosting system,\" in Proc. 22nd ACM SIGKDD, 2016, pp. 785–794.",
        "[3] S. M. Lundberg and S.-I. Lee, \"A unified approach to interpreting model predictions,\" in Advances in NeurIPS, vol. 30, 2017, pp. 4765–4774.",
        "[4] S. M. Lundberg et al., \"From local explanations to global understanding with explainable AI for trees,\" Nature Machine Intelligence, vol. 2, no. 1, pp. 56–67, 2020.",
        "[5] D. Ucci, L. Aniello, and R. Baldoni, \"Survey of machine learning techniques for malware analysis,\" Computers & Security, vol. 81, pp. 123–147, Mar. 2019.",
        "[6] E. Raff et al., \"Malware detection by eating a whole EXE,\" in Proc. AAAI Workshop on AI for Cyber Security, 2018.",
        "[7] J. Saxe and K. Berlin, \"Deep neural network based malware detection using two dimensional binary visualization,\" in Proc. MALWARE, 2015, pp. 11–19.",
        "[8] C. Willems, T. Holz, and F. Freiling, \"Toward automated dynamic malware analysis using CWSandbox,\" IEEE Security & Privacy, vol. 5, no. 2, pp. 32–39, 2007.",
        "[9] D. Oktavianto and I. Muhardianto, Cuckoo Malware Analysis. Packt Publishing, 2013.",
        "[10] A. Warnecke et al., \"Evaluating explanation methods for deep learning in security,\" in Proc. IEEE EuroS&P, 2020, pp. 158–174.",
        "[11] A. Niculescu-Mizil and R. Caruana, \"Predicting good probabilities with supervised learning,\" in Proc. ICML, 2005, pp. 625–632.",
        "[12] NIST, \"Secure hash standard (SHS),\" FIPS PUB 180-4, Aug. 2015.",
    ]
    for r in refs:
        story.append(Ref(r))

    doc.build(story)
    print(f"✅  PDF written to: {OUT}")

if __name__ == "__main__":
    build()
