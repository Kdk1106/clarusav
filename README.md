# ClarusAV

> Lightweight, Explainable, Container-Deployed CLI Antivirus for Windows PE Files.

[![CI](https://github.com/clarusav/clarusav/actions/workflows/ci.yml/badge.svg)](https://github.com/clarusav/clarusav/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Architecture Pipeline

```text
PE file -> pefile feature extraction -> Random Forest / XGBoost calibrated score p -> TreeSHAP attribution -> confidence gate:
  p >= tau_h (e.g. 0.85) -> MALICIOUS
  p <= tau_l (e.g. 0.15) -> BENIGN
  otherwise              -> escalate to disposable Docker sandbox -> behavioural check -> final verdict.
```

Every scan verdict carries:
- **Calibrated score ($p \in [0.0, 1.0]$)** from Isotonic Regression or Platt Scaling
- **Confidence band position** (`MALICIOUS_BAND`, `BENIGN_BAND`, or `UNCERTAIN_BAND`)
- **Top-$k$ TreeSHAP feature attributions** (`probability` for RF, `log-odds` for XGBoost)
- **Plain-English narrative explanation card** (deterministic template, zero hallucination)
- **Counterfactual decision boundary hint** (labeled strictly as model behavior, not file intent)
- **Deciding pipeline stage** (`static_gate`, `sandbox_escalation`, or `fast_path_cache`)
- **Tamper-evident audit log signature** linking into a cryptographic SHA-256 hash chain

> **Fail-Closed Guarantee**: Failures (container error, timeout, unobserved behavior) produce **"UNRESOLVED - manual review"**, never "benign".

---

## 10 Unique Features

1. **Plain-English Narrative Cards (No LLM)**: Deterministic, domain-grounded cards explaining why the binary was classified.
2. **Counterfactual Decision Boundary Hints**: SHAP-guided single-feature perturbations showing the minimal change needed to shift into the uncertain band.
3. **Dual-Signal Uncertainty Gate**: Escalates to sandbox on ambiguous scores *or* inter-model divergence between Random Forest and XGBoost.
4. **PE Section Entropy Heatmap**: Visual per-section distribution bar in terminal (Rich) and HTML indicating packing/encryption.
5. **Signed Tamper-Evident Audit Log**: Append-only audit log with SHA-256 hash chaining and `clarusav history --verify`.
6. **Fast-Path SHA-256 Cache**: Keyed by file SHA-256 and model version; automatically invalidates when the model bundle updates.
7. **Live Filesystem Watcher & TUI Dashboard**: Real-time directory monitoring via `watchdog` with debouncing, concurrency caps, and live Rich display.
8. **Prediction Distribution Drift Monitor**: Online monitoring of observed scan score means compared to training baseline to signal concept drift.
9. **Self-Contained Dark-Mode HTML Report**: Glassmorphic standalone HTML reports for analyst handoff.
10. **Reproducibility Benchmark Suite**: `clarusav bench` computing exact F1, precision, recall, FPR, escalation rates, and p50/p95/p99 latency percentiles to `bench_results.csv`.

---

## Mathematical Formulations & Implementation Code Mapping

All key mathematical equations, rules, and algorithms documented in the conference paper are mapped directly to their implementations in the ClarusAV codebase below:

### 1. Shannon Section Entropy Calculation (Paper Equation 1)
Measures peak byte-level randomness across PE sections to detect packed code, compressed payloads, or cryptographic shellcode:

$$\mathcal{H} = - \sum_{b=0}^{255} q_b \log_2 q_b$$

* **Exact Implementation**:
  - [`clarusav/features/entropy.py` (Lines 7–27)](file:///Users/devakrishnak/final/clarusav/features/entropy.py#L7-L27): Computes Shannon entropy over byte frequencies $q_b = \frac{\text{count}(b)}{N}$.
  - [`clarusav/features/extractor.py` (Lines 142–148)](file:///Users/devakrishnak/final/clarusav/features/extractor.py#L142-L148): Iterates over all PE sections and evaluates the peak entropy: $\text{feat\_max\_entropy} = \max(\mathcal{H}_{\text{sections}})$.

---

### 2. Dual-Signal Confidence Gate & Escalation Rate (Paper Equation 2 & Listing 1)
Defines inter-model disagreement $d(x) = |p(x) - p_{\text{rf}}(x)|$ and decomposes the sandbox escalation rate $\epsilon$ across score conviction thresholds and model consensus:

$$\epsilon = \Pr(\tau_l < p < \tau_h) + \Pr((p \le \tau_l \lor p \ge \tau_h) \land d > \delta)$$

Decision rule:
$$\text{Verdict}(x) = \begin{cases} \text{MALICIOUS}, & p(x) \ge \tau_h \land d(x) \le \delta \\ \text{BENIGN}, & p(x) \le \tau_l \land d(x) \le \delta \\ \text{ESCALATE}, & \text{otherwise} \end{cases}$$

* **Exact Implementation**:
  - [`clarusav/gate/uncertainty.py` (Lines 48–101)](file:///Users/devakrishnak/final/clarusav/gate/uncertainty.py#L48-L101): `DualSignalGate.evaluate` calculates $d(x) = |p(x) - p_{\text{rf}}(x)|$ (line 57), checks uncertain score bands (line 59), and emits `DUAL_TRIGGER`, `SCORE_BAND`, `MODEL_DISAGREEMENT`, or static verdict.
  - [`clarusav/gate/engine.py` (Lines 75–85)](file:///Users/devakrishnak/final/clarusav/gate/engine.py#L75-L85): `ConfidenceGate.__init__` frozen operating boundaries ($\tau_h = 0.85, \tau_l = 0.15$).
  - [`clarusav/gate/engine.py` (Lines 88–228)](file:///Users/devakrishnak/final/clarusav/gate/engine.py#L88-L228): `ConfidenceGate.fit_from_validation` deterministic grid search optimizing $\tau_l, \tau_h$ to minimize escalation rate $\epsilon$ subject to a minimum recall floor.
  - [`clarusav/gate/engine.py` (Lines 230–278)](file:///Users/devakrishnak/final/clarusav/gate/engine.py#L230-L278): `ConfidenceGate.decide` evaluates calibrated probability score against frozen thresholds.

---

### 3. Expected Pipeline Latency & Cost Model (Paper Equation 3)
Formulates mean processing cost $T_{\text{avg}}$ as a function of static stage time $T_s$, dynamic sandbox latency $T_d$, and escalation proportion $\epsilon$:

$$T_{\text{avg}} = T_s + \epsilon T_d$$

* **Exact Implementation**:
  - [`clarusav/bench/suite.py` (Lines 55–87)](file:///Users/devakrishnak/final/clarusav/bench/suite.py#L55-L87): Measures per-sample static latency percentiles ($p_{50} = 0.516\text{ ms}, p_{95}, p_{99}$), measures total escalated count, and records empirical escalation rate $\epsilon$.
  - [`clarusav/gate/engine.py` (Lines 187–205)](file:///Users/devakrishnak/final/clarusav/gate/engine.py#L187-L205): Computes the escalation-vs-quality trade-off curve across validation targets.

---

### 4. Exact TreeSHAP Additive Margin Decomposition (Paper Equation 4)
Axiomatically decomposes the ensemble margin output into the base expected value $\phi_0$ and sum of local feature attributions $\phi_j(x)$:

$$f(x) = \phi_0 + \sum_{j=1}^{6} \phi_j(x)$$

* **Exact Implementation**:
  - [`clarusav/explain/explainer.py` (Lines 69–80)](file:///Users/devakrishnak/final/clarusav/explain/explainer.py#L69-L80): Validates units (`"log-odds"` for XGBoost, `"probability"` for Random Forest) and instantiates `shap.TreeExplainer`.
  - [`clarusav/explain/explainer.py` (Lines 82–113)](file:///Users/devakrishnak/final/clarusav/explain/explainer.py#L82-L113): `_extract_shap_and_base` extracts exact Shapley values $\phi_j$ and expected base value $\phi_0$.
  - [`clarusav/explain/explainer.py` (Lines 133–146)](file:///Users/devakrishnak/final/clarusav/explain/explainer.py#L133-L146): Iterates through canonical features, computing individual contributions and risk direction.
  - [`clarusav/explain/explainer.py` (Lines 149–150)](file:///Users/devakrishnak/final/clarusav/explain/explainer.py#L149-L150): Directly computes output: `output_val = float(base_val + np.sum(instance_phi))`.

---

### 5. Cryptographic Append-Only Audit Hash Chain (Paper Equation 5)
Enforces tamper-evidence across sequential scan entries by chaining SHA-256 digests:

$$\mathcal{H}_k = \text{SHA-256}(P_k \,\|\, \mathcal{H}_{k-1})$$

with genesis anchor $\mathcal{H}_0 = 0^{64}$.

* **Exact Implementation**:
  - [`clarusav/store/audit.py` (Lines 26–30)](file:///Users/devakrishnak/final/clarusav/store/audit.py#L26-L30): `AuditEntry.calculate_hash` concatenates canonical payload fields with `self.prev_hash` and hashes via `hashlib.sha256`.
  - [`clarusav/store/audit.py` (Lines 69–92)](file:///Users/devakrishnak/final/clarusav/store/audit.py#L69-L92): `AuditLog.append` retrieves previous hash $\mathcal{H}_{k-1}$ (or `GENESIS_HASH`) and writes entry $\mathcal{H}_k$.
  - [`clarusav/store/audit.py` (Lines 94–134)](file:///Users/devakrishnak/final/clarusav/store/audit.py#L94-L134): `AuditLog.verify` iterates through all entries $k=0 \dots N-1$, asserting $\mathcal{H}_k == \text{SHA-256}(P_k \,\|\, \mathcal{H}_{k-1})$.

---

### 6. PE Compile-Time Timestamp Anomaly Rule (Paper Table II)
Flags binary header timestamp $t$ as anomalous if manipulated, pre-dated, or excessively post-dated:

$$\text{Anomaly}(t) = \begin{cases} 1.0, & \text{if } t = 0 \lor t < 631152000 \text{ (1990-01-01)} \lor t > t_{\text{ref}} + 86400 \\ 0.0, & \text{otherwise} \end{cases}$$

* **Exact Implementation**:
  - [`clarusav/features/extractor.py` (Lines 184–196)](file:///Users/devakrishnak/final/clarusav/features/extractor.py#L184-L196): `compute_timestamp_anomaly` checks zeroed timestamp, minimum cutoff ($631152000$), and future tolerance.

---

### 7. Deterministic Narrative Card Automata (Paper Table IV)
Generates reproducible natural language security findings directly from observed feature values and SHAP sign without non-deterministic generative LLMs:

* **Exact Implementation**:
  - [`clarusav/explain/narrative.py` (Lines 9–82)](file:///Users/devakrishnak/final/clarusav/explain/narrative.py#L9-L82): `NarrativeExplainer.generate_narrative_cards` implements deterministic branch rules for section entropy ($\ge 6.8$ bits or $\le 4.0$ bits), watchlist APIs ($> 0$), timestamp anomalies ($== 1.0$), and sparse imports ($< 5$).

---

### 8. SHAP-Guided Counterfactual Perturbation Search
Computes minimal feature perturbation $x_j \to x'_j$ along the pivotal SHAP feature dimension required to shift prediction into the uncertain band:

* **Exact Implementation**:
  - [`clarusav/explain/counterfactual.py` (Lines 36–118)](file:///Users/devakrishnak/final/clarusav/explain/counterfactual.py#L36-L118): `CounterfactualExplainer.generate_counterfactual` searches semantic grid intervals for the top-ranking feature until $p(x') \in [\tau_l, \tau_h)$.

---

### 9. Classification Quality & Calibration Metrics (Paper Table VI)
Standard performance metrics and Brier score loss:

$$\text{Brier} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2, \quad F_1 = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}, \quad \text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

* **Exact Implementation**:
  - [`clarusav/models/trainer.py` (Lines 25–54)](file:///Users/devakrishnak/final/clarusav/models/trainer.py#L25-L54): `compute_metrics` evaluates precision, recall, F1, FPR, Brier score (`brier_score_loss`), and ROC AUC (`roc_auc_score`).

---

### 10. Sandbox Behavioral Heuristics & Fail-Closed Invariant (Paper Table V)
Behavioral rules applied to Wine trace logs inside ephemeral Docker containers:

* **Exact Implementation**:
  - [`clarusav/sandbox/rules.py` (Lines 44–65)](file:///Users/devakrishnak/final/clarusav/sandbox/rules.py#L44-L65): Fail-Closed Invariant ensuring timeouts, container faults, or zero observed events emit `"UNRESOLVED - manual review"`, never benign clearance.
  - [`clarusav/sandbox/rules.py` (Lines 67–86)](file:///Users/devakrishnak/final/clarusav/sandbox/rules.py#L67-L86): Bulk file modification burst detection ($\ge 20$ writes at $\ge 5.0/\text{sec}$).
  - [`clarusav/sandbox/rules.py` (Lines 88–106)](file:///Users/devakrishnak/final/clarusav/sandbox/rules.py#L88-L106): Ransomware mass-rename and extension mutation rule ($\ge 5$ renames).
  - [`clarusav/sandbox/rules.py` (Lines 108–134)](file:///Users/devakrishnak/final/clarusav/sandbox/rules.py#L108-L134): High-risk child process spawning detection (`cmd.exe`, `powershell.exe`, `wscript.exe`).

---

### 11. Fast-Path SHA-256 Allow/Deny Cache
Bypasses static ML inference when binary digest matches a previously convicted verdict under the active model version:

* **Exact Implementation**:
  - [`clarusav/store/cache.py` (Lines 34–57)](file:///Users/devakrishnak/final/clarusav/store/cache.py#L34-L57): `FastPathCache.get` lookup yielding sub-$0.05\text{ ms}$ response.
  - [`clarusav/store/cache.py` (Lines 59–79)](file:///Users/devakrishnak/final/clarusav/store/cache.py#L59-L79): `FastPathCache.set` persistence.

---

## Workflows & Command Reference

The complete end-to-end operation of ClarusAV is divided into 11 distinct, independently executable workflows:

### 1. Environment Setup & Health Verification Workflow
Ensure all dependencies, virtual environments, ML models, and Docker backends are healthy:

```bash
# 1. Activate the Python virtual environment
source .venv/bin/activate

# 2. Run ClarusAV environment health check (Docker, models, audit ledger, and schema)
.venv/bin/clarusav doctor

# 3. View registered PE feature schema and schema hashes
.venv/bin/clarusav features

# 4. Check CLI version
.venv/bin/clarusav --version
```

---

### 2. Automated Test Suite Workflow
Execute test suites covering entropy algorithms, static feature extraction, confidence gating, TreeSHAP explainability, and sandbox backends:

```bash
# Run all unit tests
.venv/bin/pytest tests/ -v

# Run individual test modules:
.venv/bin/python tests/test_entropy.py     # Shannon entropy computation
.venv/bin/pytest tests/test_features.py -v   # PE static feature extraction
.venv/bin/pytest tests/test_gate.py -v       # Dual-signal confidence gating
.venv/bin/pytest tests/test_explain.py -v    # TreeSHAP units & attribution
.venv/bin/pytest tests/test_sandbox.py -v    # Ephemeral Docker sandbox rules
```

---

### 3. Demo Binary Sample Generation Workflow
Create synthetic test PE files across distinct risk profiles (clean, packed, high-entropy) to test detection without live malware:

```bash
# 1. Generate benign, suspicious, and high-entropy ransomware PE samples
.venv/bin/python scripts/make_sample_pe.py

# Generated binaries in samples/:
#  - samples/benign_calc.exe    (19 KB, low entropy ~2.52 bits, clean profile)
#  - samples/suspicious_mid.exe (41 KB, moderate entropy ~5.80 bits, uncertain band)
#  - samples/malware_ransom.exe (66 KB, high entropy ~7.99 bits, packed/encrypted profile)

# 2. Inspect raw PE header characteristics without running ML inference
.venv/bin/clarusav inspect-pe samples/malware_ransom.exe
.venv/bin/clarusav inspect-pe samples/benign_calc.exe
```

---

### 4. Machine Learning Lifecycle Workflow (Train, Calibrate, Evaluate & Benchmark)
Train candidate estimators (Random Forest + XGBoost), calibrate posterior probabilities using isotonic regression, and evaluate performance:

```bash
# 1. Train models and select champion bundle
.venv/bin/clarusav train \
  --data dataset/ember_sample_train.jsonl \
  --output models/artefacts \
  --val-fraction 0.2

# 2. Evaluate calibrated model bundle on the test split
.venv/bin/clarusav eval \
  --model models/artefacts/model_bundle.joblib \
  --data dataset/ember_sample_test.jsonl

# 3. Run reproducibility benchmark suite (computes F1, precision, recall, FPR, p50/p95/p99 latency)
.venv/bin/clarusav bench \
  --data dataset/ember_sample_test.jsonl \
  --model models/artefacts/model_bundle.joblib \
  --output bench_results.csv \
  --limit 50
```

---

### 5. Detection & Threat Scanning Workflow
Scan individual files or batch directories using the calibrated confidence gate, section entropy analysis, and optional container escalation:

#### A. Interactive Shell Mode
```bash
# Start the interactive Metasploit-style shell
.venv/bin/clarusav

# (Inside the shell prompt 'clarus >'):
scan samples/malware_ransom.exe
scan samples/malware_ransom.exe --deep
scan samples/benign_calc.exe
explain samples/malware_ransom.exe
doctor
help
exit
```

#### B. Single File Static ML Scans (Sub-Millisecond Triage)
```bash
# Scan a high-entropy malicious executable
.venv/bin/clarusav scan samples/malware_ransom.exe

# Scan a benign executable
.venv/bin/clarusav scan samples/benign_calc.exe

# Scan a borderline/suspicious sample
.venv/bin/clarusav scan samples/suspicious_mid.exe
```

#### C. Deep Behavioral Scan (Container Sandbox Detonation)
Forces sample detonation inside an isolated, air-gapped Docker container with Wine emulation:
```bash
.venv/bin/clarusav scan samples/malware_ransom.exe --deep
```

#### D. Batch Directory Scan with Auto-Quarantine & Multi-Format Reporting
Scans an entire directory, automatically quarantines malicious binaries (`chmod 000`), and produces standalone HTML and SARIF reports:
```bash
.venv/bin/clarusav scan samples/ \
  --quarantine \
  --html scan_report.html \
  --sarif scan_alerts.sarif \
  --json-out scan_results.json
```

---

### 6. Explainable AI (XAI) & Counterfactual Analysis Workflow
Inspect exact game-theoretic TreeSHAP feature attributions, severity badges, plain-English narrative cards, and counterfactual boundary simulations:

```bash
# Run standalone explanation on a target sample
.venv/bin/clarusav explain samples/malware_ransom.exe
```

* **Alert Level**: 🚨 `CRITICAL`, ⚠️ `HIGH RISK`, `⚡ ELEVATED`, `✓ BENIGN`
* **Threat Shift**: Indicates whether the feature pushes towards Malicious (`▲`) or Benign (`▼`).
* **Counterfactual Simulation**: Calculates the minimal single-feature perturbation required to flip the verdict across the decision threshold.

---

### 7. Quarantine Vault Management Workflow
Manage quarantined files stored with revoked execution permissions:

```bash
# 1. List all currently quarantined files in the vault
.venv/bin/clarusav quarantine list

# 2. Restore an isolated file from quarantine (in case of false positive)
.venv/bin/clarusav quarantine restore --id <QUARANTINE_RECORD_ID>
```

---

### 8. Cryptographic Audit Trail Workflow
Review and mathematically verify the append-only SHA-256 hash-chained log to detect retroactive file tampering:

```bash
# 1. View chronological scan audit history (last 20 records)
.venv/bin/clarusav history

# 2. Mathematically verify the integrity of the SHA-256 hash chain
.venv/bin/clarusav history --verify
```

---

### 9. Real-Time Filesystem Monitoring Workflow
Monitor an incoming directory for new PE binaries with debounced auto-scanning and a live Rich terminal dashboard:

```bash
# Monitor directory and auto-quarantine detected threats in real time
.venv/bin/clarusav watch samples/ --quarantine
```

---

### 10. Disposable Docker Sandbox Setup Workflow
Build and verify the air-gapped Wine detonation sandbox container:

```bash
# 1. Build the Docker sandbox image
docker build -t clarusav-sandbox:latest -f sandbox/Dockerfile .

# 2. Test Docker daemon status with ClarusAV
.venv/bin/clarusav doctor
```

---

### 11. Conference Paper & Visual Asset Generation Workflow
Generate and compile the academic conference paper (`.docx`, `.pdf`, `.html`, `.tex`) and CLI screenshots:

```bash
# 1. Generate the IEEE 2-column Word Document (.docx)
.venv/bin/python docs/generate_docx.py

# 2. Compile the 6-page IEEE LaTeX PDF via Docker TeX Live
docker run --rm -v "$(pwd)/docs:/work" -w /work texlive/texlive pdflatex -interaction=nonstopmode conference_paper.tex

# 3. Generate high-resolution CLI screenshots (PNG & SVG)
.venv/bin/python docs/generate_cli_picture.py

# 4. Copy generated artifacts to your Downloads folder
cp docs/conference_paper.docx docs/conference_paper.pdf docs/clarusav_cli.png ~/Downloads/
```

---

## Threat Model & Security Posture

- **Host Safety**: Samples are **NEVER** executed on the host. Dynamic analysis runs exclusively within disposable ephemeral containers.
- **Strict Isolation Controls**: Ephemeral containers run with:
  - `--network none` (complete air gap)
  - `--read-only` root filesystem
  - `--cap-drop ALL`
  - `--security-opt no-new-privileges:true`
  - Strict CPU quota and memory limits (`512MB`)
  - Bounded PIDs (`64`)
  - Ephemeral scratch `tmpfs` mounts (`noexec,nosuid`)
  - Hard timeouts and unconditional destruction on completion/failure.

---

## Known Limitations

1. **Host Kernel Sharing**: Docker containers share the host Linux kernel. Hardened isolation mitigates exposure, but kernel exploits remain a theoretical vector.
2. **Wine Emulation Fidelity**: User-mode Wine emulation does not support Windows kernel drivers (`.sys`) or undocumented kernel APIs.
3. **Adversarial Perturbations**: Static PE features can be manipulated by adversaries (e.g. padding to manipulate entropy, benign import inflation).
4. **Empirical Verification Notice**: No performance or quality metrics are claimed without real execution results via `clarusav bench` on verified datasets.