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

## CLI Usage Guide

### 1. Diagnostic Health Check
```bash
clarusav doctor
```

### 2. Inspect Windows PE Features
```bash
clarusav inspect-pe path/to/binary.exe
```

### 3. Model Training & Selection
```bash
clarusav train --data dataset/ember_sample_train.jsonl --output models/artefacts
```

### 4. Model Evaluation on Test Split
```bash
clarusav eval --model models/artefacts/model_bundle.joblib --data dataset/ember_sample_test.jsonl
```

### 5. Scanning Executables
```bash
# Standard scan with confidence gating and fast-path cache
clarusav scan sample.exe

# Force deep behavioral execution in disposable sandbox
clarusav scan sample.exe --deep

# Scan directory with auto-quarantine and export reports
clarusav scan /path/to/binaries/ -q --html report.html --sarif alerts.sarif --json-out results.json
```

### 6. Explain Verdicts
```bash
clarusav explain sample.exe
```

### 7. Quarantine Vault
```bash
# List isolated binaries
clarusav quarantine list

# Restore false positive to original path
clarusav quarantine restore --id <ITEM_ID>
```

### 8. Live Directory Watch
```bash
clarusav watch /path/to/downloads -q
```

### 9. Verify Tamper-Evident Audit Trail
```bash
# View recent scan history
clarusav history

# Verify cryptographic hash chain integrity
clarusav history --verify
```

### 10. Run Benchmark Suite
```bash
clarusav bench --data dataset/ember_sample_test.jsonl --output bench_results.csv
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
