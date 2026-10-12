# ClarusAV

> Lightweight, Explainable, Container-Deployed CLI Antivirus for Windows PE Files.

## Architecture

```text
PE file -> pefile feature extraction -> Random Forest / XGBoost score p -> SHAP explanation -> confidence gate:
  p >= tau_h -> MALICIOUS
  p <= tau_l -> BENIGN
  otherwise  -> escalate to disposable Docker sandbox -> behavioural check -> final verdict.
```

Every verdict carries:
- Model score ($p$)
- Band position (Malicious, Benign, or Escalated)
- Top-$k$ SHAP features
- Deciding pipeline stage
- Tamper-evident hash chain entry

Failures (container error, timeout, unobserved behavior) produce **"UNRESOLVED - manual review"**, never "benign".

## Threat Model & Security Posture

- **Host Safety**: Samples are **NEVER** executed on the host. Behavioral execution runs exclusively within disposable ephemeral containers.
- **Container Hardening**: Ephemeral containers run with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, strict memory and CPU quotas, read-only root filesystems, and temporary scratch tmpfs.
- **Fail-Closed Design**: Any sandbox failure, timeout, or ambiguity defaults to `UNRESOLVED` rather than false negative clearance.

## Known Limitations

1. **Host Kernel Sharing**: Docker containers share the host Linux kernel. While capabilities and syscalls are stripped, kernel vulnerabilities could theoretically be targeted.
2. **Wine Emulation Fidelity**: User-mode Windows API emulation in Wine does not guarantee 100% bug-for-bug fidelity with Windows kernels or kernel-mode drivers.
3. **Adversarial Perturbation**: Static PE features can be manipulated by determined adversaries (e.g. padding sections, import manipulation).
4. **Empirical Verification Notice**: *No performance, precision, recall, or FPR metrics are claimed until `clarusav bench` is executed against validated real-world datasets.*

## Core Stack

- Python 3.11
- Static Extraction: `pefile`
- Machine Learning & Calibration: `scikit-learn`, `xgboost`
- Explainability: `shap`
- CLI & TUI: `Typer`, `Rich`
- Behavioral Monitoring: `psutil`, `watchdog`
- Containerization: `docker`, Docker Compose
- Testing & Quality: `pytest`, `ruff`

## Repository Structure

```text
clarusav/
├── cli/          # Typer CLI application and commands
├── features/     # Feature registry, entropy calculator, and EMBER loader
├── models/       # Tree classifiers and probability calibration
├── explain/      # TreeSHAP and narrative explanation cards
├── gate/         # Confidence thresholding and escalation engine
├── sandbox/      # Disposable Docker sandbox backends
├── report/       # Terminal, JSON, HTML, SARIF export
├── quarantine/   # Safe isolation and restoration vault
├── watch/        # Live directory monitoring and Rich TUI
├── bench/        # Benchmark evaluation tables and metrics
└── store/        # Tamper-evident signed audit log
sandbox/          # In-container monitor agent & Dockerfile
cli/              # Containerized CLI runner
configs/          # YAML configuration files
tests/            # Test suite
docs/             # Architectural specifications
```
