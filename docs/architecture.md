# ClarusAV Architecture Specification

## 1. System Overview

ClarusAV is an explainable, container-deployed antivirus scanner for Windows Portable Executable (PE) files. It balances throughput and fidelity through a tiered gating architecture:

```
[ PE Binary ]
      │
      ▼
[ Static Feature Extraction ]
      │ (pefile / 6 compact features)
      ▼
[ ML Model Scoring ]
      │ (Random Forest / XGBoost calibrated p)
      ▼
[ TreeSHAP Attribution ]
      │
      ▼
[ Confidence Gate ]
 ├── p >= tau_h ────────► [ MALICIOUS Verdict ]
 ├── p <= tau_l ────────► [ BENIGN Verdict ]
 └── tau_l < p < tau_h ──► [ Sandbox Escalation ]
                                │
                                ▼
                   [ Disposable Docker Sandbox ]
                   (Wine + watchdog + psutil)
                                │
                                ▼
                   [ Behavioral Rule Engine ]
                                │
                                ▼
                   [ Final Verdict / UNRESOLVED ]
```

## 2. Feature Registry & Schema

The Phase 1 feature set contains 6 compact static indicators:
1. `file_size`: Total size of PE binary in bytes.
2. `section_count`: Total number of sections declared in headers.
3. `max_section_entropy`: Shannon entropy maximum across all sections ($H \in [0.0, 8.0]$).
4. `import_count`: Total count of imported API functions.
5. `suspicious_import_count`: Count of imports matching high-risk security watchlist.
6. `timestamp_anomaly`: Binary indicator (0/1) for zeroed, pre-1990, or post-dated timestamps.

Schema consistency is enforced via SHA-256 fingerprinting across train and inference pipelines.

## 3. Confidence Gating & Escalation

- Scores in the confident malicious band ($p \ge \tau_h$) are convicted statically.
- Scores in the confident benign band ($p \le \tau_l$) are cleared statically.
- Uncertain scores ($\tau_l < p < \tau_h$) or inter-model disagreements are escalated to an ephemeral container sandbox.

## 4. Threat Model & Limitations

1. **Shared Host Kernel**: Linux Docker containers share the host Linux kernel. Hardened isolation (`--network none`, `--cap-drop ALL`, `no-new-privileges`, read-only root) reduces exposure, but kernel zero-days remain an escape vector.
2. **Wine Fidelity**: Wine implements Windows APIs in user-space emulation. Malware targeting low-level NT kernel drivers or obscure undocumented APIs may behave differently in Wine than on native Windows.
3. **Adversarial Evasion**: Static feature extraction can be targeted by feature-space perturbations (e.g. section padding to alter entropy, benign import inflation).
4. **Benchmark Verification**: In accordance with project principles, no benchmark metrics are claimed until `clarusav bench` is executed against ground-truth datasets.
