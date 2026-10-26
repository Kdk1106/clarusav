# ClarusAV — Claude Architecture & Integration Guide

> **ClarusAV**: Lightweight, Explainable, Confidence-Gated Antivirus Framework for Windows PE Binaries with Container Detonation & Cryptographic Auditing.

---

## 🤖 Claude Integration Features

ClarusAV provides two native integrations for Claude:

### 1. Claude SOC Incident Advisory & YARA Synthesis
- **CLI Commands**:
  - `clarusav scan <target.exe> --claude`: Automatically appends a Claude SOC incident response assessment, threat classification, and tailored YARA detection rule to the scan output.
  - `clarusav ask-claude <target.exe> -q "Is this section entropy consistent with ransomware?"`: Interactive threat Q&A grounded in live PE features and TreeSHAP attributions.
- **Environment Variable**:
  ```bash
  export ANTHROPIC_API_KEY="sk-ant-..."
  ```
  *(Note: If no API key is provided, ClarusAV gracefully falls back to a deterministic offline heuristic advisory.)*

### 2. Model Context Protocol (MCP) Server for Claude Desktop & Claude Code
ClarusAV implements the JSON-RPC 2.0 Model Context Protocol (MCP), allowing Claude to directly call antivirus tools on your workstation.

#### Adding ClarusAV to Claude Desktop:
Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "clarusav": {
      "command": "/Users/devakrishnak/final/.venv/bin/clarusav",
      "args": ["mcp"]
    }
  }
}
```

#### Available MCP Tools:
- `clarusav_scan_pe`: Full ML scan with confidence gating, TreeSHAP, and optional sandbox detonation.
- `clarusav_inspect_pe`: Extracts compact 6-feature vector and peak section Shannon entropy.
- `clarusav_explain`: Computes local TreeSHAP attributions, narrative cards, and counterfactuals.
- `clarusav_verify_audit`: Verifies the SHA-256 tamper-evident hash chain.
- `clarusav_doctor`: Checks system diagnostics, models, and container substrate.
- `clarusav_ask_claude`: Generates executive SOC incident advisory and YARA rules.

---

## 🏗️ Architecture Summary

ClarusAV operates as a tiered Directed Acyclic Graph (DAG):
```text
Windows PE Binary -> Fast-Path Cache -> 6-Feature Extractor (pefile) -> Calibrated XGBoost/RF -> TreeSHAP Attribution -> Dual-Signal Confidence Gate:
  p >= tau_h (0.85) and consensus -> MALICIOUS
  p <= tau_l (0.15) and consensus -> BENIGN
  Ambiguous / Model Disagreement  -> Escalate to Ephemeral Docker Sandbox (Wine) -> Behavioral Rule Engine
  Failures / Timeouts             -> Fail-Closed UNRESOLVED (Manual Review)
Final Verdict -> SHA-256 Chained Audit Ledger & 0o000 Quarantine Vault
```

---

## 🛠️ CLI & Development Workflow

### Diagnostics & Features
```bash
.venv/bin/clarusav doctor               # Health check
.venv/bin/clarusav features             # Display 6-feature schema & hash
.venv/bin/clarusav inspect-pe <file>    # Inspect PE headers & entropy
```

### Threat Scanning & Explanations
```bash
.venv/bin/clarusav scan samples/malware_ransom.exe             # Static ML scan
.venv/bin/clarusav scan samples/malware_ransom.exe --claude    # With Claude SOC advisory
.venv/bin/clarusav scan samples/malware_ransom.exe --deep      # With sandbox detonation
.venv/bin/clarusav scan samples/ --quarantine --html rep.html  # Batch directory scan
.venv/bin/clarusav explain samples/malware_ransom.exe          # TreeSHAP & counterfactuals
```

### Forensic Ledger & Vault
```bash
.venv/bin/clarusav history              # Chronological scan entries
.venv/bin/clarusav history --verify     # Cryptographic SHA-256 verification
.venv/bin/clarusav quarantine list      # Vault records (chmod 000)
```

### Benchmark & Testing
```bash
.venv/bin/clarusav bench --data dataset/ember_sample_test.jsonl --output bench_results.csv
.venv/bin/pytest tests/ -v              # Run 81 unit & integration tests
```

---

## 🔒 Critical Invariants

1. **Fail-Closed Invariant**: Sandbox errors, container timeouts, or empty behavioral traces must **ALWAYS** emit `"UNRESOLVED - manual review"`, **NEVER** benign clearance.
2. **TreeSHAP Units**: Always `log-odds` for XGBoost models and `probability` for Random Forests.
3. **Forensic Hash Chaining**: Every audit entry must compute `SHA-256(Payload || H_{k-1})`.
4. **Schema Locking**: Feature changes must update the canonical registry and re-verify `schema_hash`.
