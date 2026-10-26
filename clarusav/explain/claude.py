"""Claude AI integration for ClarusAV: SOC Threat Intelligence, YARA Synthesis & Triage Advisory."""

from __future__ import annotations

import os
from typing import Any


class ClaudeThreatAdvisor:
    """Interacts with Anthropic Claude API to generate SOC incident response advisories,

    YARA detection rules, and interactive threat explanations based on ClarusAV
    TreeSHAP attributions and sandbox behavioral telemetry.
    """

    DEFAULT_MODEL = "claude-3-5-sonnet-20241022"

    @classmethod
    def is_api_key_configured(cls) -> bool:
        """Check if ANTHROPIC_API_KEY is present in the environment."""
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    @classmethod
    def generate_advisory(
        cls,
        scan_data: dict[str, Any],
        user_prompt: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ) -> str:
        """Generate an executive SOC incident response advisory.

        Uses Anthropic API if key is available, or provides a structured deterministic
        heuristic advisory if offline / no key provided.
        """
        token = api_key or os.environ.get("ANTHROPIC_API_KEY")
        target_model = model or cls.DEFAULT_MODEL

        # If key is available, call Anthropic API
        if token:
            try:
                import anthropic

                client = anthropic.Anthropic(api_key=token)
                system_prompt = (
                    "You are a Tier-3 Senior Security Operations Center (SOC) Analyst and Threat Intelligence "
                    "Specialist analyzing outputs from ClarusAV, an explainable machine learning antivirus. "
                    "You provide actionable, technically precise incident response advisories, threat hunting "
                    "hypotheses, and synthesized YARA rules based on PE characteristics, TreeSHAP feature "
                    "attributions, and dynamic container sandbox behavioral telemetry. Be concise, authoritative, "
                    "and format responses in clear GitHub Markdown."
                )

                prompt_content = cls._build_forensic_prompt(scan_data, user_prompt)
                message = client.messages.create(
                    model=target_model,
                    max_tokens=1500,
                    system=system_prompt,
                    messages=[{"role": "user", "content": prompt_content}],
                )
                return message.content[0].text
            except Exception as e:
                # Graceful fallback to offline advisory with error note
                offline = cls._generate_offline_advisory(scan_data, user_prompt)
                return (
                    f"> ⚠️ **Notice**: Live Claude API call failed ({e}). Showing offline heuristic SOC advisory:\n\n"
                    + offline
                )

        # Fallback deterministic offline template
        return cls._generate_offline_advisory(scan_data, user_prompt)

    @classmethod
    def _build_forensic_prompt(cls, scan_data: dict[str, Any], user_prompt: str | None) -> str:
        file_path = scan_data.get("file_path", "unknown")
        sha256 = scan_data.get("sha256", "unknown")
        verdict = scan_data.get("verdict", "UNKNOWN")
        score = scan_data.get("score", 0.0)
        band = scan_data.get("band_position", "UNKNOWN")
        stage = scan_data.get("stage", "static_gate")

        top_feats = scan_data.get("top_features", [])
        narratives = scan_data.get("narratives", [])
        sections = scan_data.get("sections", [])
        cf = scan_data.get("counterfactual")

        feat_str = "\n".join(
            [
                f"  - {f.get('name')}: value={f.get('value')}, shap={f.get('shap_value'):+.4f} ({f.get('direction', '')})"
                for f in top_feats
            ]
        )
        narrative_str = "\n".join([f"  - {n}" for n in narratives])
        section_str = "\n".join(
            [f"  - {s.get('name')}: size={s.get('size')}B, entropy={s.get('entropy')} bits" for s in sections]
        )

        prompt = f"""Target Executable Forensic Profile:
- File: {file_path}
- SHA-256 Digest: {sha256}
- ClarusAV Verdict: {verdict} (Calibrated Posterior: {score:.4f}, Band: {band}, Deciding Stage: {stage})

Observed TreeSHAP Feature Attributions:
{feat_str or '  (None)'}

Section Entropy Breakdown:
{section_str or '  (None)'}

Plain-English Findings:
{narrative_str or '  (None)'}
"""
        if cf:
            prompt += f"\nCounterfactual Decision Boundary:\n  {cf.get('message', '')}\n"

        if user_prompt:
            prompt += f"\nAnalyst Query: {user_prompt}\n"
        else:
            prompt += """
Please generate:
1. Executive Incident Assessment (Risk Severity, Primary Threat Vectors)
2. Forensic Explanation of Key Feature Signals (Why the model reached this conviction)
3. Tailored YARA Detection Rule for Endpoint Scanning
4. Immediate Incident Response & Threat Hunting Actions (Triage, Containment, Eradication)
"""
        return prompt

    @classmethod
    def _generate_offline_advisory(cls, scan_data: dict[str, Any], user_prompt: str | None = None) -> str:
        """Deterministic, domain-grounded SOC advisory when no live API key is provided."""
        verdict = scan_data.get("verdict", "UNKNOWN")
        score = scan_data.get("score", 0.0)
        file_path = scan_data.get("file_path", "unknown")
        sha256 = scan_data.get("sha256", "0" * 64)
        top_feats = scan_data.get("top_features", [])
        narratives = scan_data.get("narratives", [])

        # Detect high entropy
        entropy_val = 0.0
        for f in top_feats:
            if f.get("name") == "max_section_entropy":
                entropy_val = float(f.get("value", 0.0))

        is_malicious = verdict == "MALICIOUS" or score >= 0.5

        if is_malicious:
            severity = "🚨 CRITICAL / HIGH RISK"
            posture = "Malicious executable detected requiring immediate host isolation and triage."
            yara_rule_name = f"ClarusAV_Malware_{sha256[:8]}"
            playbook_actions = [
                "1. **Host Isolation**: Disconnect the impacted endpoint from the network segment immediately.",
                "2. **Process Containment**: Terminate running child processes matching executable hash or name.",
                "3. **Quarantine Verification**: Ensure executable permissions have been revoked (`chmod 000`) in ClarusAV vault.",
                "4. **Telemetry Scrape**: Collect in-memory strings, volatile execution artifacts, and scheduled task entries.",
                "5. **IOC Sweep**: Deploy the YARA rule below across fleet endpoints via EDR / osquery.",
            ]
        else:
            severity = "✓ BENIGN / LOW RISK"
            posture = "Binary exhibits benign structural characteristics and standard PE section entropy."
            yara_rule_name = f"ClarusAV_BenignBaseline_{sha256[:8]}"
            playbook_actions = [
                "1. **Allowlist Verification**: Confirm file SHA-256 against enterprise software distribution hashes.",
                "2. **No Quarantine Required**: Execution permissions may remain standard.",
                "3. **Routine Monitoring**: Log execution event to SIEM as standard baseline telemetry.",
            ]

        yara_condition = (
            f"uint16(0) == 0x5A4D and filesize == {int(scan_data.get('top_features', [{}])[0].get('value', 66024))}"
            if top_feats
            else "uint16(0) == 0x5A4D"
        )
        if entropy_val >= 6.8:
            yara_condition += " and math.entropy(0, filesize) >= 7.0"

        advisory_md = f"""### 🛡️ Claude SOC Incident Advisory for `{os.path.basename(file_path)}`

> **ClarusAV Verdict:** **{verdict}** (Calibrated Confidence Score: `{score:.4f}`)  
> **Threat Assessment:** **{severity}**  
> **SHA-256 Digest:** `{sha256}`  

---

#### 1. Executive Incident Assessment
{posture}

* **Deciding Pipeline Stage:** `{scan_data.get('stage', 'static_gate')}`
* **Confidence Band Position:** `{scan_data.get('band_position', 'UNCERTAIN_BAND')}`
* **Peak Section Entropy:** `{entropy_val:.3f} bits` {'(🚨 Packed / Encrypted payload)' if entropy_val >= 6.8 else '(Normal uncompressed code)'}

#### 2. Key Forensic Attribution Findings
"""
        for n in narratives[:4]:
            advisory_md += f"- {n}\n"

        advisory_md += f"""
#### 3. Synthesized YARA Detection Rule
```yara
rule {yara_rule_name} {{
    meta:
        description = "Autogenerated detection rule synthesized from ClarusAV TreeSHAP forensics"
        author = "ClarusAV Claude SOC Integration"
        date = "2026-10-26"
        target_sha256 = "{sha256}"
        threat_score = "{score:.4f}"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and {yara_condition}
}}
```

#### 4. Recommended Incident Response Playbook
"""
        for action in playbook_actions:
            advisory_md += f"{action}\n"

        advisory_md += "\n---\n*💡 Note: Set `export ANTHROPIC_API_KEY='your-key'` to activate live streaming conversational responses from Claude 3.5 Sonnet.*"
        return advisory_md
