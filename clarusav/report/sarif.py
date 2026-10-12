"""SARIF 2.1.0 report generator for ClarusAV.

Emits structured SARIF logs suitable for GitHub Code Scanning and CI/CD security dashboards.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clarusav import __version__
from clarusav.gate.engine import GateVerdict


def generate_sarif_report(
    scan_results: list[dict[str, Any]],
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Convert scan results to SARIF 2.1.0 format.

    Args:
        scan_results: List of scan result dicts with keys:
            - file_path: str
            - verdict: GateVerdict
            - score: float
            - stage: str
            - top_features: list of dicts (name, importance/shap_value)
            - sha256: str
        output_path: Optional path to write JSON.
    """
    rules: list[dict[str, Any]] = [
        {
            "id": "CLARUS-001",
            "name": "MaliciousPEBinary",
            "shortDescription": {
                "text": "PE binary classified as malicious by ClarusAV ML pipeline."
            },
            "fullDescription": {
                "text": "The Windows PE binary exhibited static and/or behavioral indicators characteristic of malware."
            },
            "defaultConfiguration": {"level": "error"},
        },
        {
            "id": "CLARUS-002",
            "name": "SuspiciousEscalatedBinary",
            "shortDescription": {
                "text": "Binary escalated to sandbox with suspicious behavioral indicators."
            },
            "fullDescription": {
                "text": "Static analysis placed binary in ambiguous confidence band; dynamic behavioral checks detected suspicious activity."
            },
            "defaultConfiguration": {"level": "warning"},
        },
        {
            "id": "CLARUS-003",
            "name": "UnresolvedManualReview",
            "shortDescription": {"text": "Binary evaluation failed or timed out during analysis."},
            "fullDescription": {
                "text": "Sandbox execution failed, timed out, or produced non-actionable telemetry. Binary requires manual analyst review."
            },
            "defaultConfiguration": {"level": "warning"},
        },
    ]

    results: list[dict[str, Any]] = []

    for item in scan_results:
        verdict = item.get("verdict")
        if isinstance(verdict, str):
            verdict_val = verdict
        elif isinstance(verdict, GateVerdict):
            verdict_val = verdict.value
        else:
            verdict_val = str(verdict)

        if verdict_val == GateVerdict.BENIGN.value:
            continue  # SARIF standard: benign items do not produce vulnerability alerts

        file_path = item.get("file_path", "unknown")
        score = item.get("score", 0.0)
        stage = item.get("stage", "unknown")
        sha256 = item.get("sha256", "")
        top_features = item.get("top_features", [])

        if verdict_val == GateVerdict.MALICIOUS.value:
            rule_id = "CLARUS-001" if stage == "static_gate" else "CLARUS-002"
            level = "error"
            message_text = (
                f"Malicious Windows PE binary detected (Score: {score:.3f}, Stage: {stage}). "
                f"Top contributing features: {', '.join([f['name'] for f in top_features[:3]])}."
            )
        else:
            rule_id = "CLARUS-003"
            level = "warning"
            message_text = (
                f"Analysis unresolved for {file_path} (Stage: {stage}). Requires manual review."
            )

        result_obj: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(file_path).as_uri()
                            if Path(file_path).is_absolute()
                            else file_path
                        }
                    }
                }
            ],
            "properties": {
                "sha256": sha256,
                "score": score,
                "stage": stage,
                "verdict": verdict_val,
                "topFeatures": top_features,
            },
        }
        results.append(result_obj)

    sarif_doc: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ClarusAV",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/clarusav/clarusav",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(UTC).isoformat(),
                    }
                ],
                "results": results,
            }
        ],
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return sarif_doc
