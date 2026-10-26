"""Model Context Protocol (MCP) Server for ClarusAV.
Allows Claude Desktop and Claude Code to natively inspect, scan, explain, and detonate PE files.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from clarusav import __version__
from clarusav.config import load_config
from clarusav.explain.claude import ClaudeThreatAdvisor
from clarusav.explain.counterfactual import CounterfactualExplainer
from clarusav.explain.explainer import TreeSHAPExplainer
from clarusav.explain.narrative import NarrativeExplainer
from clarusav.features.extractor import LivePEFeatureExtractor
from clarusav.features.registry import default_registry
from clarusav.models.bundle import ModelBundle
from clarusav.store.audit import AuditLog


def get_default_bundle() -> ModelBundle | None:
    candidates = [
        Path("models/artefacts/model_bundle.joblib"),
        Path(os.path.expanduser("~/final/models/artefacts/model_bundle.joblib")),
        Path("/tmp/clarusav/model_bundle.joblib"),
    ]
    for c in candidates:
        if c.is_file():
            return ModelBundle.load(c)
    return None


class ClarusAVMCPServer:
    """Stdio-based JSON-RPC 2.0 Model Context Protocol Server for ClarusAV."""

    TOOLS = [
        {
            "name": "clarusav_doctor",
            "description": "Run ClarusAV system diagnostic health checks (engine, feature registry, model bundle, sandbox backend).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "clarusav_inspect_pe",
            "description": "Extract raw 6-dimensional feature vector and PE header properties from a Windows executable.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute or relative path to the Windows PE binary (.exe/.dll)",
                    }
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "clarusav_scan_pe",
            "description": "Perform full machine learning threat triage on a Windows PE file using calibrated models, confidence gating, and TreeSHAP explainability.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the Windows PE binary to scan",
                    },
                    "quarantine": {
                        "type": "boolean",
                        "description": "Automatically isolate malicious files with chmod 000 in the quarantine vault",
                        "default": False,
                    },
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "clarusav_explain",
            "description": "Generate exact TreeSHAP feature attributions, plain-English narrative cards, and counterfactual boundary simulations for a binary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the Windows PE binary",
                    }
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "clarusav_verify_audit",
            "description": "Cryptographically verify the integrity of the append-only SHA-256 hash-chained audit ledger to detect tampering.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "clarusav_ask_claude",
            "description": "Generate an executive SOC threat advisory and synthesized YARA rule for a binary using Claude intelligence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the Windows PE binary",
                    },
                    "question": {
                        "type": "string",
                        "description": "Specific threat inquiry or question for Claude",
                        "default": "",
                    },
                },
                "required": ["file_path"],
            },
        },
    ]

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "clarusav-mcp", "version": __version__},
                    "capabilities": {"tools": {}},
                },
            }

        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": self.TOOLS}}

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            try:
                res_text = self.execute_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": res_text}]},
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": str(e)},
                }

        elif method == "notifications/initialized":
            return None

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        }

    def execute_tool(self, name: str, args: dict[str, Any]) -> str:
        if name == "clarusav_doctor":
            from clarusav.cli.doctor import run_diagnostics

            cfg = load_config()
            results = run_diagnostics(cfg)
            res_dict = [{"component": r.component, "status": r.status, "details": r.details} for r in results]
            return json.dumps({"diagnostics": res_dict}, indent=2)

        elif name == "clarusav_inspect_pe":
            path = Path(args["file_path"])
            if not path.is_file():
                return f"Error: File not found: {path}"
            extractor = LivePEFeatureExtractor()
            feats = extractor.extract_from_file(path)
            return json.dumps({"target": str(path), "features": feats}, indent=2)

        elif name == "clarusav_scan_pe":
            path = Path(args["file_path"])
            if not path.is_file():
                return f"Error: File not found: {path}"
            bundle = get_default_bundle()
            if not bundle:
                return "Error: Model bundle not found. Please run 'clarusav train' first."

            from clarusav.cli.main import _scan_single_file

            res = _scan_single_file(path, bundle=bundle, force_deep=False, auto_quarantine=args.get("quarantine", False))
            return json.dumps(res, indent=2)

        elif name == "clarusav_explain":
            path = Path(args["file_path"])
            if not path.is_file():
                return f"Error: File not found: {path}"
            bundle = get_default_bundle()
            if not bundle:
                return "Error: Model bundle not found."

            import numpy as np

            extractor = LivePEFeatureExtractor()
            feats = extractor.extract_from_file(path)
            x_vec = np.array([feats[n] for n in bundle.feature_names], dtype=np.float64)
            explainer = TreeSHAPExplainer(model=bundle.model, model_type=bundle.selected_model_type, feature_names=bundle.feature_names)
            expl = explainer.explain_instance(x_vec, sample_id=path.name, top_k=6)
            narratives = NarrativeExplainer.generate_narrative_cards(expl)
            cf = CounterfactualExplainer.generate_counterfactual(bundle, x_vec, expl)

            return json.dumps(
                {
                    "target": str(path),
                    "base_value": expl.base_value,
                    "output_value": expl.output_value,
                    "top_features": [f.to_dict() for f in expl.top_features],
                    "narratives": narratives,
                    "counterfactual": cf.to_dict() if cf else None,
                },
                indent=2,
            )

        elif name == "clarusav_verify_audit":
            cfg = load_config()
            log = AuditLog(cfg.paths.audit_log_path)
            valid, msg, count = log.verify()
            return json.dumps({"verified": valid, "details": msg, "count": count}, indent=2)

        elif name == "clarusav_ask_claude":
            path = Path(args["file_path"])
            if not path.is_file():
                return f"Error: File not found: {path}"
            bundle = get_default_bundle()
            if not bundle:
                return "Error: Model bundle not found."

            from clarusav.cli.main import _scan_single_file

            res = _scan_single_file(path, bundle=bundle, force_deep=False, auto_quarantine=False)
            advisory = ClaudeThreatAdvisor.generate_advisory(res, user_prompt=args.get("question"))
            return advisory

        return f"Unknown tool: {name}"

    def run_stdio(self) -> None:
        """Run standard I/O loop reading JSON-RPC lines from stdin and writing to stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {e}"}}
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def main() -> None:
    server = ClarusAVMCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
