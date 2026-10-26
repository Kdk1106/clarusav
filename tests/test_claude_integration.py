"""Unit and integration tests for ClarusAV Claude AI integration & MCP Server."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clarusav.explain.claude import ClaudeThreatAdvisor
from clarusav.mcp.server import ClarusAVMCPServer


def test_claude_advisor_offline_generation_malicious():
    scan_data = {
        "file_path": "samples/malware_ransom.exe",
        "sha256": "8d3f87717d819d637d9fce3ae997f162f055e12de34f91e3e5a6f756967dba32",
        "score": 1.0,
        "verdict": "MALICIOUS",
        "band_position": "MALICIOUS_BAND",
        "stage": "static_gate",
        "top_features": [
            {"name": "file_size", "value": 66024.0, "shap_value": 3.2251, "direction": "increased risk"},
            {"name": "max_section_entropy", "value": 7.994, "shap_value": 0.0, "direction": "reduced risk"},
        ],
        "narratives": [
            "Binary file size of 66,024 bytes contributed raised the score.",
            "High entropy (7.99 bits) in sections indicates packed code or cryptographic encryption.",
        ],
    }

    advisory = ClaudeThreatAdvisor.generate_advisory(scan_data)
    assert "### 🛡️ Claude SOC Incident Advisory" in advisory
    assert "MALICIOUS" in advisory
    assert "🚨 CRITICAL / HIGH RISK" in advisory
    assert "rule ClarusAV_Malware_" in advisory
    assert "Recommended Incident Response Playbook" in advisory


def test_claude_advisor_offline_generation_benign():
    scan_data = {
        "file_path": "samples/benign_calc.exe",
        "sha256": "5eaeca02e636b78f26b4b836b54f4167e657bddb2f20ea17fc345c3a1cff8273",
        "score": 0.0,
        "verdict": "BENIGN",
        "band_position": "BENIGN_BAND",
        "stage": "static_gate",
        "top_features": [
            {"name": "file_size", "value": 19024.0, "shap_value": -3.584, "direction": "reduced risk"},
            {"name": "max_section_entropy", "value": 2.522, "shap_value": 0.0, "direction": "reduced risk"},
        ],
        "narratives": [
            "Binary file size of 19,024 bytes contributed lowered the score.",
            "Low section entropy (2.52 bits) indicates uncompressed, plain executable code.",
        ],
    }

    advisory = ClaudeThreatAdvisor.generate_advisory(scan_data)
    assert "### 🛡️ Claude SOC Incident Advisory" in advisory
    assert "BENIGN" in advisory
    assert "✓ BENIGN / LOW RISK" in advisory
    assert "rule ClarusAV_BenignBaseline_" in advisory


def test_mcp_server_initialize_and_tools_list():
    server = ClarusAVMCPServer()

    # Initialize
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    init_resp = server.handle_request(init_req)
    assert init_resp["id"] == 1
    assert init_resp["result"]["serverInfo"]["name"] == "clarusav-mcp"

    # Tools list
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    list_resp = server.handle_request(list_req)
    tools = list_resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "clarusav_scan_pe" in tool_names
    assert "clarusav_inspect_pe" in tool_names
    assert "clarusav_explain" in tool_names
    assert "clarusav_verify_audit" in tool_names
    assert "clarusav_ask_claude" in tool_names


def test_mcp_server_tool_call_inspect_pe():
    server = ClarusAVMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "clarusav_inspect_pe",
            "arguments": {"file_path": "samples/benign_calc.exe"},
        },
    }
    resp = server.handle_request(req)
    assert resp["id"] == 3
    content_text = resp["result"]["content"][0]["text"]
    data = json.loads(content_text)
    assert "file_size" in data["features"]
    assert "max_section_entropy" in data["features"]


def test_mcp_server_tool_call_verify_audit():
    server = ClarusAVMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "clarusav_verify_audit", "arguments": {}},
    }
    resp = server.handle_request(req)
    assert resp["id"] == 4
    content_text = resp["result"]["content"][0]["text"]
    data = json.loads(content_text)
    assert data["verified"] is True
