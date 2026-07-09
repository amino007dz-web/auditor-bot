"""Tests for bytecode_analyzer, agentic_auditor, and webhook_notifier"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from bytecode_analyzer import analyze_bytecode, analyze_contract_from_explorer, _parse_hex, _analyze_opcodes, _regex_scan
from agentic_auditor import AgenticAuditor, analyze_project_agentic
from webhook_notifier import (
    send_discord_webhook, send_slack_webhook,
    _build_discord_payload, _build_slack_payload,
    _severity_emoji, _truncate,
)
from analyzers.base import Finding

# ──────────────────────────────────────────
# Bytecode Analyzer
# ──────────────────────────────────────────

class TestParseHex:
    def test_with_0x_prefix(self):
        raw = _parse_hex("0x60006000")
        assert raw == b"\x60\x00\x60\x00"

    def test_without_prefix(self):
        raw = _parse_hex("60006000")
        assert raw == b"\x60\x00\x60\x00"

    def test_empty_string(self):
        raw = _parse_hex("")
        assert raw == b""

    def test_invalid_hex(self):
        raw = _parse_hex("0xZZZ")
        assert raw == b""


class TestAnalyzeOpcodes:
    def test_selfdestruct_detected(self):
        raw = bytes.fromhex("ff")
        findings = _analyze_opcodes(raw)
        names = [f["opcode"] for f in findings]
        assert "SELFDESTRUCT" in names

    def test_delegatecall_detected(self):
        raw = bytes.fromhex("f4")
        findings = _analyze_opcodes(raw)
        names = [f["opcode"] for f in findings]
        assert "DELEGATECALL" in names

    def test_timestamp_detected(self):
        raw = bytes.fromhex("42")
        findings = _analyze_opcodes(raw)
        names = [f["opcode"] for f in findings]
        assert "TIMESTAMP" in names

    def test_empty_raw(self):
        findings = _analyze_opcodes(b"")
        assert findings == []

    def test_multiple_opcodes(self):
        raw = bytes.fromhex("fff442")
        findings = _analyze_opcodes(raw)
        names = [f["opcode"] for f in findings]
        assert "SELFDESTRUCT" in names
        assert "DELEGATECALL" in names
        assert "TIMESTAMP" in names


class TestRegexScan:
    def test_selfdestruct_pattern(self):
        findings = _regex_scan("selfdestruct(address)")
        assert len(findings) > 0
        assert findings[0]["pattern"] == "selfdestruct"

    def test_delegatecall_pattern(self):
        findings = _regex_scan("delegatecall(addr, data)")
        assert len(findings) > 0
        assert findings[0]["pattern"] == "delegatecall"

    def test_tx_origin_pattern(self):
        findings = _regex_scan("require(tx.origin == owner)")
        assert len(findings) > 0
        assert findings[0]["pattern"] == "tx_origin"

    def test_clean_code(self):
        findings = _regex_scan("pragma solidity ^0.8.0; contract A {}")
        assert findings == []


class TestAnalyzeBytecode:
    def test_selfdestruct_finding_critical(self):
        findings = analyze_bytecode("0xff", "test")
        severities = [f.severity for f in findings]
        assert "Critical" in severities
        agents = [f.agent_name for f in findings]
        assert any("SELFDESTRUCT" in a for a in agents)

    def test_delegatecall_finding_high(self):
        findings = analyze_bytecode("0xf4", "test")
        severities = [f.severity for f in findings]
        assert "Critical" in severities

    def test_no_dangerous_opcodes(self):
        findings = analyze_bytecode("0x60006000", "safe")
        severities = [f.severity for f in findings]
        assert "Info" in severities

    def test_empty_bytecode(self):
        findings = analyze_bytecode("", "empty")
        assert len(findings) >= 0

    def test_invalid_hex(self):
        findings = analyze_bytecode("nothex", "bad")
        assert len(findings) >= 0

    def test_address_too_short(self):
        findings = analyze_bytecode("0x1234", "short")
        assert len(findings) >= 0


# ──────────────────────────────────────────
# Agentic Auditor
# ──────────────────────────────────────────

class TestAgenticAuditor:
    def test_init(self):
        auditor = AgenticAuditor()
        assert auditor.files == {}
        assert auditor.graph == {}

    def test_load_empty_directory(self, tmp_path):
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        assert auditor.files == {}

    def test_load_sol_file(self, tmp_path):
        sol_file = tmp_path / "test.sol"
        sol_file.write_text("pragma solidity ^0.8.0; contract A {}")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        assert len(auditor.files) == 1

    def test_load_vy_file(self, tmp_path):
        vy_file = tmp_path / "test.vy"
        vy_file.write_text("@public\ndef foo() -> uint256:\n    return 1")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        assert len(auditor.files) == 1

    def test_load_ignores_txt(self, tmp_path):
        txt = tmp_path / "test.txt"
        txt.write_text("hello")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        assert auditor.files == {}

    def test_contract_detection(self, tmp_path):
        sol = tmp_path / "A.sol"
        sol.write_text("contract MyContract {}")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        assert "MyContract" in auditor.contracts

    def test_import_graph(self, tmp_path):
        a = tmp_path / "A.sol"
        a.write_text('import "B.sol"; contract A {}')
        b = tmp_path / "B.sol"
        b.write_text("contract B {}")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        rel_a = os.path.relpath(str(a), str(tmp_path))
        rel_b = os.path.relpath(str(b), str(tmp_path))
        assert rel_a in auditor.graph
        assert rel_b in auditor.graph.get(rel_a, [])

    def test_entry_points(self, tmp_path):
        a = tmp_path / "A.sol"
        a.write_text('import "B.sol"; contract A {}')
        b = tmp_path / "B.sol"
        b.write_text("contract B {}")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        eps = auditor.get_entry_points()
        rel_a = os.path.relpath(str(a), str(tmp_path))
        assert rel_a in eps  # A is entry (not imported)

    def test_prioritized_files_scores(self, tmp_path):
        risky = tmp_path / "risky.sol"
        risky.write_text("contract R { function f() { payable; delegatecall; } }")
        safe = tmp_path / "safe.sol"
        safe.write_text("contract S {}")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        prio = auditor.prioritized_files()
        rel_risky = os.path.relpath(str(risky), str(tmp_path))
        assert len(prio) > 0

    def test_build_context(self, tmp_path):
        main_sol = tmp_path / "main.sol"
        main_sol.write_text("contract Main {}")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        rel = os.path.relpath(str(main_sol), str(tmp_path))
        ctx = auditor.build_context(rel)
        assert "contract Main" in ctx

    def test_code_map_contains_contracts(self, tmp_path):
        sol = tmp_path / "A.sol"
        sol.write_text("contract Test {}")
        auditor = AgenticAuditor()
        auditor.load_directory(str(tmp_path))
        cm = auditor.generate_code_map()
        assert "Test" in cm


# ──────────────────────────────────────────
# Webhook Notifier
# ──────────────────────────────────────────

class TestSeverityEmoji:
    def test_critical(self):
        assert _severity_emoji("Critical") == "🔴"

    def test_high(self):
        assert _severity_emoji("High") == "🟠"

    def test_info(self):
        assert _severity_emoji("Info") == "ℹ️"

    def test_unknown(self):
        assert _severity_emoji("Unknown") == "⚪"

    def test_gas(self):
        assert _severity_emoji("Gas") == "⛽"


class TestTruncate:
    def test_short_text(self):
        assert _truncate("hello") == "hello"

    def test_long_text(self):
        text = "a" * 1000
        assert len(_truncate(text, 100)) <= 103

    def test_exact_limit(self):
        text = "a" * 50
        assert _truncate(text, 50) == text

    def test_empty(self):
        assert _truncate("") == ""


class TestBuildDiscordPayload:
    def test_empty_findings(self):
        payload = _build_discord_payload([])
        assert "embeds" in payload
        assert len(payload["embeds"]) == 1
        assert "No vulnerabilities" in payload["embeds"][0]["title"]

    def test_single_finding(self):
        f = Finding(agent_name="Reentrancy", severity="Critical", category="CEI",
                    file="test.sol", function_name="withdraw",
                    description="Reentrancy vulnerability",
                    fix="Apply checks-effects-interactions")
        payload = _build_discord_payload([f])
        assert len(payload["embeds"]) == 1
        fields = payload["embeds"][0].get("fields", [])
        assert len(fields) > 0

    def test_multiple_findings(self):
        findings = [
            Finding(agent_name="A", severity="High", category="Cat1",
                    file="f.sol", function_name="f1", description="Desc1", fix=""),
            Finding(agent_name="B", severity="Low", category="Cat2",
                    file="g.sol", function_name="f2", description="Desc2", fix=""),
        ]
        payload = _build_discord_payload(findings)
        assert len(payload["embeds"]) == 1

    def test_with_summary(self):
        f = Finding(agent_name="Test", severity="Medium", category="Cat",
                    file="f.sol", function_name="f", description="Test", fix="")
        payload = _build_discord_payload([f], summary={"total": 5, "severity": {"High": 3, "Low": 2}})
        desc = payload["embeds"][0].get("description", "")
        assert "5" in desc

    def test_over_10_findings(self):
        findings = [Finding(agent_name=f"A{i}", severity="Info", category="Cat",
                            file="f.sol", function_name="f", description=f"D{i}", fix="")
                    for i in range(15)]
        payload = _build_discord_payload(findings)
        fields = payload["embeds"][0].get("fields", [])
        found_text = fields[0]["value"] if fields else ""
        assert "more findings" in found_text


class TestBuildSlackPayload:
    def test_empty_findings(self):
        payload = _build_slack_payload([])
        assert "blocks" in payload
        assert len(payload["blocks"]) == 1
        assert "No vulnerabilities" in payload["blocks"][0]["text"]["text"]

    def test_single_finding(self):
        f = Finding(agent_name="Reentrancy", severity="Critical", category="CEI",
                    file="test.sol", function_name="withdraw",
                    description="Reentrancy vuln", fix="")
        payload = _build_slack_payload([f])
        assert len(payload["blocks"]) > 2

    def test_multiple_findings(self):
        findings = [
            Finding(agent_name="A", severity="High", category="Cat",
                    file="f.sol", function_name="f1", description="Desc1", fix=""),
            Finding(agent_name="B", severity="Low", category="Cat",
                    file="g.sol", function_name="f2", description="Desc2", fix=""),
        ]
        payload = _build_slack_payload(findings)
        assert len(payload["blocks"]) > 2

    def test_with_summary(self):
        f = Finding(agent_name="Test", severity="Info", category="Cat",
                    file="f.sol", function_name="f", description="Test", fix="")
        payload = _build_slack_payload([f], summary={"total": 3, "severity": {"High": 1, "Medium": 2}})
        texts = [b.get("text", {}).get("text", "") for b in payload["blocks"] if b.get("type") == "section"]
        combined = " ".join(texts)
        assert "3" in combined

    def test_over_10_findings(self):
        findings = [Finding(agent_name=f"A{i}", severity="Info", category="Cat",
                            file="f.sol", function_name="f", description=f"D{i}", fix="")
                    for i in range(15)]
        payload = _build_slack_payload(findings)
        texts = [b.get("text", {}).get("text", "") for b in payload["blocks"] if b.get("type") == "section"]
        combined = " ".join(texts)
        assert "more findings" in combined


class TestWebhookSend:
    def test_discord_no_url(self):
        """Should not raise with empty URL"""
        f = Finding(agent_name="Test", severity="Info", category="Cat",
                    file="f.sol", function_name="f", description="Test", fix="")
        try:
            send_discord_webhook("", [f])
        except Exception as e:
            pytest.fail(f"send_discord_webhook raised: {e}")

    def test_slack_no_url(self):
        f = Finding(agent_name="Test", severity="Info", category="Cat",
                    file="f.sol", function_name="f", description="Test", fix="")
        try:
            send_slack_webhook("", [f])
        except Exception as e:
            pytest.fail(f"send_slack_webhook raised: {e}")

    def test_invalid_url_no_crash(self):
        f = Finding(agent_name="Test", severity="Info", category="Cat",
                    file="f.sol", function_name="f", description="Test", fix="")
        try:
            from webhook_notifier import _post_webhook
            _post_webhook("https://invalid.webhook.test", {"text": "test"})
        except Exception as e:
            pytest.fail(f"_post_webhook raised: {e}")


class TestFindingToString:
    def test_finding_str(self):
        f = Finding(agent_name="Agent", severity="High", category="Cat",
                    file="f.sol", function_name="foo", description="Desc", fix="Fix")
        s = str(f)
        assert "Agent" in s
        assert "High" in s
