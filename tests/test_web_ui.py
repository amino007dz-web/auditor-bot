"""Web UI Tests"""
import sys
import os
import json
import tempfile
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

os.environ["RATE_LIMIT_PER_MINUTE"] = "999"
os.environ["AUDITOR_API_KEY"] = ""
from web_ui import app, REPORT_DIR, ensure_report_dir

MOCK_REPORT = """## Security Analysis Report
### Summary
1 critical finding
### Critical: Reentrancy in withdraw()
- Severity: Critical (CVSS 9.8)
- Description: The withdraw function sends ETH before updating state
- Fix: Use Checks-Effects-Interactions pattern
"""


@pytest.fixture(autouse=True)
def _no_rate_limit():
    os.environ["RATE_LIMIT_PER_MINUTE"] = "999"
    yield


@pytest.fixture(autouse=True)
def _mock_llm():
    with patch("agents.pipeline._call_ollama", return_value=MOCK_REPORT):
        with patch("agents.validation.call_model_with_fallback", return_value=MOCK_REPORT):
            yield


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


class TestWebUI:
    def test_index(self, client):
        rv = client.get('/')
        assert rv.status_code == 200
        assert b'Smart Contract Auditor' in rv.data

    def test_report_list_empty(self, client):
        rv = client.get('/report/list')
        assert rv.status_code == 200
        assert b'Smart Contract Auditor' in rv.data

    def test_analyze_no_file(self, client):
        rv = client.post('/api/analyze', data={})
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert 'error' in data

    def test_analyze_with_demo_code(self, client):
        """Simulate uploading a simple file and analyzing it"""
        ensure_report_dir()
        tmpdir = tempfile.mkdtemp()
        sol_path = os.path.join(tmpdir, "test.sol")
        with open(sol_path, "w", encoding="utf-8") as f:
            f.write("contract C { function f() public pure returns (uint) { return 1; } }")

        with open(sol_path, "rb") as f:
            rv = client.post('/api/analyze', data={
                'file': (f, 'test.sol'),
                'analysis_type': 'opcodes'
            })
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert 'report' in data
        assert 'filename' in data

        # Verify the report exists
        report_path = os.path.join(REPORT_DIR, data['filename'])
        assert os.path.isfile(report_path)
        os.remove(report_path)

    def test_analyze_audit_type(self, client):
        ensure_report_dir()
        tmpdir = tempfile.mkdtemp()
        sol_path = os.path.join(tmpdir, "vuln.sol")
        reentrancy_code = """
        pragma solidity ^0.8.0;
        contract V {
            mapping(address => uint) b;
            function w(uint a) public {
                require(b[msg.sender] >= a);
                (bool s,) = msg.sender.call{value: a}("");
                b[msg.sender] -= a;
            }
            function d() public payable { b[msg.sender] += msg.value; }
        }"""
        with open(sol_path, "w", encoding="utf-8") as f:
            f.write(reentrancy_code)

        with open(sol_path, "rb") as f:
            rv = client.post('/api/analyze', data={
                'file': (f, 'vuln.sol'),
                'analysis_type': 'audit'
            })
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert 'report' in data

    def test_download_nonexistent(self, client):
        rv = client.get('/download/nonexistent.txt')
        assert rv.status_code == 404

    def test_report_view_nonexistent(self, client):
        rv = client.get('/report/view/nonexistent.txt')
        assert rv.status_code == 404

    def test_save_and_view_report(self, client):
        ensure_report_dir()
        from main import save_report_txt
        save_report_txt("_test_web.txt", "Test Report Content")
        rv = client.get('/report/view/_test_web.txt')
        assert rv.status_code == 200
        assert b'Test Report Content' in rv.data
        os.remove(os.path.join(REPORT_DIR, "_test_web.txt"))

    def test_html_report_saved(self, client):
        ensure_report_dir()
        from web_ui import _save_html_report
        path = _save_html_report("_test.html", "Test HTML", "test", "audit")
        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Test HTML" in content
        assert "audit" in content
        os.remove(path)

    def test_report_list_after_creation(self, client):
        ensure_report_dir()
        from main import save_report_txt
        save_report_txt("_test_list.txt", "test")
        rv = client.get('/report/list')
        assert rv.status_code == 200
        assert b'_test_list' in rv.data
        os.remove(os.path.join(REPORT_DIR, "_test_list.txt"))

    def test_analyze_different_types(self, client):
        atypes = ['opcodes', 'storage', 'inheritance', 'combined']
        for atype in atypes:
            ensure_report_dir()
            sol_path = os.path.join(tempfile.mkdtemp(), f"t_{atype}.sol")
            code = "contract C { function f() public pure returns (uint) { return 1; } }"
            with open(sol_path, "w", encoding="utf-8") as f:
                f.write(code)
            with open(sol_path, "rb") as f:
                rv = client.post('/api/analyze', data={
                    'file': (f, f't_{atype}.sol'),
                    'analysis_type': atype
                })
            assert rv.status_code == 200, f"Failed for type {atype}"
            data = json.loads(rv.data)
            assert 'report' in data

    def test_download_html(self, client):
        ensure_report_dir()
        from web_ui import _save_html_report
        html_path = _save_html_report("_test_dl.html", "DL Test", "test", "audit")
        rv = client.get('/download/_test_dl.html')
        assert rv.status_code == 200
        assert b'DL Test' in rv.data
        rv.close()
        import time; time.sleep(0.1)
        try:
            os.remove(html_path)
        except PermissionError:
            pass
