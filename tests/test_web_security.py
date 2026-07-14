"""Security tests for file upload and API key validation."""
import sys
import os
import json
import tempfile
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

os.environ["RATE_LIMIT_PER_MINUTE"] = "999"
os.environ["AUDITOR_API_KEY"] = ""
from web_ui import app

MOCK_REPORT = "## Security Analysis Report\n### Summary\n1 finding\n"

@pytest.fixture(autouse=True)
def _mock_llm():
    with patch("agents.pipeline._call_ollama", return_value=MOCK_REPORT):
        with patch("agents.validation.call_model_with_fallback", return_value=MOCK_REPORT):
            yield

@pytest.fixture(autouse=True)
def _no_rate_limit():
    os.environ["RATE_LIMIT_PER_MINUTE"] = "999"
    yield

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c

def _make_file_request(client, filename, content="contract C {}", analysis_type="opcodes"):
    tmpdir = tempfile.mkdtemp()
    fpath = os.path.join(tmpdir, filename)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)
    with open(fpath, "rb") as f:
        return client.post('/api/analyze', data={
            'file': (f, filename),
            'analysis_type': analysis_type
        })

class TestFileUploadSecurity:
    def test_reject_py_file(self, client):
        rv = _make_file_request(client, "test.py")
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert "error" in data

    def test_reject_image_file(self, client):
        rv = _make_file_request(client, "image.png", content="")
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert "error" in data

    def test_reject_php_file(self, client):
        rv = _make_file_request(client, "exploit.php")
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert "error" in data

    def test_accept_sol_file(self, client):
        rv = _make_file_request(client, "contract.sol")
        assert rv.status_code in (200, 500)
        if rv.status_code == 200:
            data = json.loads(rv.data)
            assert "report" in data

    def test_rate_limit_exceeded(self, client):
        os.environ["RATE_LIMIT_PER_MINUTE"] = "1"
        tmpdir = tempfile.mkdtemp()
        fpath = os.path.join(tmpdir, "rate.sol")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("contract C {}")
        for _ in range(5):
            with open(fpath, "rb") as f:
                rv = client.post('/api/analyze', data={
                    'file': (f, 'rate.sol'),
                    'analysis_type': 'opcodes'
                })
        os.environ["RATE_LIMIT_PER_MINUTE"] = "999"
        assert rv.status_code == 429
        data = json.loads(rv.data)
        assert "Rate limit" in data.get("error", "")

    def test_missing_api_key(self, client):
        import _shared
        with patch.object(_shared, '_EXPECTED_API_KEY', 'test-secret-key'):
            app.config['TESTING'] = True
            tmpdir = tempfile.mkdtemp()
            fpath = os.path.join(tmpdir, "key.sol")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("contract C {}")
            with open(fpath, "rb") as f:
                rv = client.post('/api/analyze', data={
                    'file': (f, 'key.sol'),
                    'analysis_type': 'opcodes'
                }, headers={})
            assert rv.status_code == 401
            data = json.loads(rv.data)
            assert "error" in data
