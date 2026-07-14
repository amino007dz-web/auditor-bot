"""Tests for file upload analysis endpoint."""
import os
import sys
import json
import io
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

os.environ["RATE_LIMIT_PER_MINUTE"] = "999"
os.environ["AUDITOR_API_KEY"] = ""
from web_ui import app

API_KEY = os.environ.get("AUDITOR_API_KEY", "")
AUTH_HEADER = {"Authorization": f"Bearer {API_KEY}"} if API_KEY else {}

MOCK_REPORT = "## Security Analysis Report\n### Summary\nNo vulnerabilities found\n"

SAFE_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeStorage {
    uint256 private value;
    function store(uint256 _value) public { value = _value; }
    function retrieve() public view returns (uint256) { return value; }
}
"""


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


class TestFileUpload:
    def test_upload_safe_sol_returns_report(self, client):
        data = {
            'file': (io.BytesIO(SAFE_CONTRACT.encode('utf-8')), 'SafeStorage.sol'),
            'analysis_type': 'audit'
        }
        rv = client.post('/api/analyze', data=data, headers=AUTH_HEADER)
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert "report" in resp

    def test_upload_empty_file_rejected(self, client):
        data = {
            'file': (io.BytesIO(b''), 'empty.sol'),
            'analysis_type': 'audit'
        }
        rv = client.post('/api/analyze', data=data, headers=AUTH_HEADER)
        assert rv.status_code == 400
        resp = json.loads(rv.data)
        assert "error" in resp

    def test_upload_no_file_rejected(self, client):
        rv = client.post('/api/analyze', data={'analysis_type': 'audit'}, headers=AUTH_HEADER)
        assert rv.status_code == 400
        resp = json.loads(rv.data)
        assert "error" in resp

    def test_upload_large_file_rejected(self, client):
        data = {
            'file': (io.BytesIO(b"x" * (5 * 1024 * 1024 + 1)), 'huge.sol'),
            'analysis_type': 'audit'
        }
        rv = client.post('/api/analyze', data=data, headers=AUTH_HEADER)
        assert rv.status_code == 413
