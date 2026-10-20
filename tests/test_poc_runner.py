"""
Unit tests for CHARLO Live Interactive PoC Exploit & Sandbox Runner.
"""

import pytest
from unittest.mock import patch, MagicMock
import urllib.error
import io

from charlo.core.poc_runner import PocRunner, PocExecutionResult


def test_poc_runner_confirmed_sql_vulnerable():
    """Verify that SQL error reflections in response body mark verification as CONFIRMED_VULNERABLE."""
    fake_body = b"Database query error: syntax error in sql near 'SELECT' at line 1"
    mock_response = MagicMock()
    mock_response.status = 500
    mock_response.getcode.return_value = 500
    mock_response.headers = {"Content-Type": "text/html", "Server": "Apache/2.4"}
    mock_response.read.return_value = fake_body
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        res = PocRunner.execute_poc(
            flaw_id="SQLI-001",
            target_url="https://audit-target.local/products?id=1'",
            method="GET",
            probe_type="sql_error"
        )

    assert isinstance(res, PocExecutionResult)
    assert res.flaw_id == "SQLI-001"
    assert res.status_code == 500
    assert res.verification_status == "CONFIRMED_VULNERABLE"
    assert "syntax error in sql" in res.analysis_summary
    assert res.response_headers.get("Server") == "Apache/2.4"
    assert "syntax error in sql" in res.response_body_preview


def test_poc_runner_confirmed_xss_probe():
    """Verify that reflection of probe tag marks target as CONFIRMED_VULNERABLE."""
    fake_body = b"<html>Search result for: <charlo_xss_probe></html>"
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.getcode.return_value = 200
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.read.return_value = fake_body
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        res = PocRunner.execute_poc(
            flaw_id="XSS-002",
            target_url="https://audit-target.local/search?q=<charlo_xss_probe>",
            method="GET",
            probe_type="xss_probe"
        )

    assert res.verification_status == "CONFIRMED_VULNERABLE"
    assert "<charlo_xss_probe>" in res.analysis_summary


def test_poc_runner_mitigated_response():
    """Verify clean response without vulnerable signature is marked as MITIGATED."""
    fake_body = b"<html>Welcome to the secure user dashboard. No errors found.</html>"
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.getcode.return_value = 200
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.read.return_value = fake_body
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        res = PocRunner.execute_poc(
            flaw_id="CHECK-CLEAN",
            target_url="https://audit-target.local/dashboard",
            method="GET",
            probe_type="sql_error"
        )

    assert res.status_code == 200
    assert res.verification_status == "MITIGATED"


def test_poc_runner_network_error_handling():
    """Verify handling of urllib network timeout/unreachable errors."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        res = PocRunner.execute_poc(
            flaw_id="ERR-001",
            target_url="https://nonexistent-server-12345.local",
            method="GET"
        )

    assert res.verification_status == "ERROR"
    assert "Connection refused" in res.analysis_summary
    assert res.status_code is None


def test_poc_execution_result_to_dict():
    """Verify PocExecutionResult serializes cleanly to dict."""
    res = PocExecutionResult(
        flaw_id="TEST-1",
        target_url="https://target.local",
        method="POST",
        status_code=201,
        latency_ms=45.2,
        request_headers={"User-Agent": "CHARLO"},
        request_body='{"test": 1}',
        response_headers={"Content-Type": "application/json"},
        response_body_preview='{"status": "ok"}',
        verification_status="MITIGATED",
        analysis_summary="Clean endpoint",
        timestamp="2026-10-20T12:00:00"
    )
    d = res.to_dict()
    assert d["flaw_id"] == "TEST-1"
    assert d["latency_ms"] == 45.2
    assert d["status_code"] == 201
