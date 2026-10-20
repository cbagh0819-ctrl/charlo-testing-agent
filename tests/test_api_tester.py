"""
Unit and integration tests for CHARLO REST & Backend API Testing, Schema Validation & Endpoint Boundary Fuzzer.

Tests:
- API endpoint discovery & OpenAPI / Swagger spec parsing.
- REST contract schema verification (Content-Type, CORS, Method Not Allowed).
- Negative boundary fuzzing (data type violations, 500KB payload, malformed JSON, null bytes).
- Authentication, RBAC, and BOLA/IDOR security verification.
- Rate-limiting & burst throttling diagnostics.
- Error envelope & information leakage / stack trace trapping.
- Ready-to-Run Pytest script generation.
- Postman Collection v2.1.0 JSON format & schema conformance.
- Copiable corporate Markdown client deliverable generation.
- Standalone API HTML report generation via HTMLReporter.
- Engine integration verifying metadata["api_report"] persistence.
"""

import json
import pytest
from charlo.core.models import TargetType, ScanTarget, CheckFinding, CheckStatus, Severity, ScanLevel
from charlo.core.engine import ScanEngine
from charlo.analyzers.api_tester import (
    ApiTester, ApiEndpoint, ApiTestCase, ApiTestReport
)
from charlo.reporting.html_reporter import HTMLReporter


def test_api_tester_web_target_with_context():
    """Verify ApiTester generates comprehensive API audit suites for a Web target."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    context = {
        "html_content": """
        <html>
            <head><title>PMEC Campus Portal</title></head>
            <body>
                <a href="/api/v1/auth/login">Login API</a>
                <a href="/api/v1/students/records">Students API</a>
                <a href="/swagger.json">API Docs</a>
            </body>
        </html>
        """,
        "status_code": 200,
        "response_time_ms": 110,
        "cors_allow_origin": "*",
        "rate_limit_detected": False,
        "error_leak_found": False
    }
    findings = [
        CheckFinding(
            check_id="WEB-003",
            check_name="CORS Permissive Policy",
            target_type=TargetType.WEB,
            category="Security",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAILED,
            title="Permissive CORS Origin",
            description="Access-Control-Allow-Origin: * allows untrusted cross-origin access",
            affected_component="/api/v1",
            evidence="Access-Control-Allow-Origin: *",
            impact="Cross-origin data extraction",
            remediation="Restrict Access-Control-Allow-Origin to specific trusted origins"
        )
    ]

    report = ApiTester.run_tests(target, context, findings)

    assert isinstance(report, ApiTestReport)
    assert report.total_endpoints >= 4
    assert report.total_tests >= 10
    assert report.passed_tests > 0
    assert 0.0 <= report.quality_score <= 100.0

    # Check categories of test cases
    categories = set(tc.category for tc in report.test_cases)
    assert any("Contract" in cat for cat in categories)
    assert any("Boundary" in cat or "Fuzzing" in cat for cat in categories)
    assert any("Auth" in cat or "BOLA" in cat for cat in categories)
    assert any("Rate Limiting" in cat for cat in categories)
    assert any("Info Leakage" in cat or "Error" in cat for cat in categories)

    # Check test cases inside report
    assert len(report.test_cases) == report.total_tests
    for tc in report.test_cases:
        assert tc.test_id.startswith("API-")
        assert tc.endpoint != ""
        assert tc.method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        assert tc.status in ["PASSED", "FAILED", "WARNING", "SKIPPED"]
        assert tc.expected_status != ""
        assert tc.actual_status != ""
        assert tc.details != ""
        assert tc.reproduction_curl != ""
        assert any(k in tc.reproduction_curl.lower() for k in ("curl", "requests", "python"))

    # Check Ready-to-Run Pytest script
    assert "import pytest" in report.ready_to_run_python_script
    assert "import requests" in report.ready_to_run_python_script
    assert "BASE_URL" in report.ready_to_run_python_script
    assert "def test_api_" in report.ready_to_run_python_script

    # Check Postman Collection v2.1.0 format
    assert report.postman_collection_json != ""
    collection = json.loads(report.postman_collection_json)
    assert "info" in collection
    assert collection["info"]["schema"] == "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    assert "item" in collection
    assert len(collection["item"]) > 0
    assert "variable" in collection
    var_keys = [v["key"] for v in collection["variable"]]
    assert "baseUrl" in var_keys
    assert "access_token" in var_keys

    # Check Markdown deliverable
    assert "REST & BACKEND API AUDIT" in report.copiable_client_markdown
    assert "1. EXECUTIVE API SUMMARY" in report.copiable_client_markdown
    assert "2. ENDPOINT INVENTORY & ROUTE MAP" in report.copiable_client_markdown
    assert "3. DETAILED TEST EXECUTION BREAKDOWN" in report.copiable_client_markdown
    assert "4. ACTIONABLE DEFECTS" in report.copiable_client_markdown
    assert "5. AUTOMATION ARTIFACTS" in report.copiable_client_markdown


def test_api_tester_apk_and_exe_targets():
    """Verify ApiTester generates cloud API audits for APK and EXE targets."""
    target_apk = ScanTarget(
        target_type=TargetType.APK,
        target_path="app-release.apk",
        display_name="app-release.apk"
    )
    context_apk = {
        "extracted_urls": [
            "https://api.mobilebackend.io/v1/auth/login",
            "https://api.mobilebackend.io/v1/user/sync",
            "https://api.mobilebackend.io/v1/payments/checkout"
        ]
    }
    report_apk = ApiTester.run_tests(target_apk, context_apk, [])
    assert report_apk.total_endpoints >= 3
    assert report_apk.total_tests >= 10
    assert any("mobilebackend.io" in ep.path for ep in report_apk.endpoints)

    target_exe = ScanTarget(
        target_type=TargetType.EXE,
        target_path="desktop_client.exe",
        display_name="desktop_client.exe"
    )
    context_exe = {
        "extracted_urls": [
            "https://cloud.desktopapp.com/api/v2/telemetry",
            "https://cloud.desktopapp.com/api/v2/license/validate"
        ]
    }
    report_exe = ApiTester.run_tests(target_exe, context_exe, [])
    assert report_exe.total_endpoints >= 2
    assert report_exe.total_tests >= 10
    assert any("desktopapp.com" in ep.path for ep in report_exe.endpoints)


def test_api_tester_custom_openapi_spec_parsing():
    """Verify that ApiTester extracts endpoints directly when an OpenAPI spec is available."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://api.samplecorp.com",
        display_name="api.samplecorp.com"
    )
    openapi_spec = {
        "openapi": "3.0.1",
        "info": {"title": "SampleCorp Service API", "version": "1.0.0"},
        "paths": {
            "/api/v1/users": {
                "get": {
                    "summary": "List users",
                    "responses": {"200": {"description": "Success"}}
                },
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "required": ["username", "email", "age"],
                                    "properties": {
                                        "username": {"type": "string"},
                                        "email": {"type": "string"},
                                        "age": {"type": "integer"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            },
            "/api/v1/orders/{order_id}": {
                "get": {
                    "summary": "Get order by ID",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Order details"}}
                }
            }
        }
    }
    report = ApiTester.run_tests(target, {}, [], custom_spec=openapi_spec)

    paths = [ep.path for ep in report.endpoints]
    assert "/api/v1/users" in paths
    assert "/api/v1/orders/{order_id}" in paths
    assert report.total_tests >= 10


def test_api_html_report_generation():
    """Verify HTMLReporter generates standalone API report correctly."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    report = ApiTester.run_tests(target, {}, [])
    html = HTMLReporter.generate_api_report(report)

    assert "<!DOCTYPE html>" in html
    assert "REST & BACKEND API AUDIT" in html
    assert "API Quality Score" in html
    assert "API Endpoint Inventory & Route Map" in html
    assert "Postman Collection v2.1.0" in html
    assert "Ready-to-Run Python Test Script" in html
    assert "CHARLO Testing Agent" in html


def test_scan_engine_api_integration():
    """Verify ScanEngine.run_scan executes ApiTester and stores result in target.metadata."""
    engine = ScanEngine()
    result = engine.run_scan(
        target_input="https://example.com",
        target_type=TargetType.WEB,
        level=ScanLevel.BASIC
    )

    assert "api_report" in result.target.metadata
    api_report = result.target.metadata["api_report"]
    assert isinstance(api_report, dict)
    assert api_report["total_endpoints"] > 0
    assert api_report["total_tests"] > 0
    assert len(api_report["postman_collection_json"]) > 50
    assert len(api_report["ready_to_run_python_script"]) > 50
