"""
Unit and integration tests for CHARLO Performance, Stress & Concurrency Load Simulator.

Tests:
- Virtual User concurrency simulation (Smoke, Load, Stress, Soak profiles).
- Throughput calculation (RPS) and latency percentiles (Min, Avg, p50, p90, p95, p99, Max).
- Status code distribution and error rate calculations under high concurrency.
- Capacity bottleneck diagnosis and SLA compliance gating.
- Grafana k6 JavaScript load test script generation.
- Apache JMeter 5.x XML Test Plan (.jmx) generation and XML validity.
- Standalone Python concurrency runner script generation.
- Copiable executive Markdown deliverable generation.
- Standalone HTML performance report generation via HTMLReporter.
- ScanEngine integration verifying metadata["performance_report"] persistence.
"""

import xml.etree.ElementTree as ET
import pytest
from charlo.core.models import TargetType, ScanTarget, CheckFinding, CheckStatus, Severity, ScanLevel
from charlo.core.engine import ScanEngine
from charlo.analyzers.performance_tester import (
    PerformanceTester, PerformanceTestReport, LatencyPercentiles
)
from charlo.reporting.html_reporter import HTMLReporter


def test_performance_tester_standard_load_profile():
    """Verify standard load test simulation generates accurate concurrency metrics."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    context = {
        "response_time_ms": 115.0,
        "status_code": 200,
    }
    findings = []

    report = PerformanceTester.run_tests(
        target=target,
        context=context,
        findings=findings,
        profile_key="load",
        custom_vus=50,
        custom_duration=30,
    )

    assert isinstance(report, PerformanceTestReport)
    assert report.virtual_users == 50
    assert report.duration_seconds == 30.0
    assert report.total_requests >= 50
    assert report.throughput_rps > 0.0
    assert report.successful_requests > 0
    assert report.error_rate_pct <= 5.0
    assert report.performance_grade in ["A", "B", "C", "D", "F"]
    assert report.sla_status in ["COMPLIANT", "DEGRADED", "WARNING", "FAILED SLA"]

    # Verify percentiles ordering: min <= avg <= max, p50 <= p90 <= p95 <= p99
    pct = report.percentiles
    assert isinstance(pct, LatencyPercentiles)
    assert pct.min_ms > 0
    assert pct.min_ms <= pct.median_p50_ms
    assert pct.median_p50_ms <= pct.p90_ms
    assert pct.p90_ms <= pct.p95_ms
    assert pct.p95_ms <= pct.p99_ms
    assert pct.p99_ms <= pct.max_ms

    # Status codes distribution
    assert len(report.status_codes_distribution) > 0
    assert "200 OK" in report.status_codes_distribution
    assert sum(report.status_codes_distribution.values()) == report.total_requests

    # Verify Grafana k6 script
    k6 = report.k6_script_content
    assert "import http from 'k6/http';" in k6
    assert "export const options" in k6
    assert "http_req_duration" in k6
    assert "p(95)<500" in k6
    assert "https://pmec.ac.in" in k6

    # Verify Apache JMeter XML Test Plan validity
    jmx = report.jmeter_jmx_content
    assert "<?xml version=" in jmx
    assert "<jmeterTestPlan" in jmx
    assert "<ThreadGroup" in jmx
    assert "<HTTPSamplerProxy" in jmx
    # Parse XML to verify well-formed syntax
    root = ET.fromstring(jmx)
    assert root.tag == "jmeterTestPlan"
    assert root.attrib.get("properties") == "5.0"

    # Verify Python concurrent runner
    py_script = report.python_async_script
    assert "TARGET_URL = " in py_script
    assert "CONCURRENCY_VUS = 50" in py_script
    assert "concurrent.futures" in py_script
    assert "def run_benchmark():" in py_script

    # Verify Markdown deliverable
    md = report.copiable_client_markdown
    assert "CHARLO TESTING AGENT - PROFESSIONAL PERFORMANCE & LOAD AUDIT" in md
    assert "1. EXECUTIVE PERFORMANCE SUMMARY & SLA COMPLIANCE" in md
    assert "2. LATENCY PERCENTILE PROFILING" in md
    assert "3. HTTP RESPONSE STATUS DISTRIBUTION" in md
    assert "4. CAPACITY BOTTLENECK DIAGNOSIS" in md
    assert "5. AUTOMATION ARTIFACTS & TOOL INTEGRATION" in md
    assert "6. SIGN-OFF & CERTIFICATION" in md


def test_performance_tester_stress_spike_profile():
    """Verify stress test simulates high concurrency, degradation, and throttling."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://example.com",
        display_name="example.com"
    )
    context = {"response_time_ms": 250.0}

    report = PerformanceTester.run_tests(
        target=target,
        context=context,
        findings=[],
        profile_key="stress",
        custom_vus=200,
        custom_duration=20,
    )

    assert report.virtual_users == 200
    assert report.total_requests > 100
    assert report.throughput_rps > 0.0
    # Under 200 VUs, tail latency and error rate should be tracked
    assert report.percentiles.p95_ms > 0
    assert len(report.status_codes_distribution) >= 2


def test_html_reporter_generate_performance_report():
    """Verify HTMLReporter generates standalone performance and load testing report."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    report = PerformanceTester.run_tests(target, {"response_time_ms": 90.0}, [])
    html = HTMLReporter.generate_performance_report(report)

    assert "<!DOCTYPE html>" in html
    assert "PERFORMANCE & CONCURRENCY AUDIT" in html
    assert "Throughput (RPS)" in html
    assert "p95 Latency" in html
    assert "Capacity SLA Status" in html
    assert "Latency Percentile Profiling" in html
    assert "HTTP Status Code Distribution" in html
    assert "Capacity Bottleneck Diagnosis" in html
    assert "Grafana k6 Production Load Test Script" in html
    assert "Apache JMeter 5.x Test Plan XML" in html
    assert "Enterprise Performance & Reliability Engineering Engine" in html


def test_scan_engine_performance_integration():
    """Verify ScanEngine.run_scan executes PerformanceTester and stores result in target.metadata."""
    engine = ScanEngine()
    result = engine.run_scan(
        target_input="https://example.com",
        target_type=TargetType.WEB,
        level=ScanLevel.BASIC
    )

    assert "performance_report" in result.target.metadata
    perf_data = result.target.metadata["performance_report"]
    assert isinstance(perf_data, dict)
    assert perf_data["virtual_users"] >= 5
    assert perf_data["total_requests"] > 0
    assert perf_data["throughput_rps"] > 0.0
    assert "percentiles" in perf_data
    assert perf_data["percentiles"]["p95_ms"] > 0
    assert len(perf_data["k6_script_content"]) > 50
    assert len(perf_data["jmeter_jmx_content"]) > 50
