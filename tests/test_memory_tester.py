"""
Unit and integration tests for Memory Leak, OS Handle Exhaustion & Resource Leak Testing Engine.
"""

import pytest
from charlo.core.models import ScanTarget, TargetType, CheckFinding, CheckStatus, Severity
from charlo.core.engine import ScanEngine
from charlo.analyzers.memory_tester import (
    MemoryLeakTester, ResourceLeakDefect, MemoryProfileMetrics, MemoryLeakReport
)
from charlo.reporting.html_reporter import HTMLReporter


def test_memory_profile_metrics_dataclass():
    """Verify MemoryProfileMetrics properties and serialization."""
    metrics = MemoryProfileMetrics(
        initial_memory_mb=50.0,
        peak_working_set_mb=120.0,
        post_gc_retained_mb=80.0,
        memory_growth_delta_mb=70.0,
        active_handle_count=500,
        peak_handle_count=1200,
        gdi_objects_count=350,
        detached_nodes_or_contexts=20,
        projected_leak_rate_mb_hr=12.5,
    )
    d = metrics.to_dict()
    assert d["initial_memory_mb"] == 50.0
    assert d["peak_working_set_mb"] == 120.0
    assert d["peak_handle_count"] == 1200
    assert d["projected_leak_rate_mb_hr"] == 12.5


def test_memory_leak_tester_exe_target():
    """Verify MemoryLeakTester on desktop .exe targets evaluates handles and GDI objects."""
    target = ScanTarget(
        target_type=TargetType.EXE,
        target_path="C:/tools/desktop_app.exe",
        display_name="Desktop App"
    )
    report = MemoryLeakTester.run_tests(target)
    assert isinstance(report, MemoryLeakReport)
    assert report.target_name == "Desktop App"
    assert report.target_type == "exe"
    assert report.metrics.active_handle_count > 0
    assert report.metrics.gdi_objects_count > 0
    assert report.total_checks >= 4
    assert any("Working Set" in d.category or "Heap" in d.category for d in report.defects)
    assert any("Handle" in d.category for d in report.defects)
    assert any("GDI" in d.category for d in report.defects)


def test_memory_leak_tester_apk_target():
    """Verify MemoryLeakTester on Android .apk targets checks Activity context and coroutines."""
    target = ScanTarget(
        target_type=TargetType.APK,
        target_path="C:/builds/mobile_app.apk",
        display_name="Mobile App"
    )
    report = MemoryLeakTester.run_tests(target)
    assert isinstance(report, MemoryLeakReport)
    assert report.target_type == "apk"
    assert report.total_checks >= 4
    assert any("Activity Context" in d.category for d in report.defects)
    assert any(d.defect_id == "MEM-CTX-001" for d in report.defects)


def test_memory_leak_tester_web_target():
    """Verify MemoryLeakTester on web targets checks detached DOM nodes and WebSockets."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://dashboard.enterprise.com",
        display_name="Enterprise Dashboard"
    )
    report = MemoryLeakTester.run_tests(target)
    assert isinstance(report, MemoryLeakReport)
    assert report.target_type == "web"
    assert report.metrics.detached_nodes_or_contexts > 0
    assert any("Detached DOM" in d.category for d in report.defects)
    assert any("MEM-DOM-001" == d.defect_id for d in report.defects)


def test_memory_leak_diagnostic_script_compilation():
    """Verify generated diagnostic script compiles as syntactically valid Python code."""
    target = ScanTarget(
        target_type=TargetType.EXE,
        target_path="C:/apps/worker.exe",
        display_name="Worker"
    )
    report = MemoryLeakTester.run_tests(target)
    script = report.diagnostic_script
    assert "psutil" in script
    assert "memory_info()" in script

    # Syntax compile check
    compiled = compile(script, "<string>", "exec")
    assert compiled is not None


def test_memory_leak_copiable_markdown():
    """Verify generated executive deliverable markdown is formatted cleanly."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://portal.bank.org",
        display_name="Bank Portal"
    )
    report = MemoryLeakTester.run_tests(target)
    md = report.copiable_client_markdown
    assert "CHARLO TESTING AGENT - PROFESSIONAL MEMORY & RESOURCE LEAK REPORT" in md
    assert "Bank Portal" in md
    assert "Stability Score:" in md
    assert "RESOURCE TELEMETRY & RUNAWAY METRICS" in md
    assert "DETAILED DEFECT MATRIX" in md


def test_memory_leak_html_reporter():
    """Verify HTMLReporter generates a full standalone report for memory leaks."""
    target = ScanTarget(
        target_type=TargetType.EXE,
        target_path="C:/apps/suite.exe",
        display_name="Enterprise Suite"
    )
    report = MemoryLeakTester.run_tests(target)
    html = HTMLReporter.generate_memory_report(report.to_dict())
    assert "<!DOCTYPE html>" in html
    assert "Enterprise Suite" in html
    assert "MEMORY & RESOURCE LEAK AUDIT" in html
    assert "Stability Score" in html
    assert "Resource Telemetry & Runaway Heap Profile" in html


def test_scan_engine_e2e_memory_integration():
    """Verify ScanEngine executes memory audit step and saves metadata."""
    engine = ScanEngine()
    result = engine.run_scan("https://example.com")
    assert result.target is not None
    assert "memory_report" in result.target.metadata
    mem_data = result.target.metadata["memory_report"]
    assert mem_data["total_checks"] >= 4
    assert mem_data["memory_stability_score"] > 0
    assert "metrics" in mem_data
    assert len(mem_data["defects"]) >= 4
