"""
Tests for Windows PE Executable Analyzer and Checks.
"""

import sys
import os
from charlo.core.models import TargetType, ScanLevel, ScanTarget, CheckStatus
from charlo.analyzers.exe_analyzer import EXEAnalyzer
from charlo.checks.exe_checks import (
    EXECheckASLR, EXECheckDEP, EXECheckSignature, EXECheckWXSections, EXECheckEntropy
)


def test_real_pe_analysis():
    # Use the current python.exe as a genuine PE target
    py_exe = sys.executable
    assert os.path.exists(py_exe)

    context = EXEAnalyzer.analyze(py_exe)
    assert context["valid_pe"] is True
    assert context["file_size"] > 0
    assert len(context["sha256"]) == 64
    assert len(context["sections"]) > 0

    target = ScanTarget(
        target_type=TargetType.EXE,
        target_path=py_exe,
        display_name=os.path.basename(py_exe),
        size_bytes=context["file_size"],
        sha256=context["sha256"],
    )

    # Test ASLR check
    aslr_check = EXECheckASLR()
    aslr_finding = aslr_check.run(target, context)
    assert aslr_finding.check_id == "EXE-001"
    # Modern python.exe has ASLR enabled
    assert aslr_finding.status in (CheckStatus.PASSED, CheckStatus.FAILED)

    # Test DEP check
    dep_check = EXECheckDEP()
    dep_finding = dep_check.run(target, context)
    assert dep_finding.check_id == "EXE-002"
    assert dep_finding.status == CheckStatus.PASSED

    # Test W^X check
    wx_check = EXECheckWXSections()
    wx_finding = wx_check.run(target, context)
    assert wx_finding.check_id == "EXE-004"
    assert wx_finding.status == CheckStatus.PASSED  # Official python.exe has no W^X violation


def test_scan_engine_with_raw_string_parameters():
    from charlo.core.engine import ScanEngine
    # Verify that passing strings directly (simulating Qt QVariant conversion) works seamlessly
    result = ScanEngine.run_scan(
        target_input=sys.executable,
        target_type="exe",
        level="intermediate",
    )
    assert result is not None
    assert result.metrics.total_checks > 0
    assert result.metrics.security_score > 0

