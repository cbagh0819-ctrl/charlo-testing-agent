"""
Unit tests for CHARLO Dedicated Bug Finder Engine.
Tests software defect detection across Web, Windows EXE, and Android APK targets.
"""

import pytest
from charlo.core.models import (
    TargetType,
    CheckStatus,
    Severity,
    ScanTarget,
)
from charlo.analyzers.bug_finder import (
    BugFinder,
    WebBugFinder,
    EXEBugFinder,
    APKBugFinder,
)


def test_web_stack_trace_detection():
    # Test Python traceback detection
    py_traceback = """
    <html><body>
    <h1>Internal Error</h1>
    <pre>
    Traceback (most recent call last):
      File "/app/views.py", line 42, in get_profile
        user = User.objects.get(id=user_id)
    DoesNotExist: User matching query does not exist.
    </pre>
    </body></html>
    """
    findings = WebBugFinder.audit({}, "https://test.example.com", html_content=py_traceback, probe_network=False)
    crash_finding = next(f for f in findings if f.check_id == "BUG-WEB-003")
    assert crash_finding.status == CheckStatus.FAILED
    assert crash_finding.severity == Severity.CRITICAL
    assert "Python / Django / Flask" in crash_finding.evidence


def test_web_form_defects_detection():
    # Test form missing CSRF and password without autocomplete
    html = """
    <html>
    <head><title>Login</title><meta name="viewport" content="width=device-width"></head>
    <body>
    <form action="" method="POST">
        <input type="text" name="user">
        <input type="password" name="pass">
        <button type="submit">Login</button>
    </form>
    </body>
    </html>
    """
    findings = WebBugFinder.audit({}, "https://test.example.com/login", html_content=html, probe_network=False)
    form_finding = next(f for f in findings if f.check_id == "BUG-WEB-002")
    assert form_finding.status == CheckStatus.FAILED
    assert "without anti-CSRF" in form_finding.evidence
    assert "missing 'action'" in form_finding.evidence
    assert "autocomplete" in form_finding.evidence


def test_web_semantic_and_mixed_content_defects():
    # Test missing viewport and mixed content
    html = """
    <html>
    <head></head>
    <body>
        <h1>Title 1</h1>
        <h1>Title 2</h1>
        <script src="http://insecure-cdn.example.com/analytics.js"></script>
        <img src="http://insecure-cdn.example.com/banner.png">
    </body>
    </html>
    """
    findings = WebBugFinder.audit({}, "https://secure.example.com", html_content=html, probe_network=False)
    
    # Check semantic defects
    sem_finding = next(f for f in findings if f.check_id == "BUG-WEB-005")
    assert sem_finding.status == CheckStatus.WARNING
    assert "Missing or empty <title>" in sem_finding.evidence
    assert "viewport" in sem_finding.evidence

    # Check mixed content
    mixed_finding = next(f for f in findings if f.check_id == "BUG-WEB-006")
    assert mixed_finding.status == CheckStatus.FAILED
    assert mixed_finding.severity == Severity.HIGH


def test_exe_resource_leak_detection():
    # Context with CreateFileW and HeapAlloc but no CloseHandle or HeapFree
    context = {
        "imported_functions": ["CreateFileW", "ReadFile", "HeapAlloc", "ExitProcess"],
        "has_security_cookie": True,
        "is_64bit": True,
        "is_cfg_enabled": True,
        "has_embedded_manifest": True,
        "embedded_manifest_str": "Microsoft.Windows.Common-Controls dpiAware supportedOS",
    }
    findings = EXEBugFinder.audit(context, "C:\\Windows\\notepad.exe")
    leak_finding = next(f for f in findings if f.check_id == "BUG-EXE-001")
    assert leak_finding.status == CheckStatus.FAILED
    assert leak_finding.severity == Severity.HIGH
    assert "File / Device Handle Leak Risk" in leak_finding.evidence
    assert "Heap Memory Block Leak Risk" in leak_finding.evidence


def test_exe_banned_functions_detection():
    # Context importing banned strcpy and sprintf
    context = {
        "imported_functions": ["strcpy", "sprintf", "CloseHandle", "HeapFree"],
        "has_security_cookie": True,
        "is_64bit": True,
        "is_cfg_enabled": True,
        "has_embedded_manifest": True,
        "embedded_manifest_str": "Microsoft.Windows.Common-Controls dpiAware supportedOS",
    }
    findings = EXEBugFinder.audit(context, "C:\\Test\\vulnerable.exe")
    banned_finding = next(f for f in findings if f.check_id == "BUG-EXE-002")
    assert banned_finding.status == CheckStatus.FAILED
    assert banned_finding.severity == Severity.HIGH
    assert "strcpy" in banned_finding.evidence
    assert "sprintf" in banned_finding.evidence


def test_exe_missing_guards_and_manifest():
    context = {
        "imported_functions": ["CloseHandle"],
        "has_security_cookie": False,
        "is_64bit": False,
        "is_safeseh_enabled": False,
        "is_cfg_enabled": False,
        "has_embedded_manifest": False,
    }
    findings = EXEBugFinder.audit(context, "C:\\Test\\legacy.exe")
    
    guard_finding = next(f for f in findings if f.check_id == "BUG-EXE-004")
    assert guard_finding.status == CheckStatus.FAILED
    assert "Missing /GS" in guard_finding.evidence
    assert "SafeSEH" in guard_finding.evidence

    manifest_finding = next(f for f in findings if f.check_id == "BUG-EXE-005")
    assert manifest_finding.status == CheckStatus.WARNING


def test_apk_bug_checks():
    context = {
        "target_sdk": 33,
        "manifest_strings": ["intent-filter", "MainActivity"],  # missing exported
        "has_dynamic_code_loading": True,
    }
    findings = APKBugFinder.audit(context, "test.apk")
    
    # Reflection hazard
    refl_finding = next(f for f in findings if f.check_id == "BUG-APK-003")
    assert refl_finding.status == CheckStatus.WARNING
    assert "DexClassLoader" in refl_finding.evidence

    # Android 12+ export defect
    intent_finding = next(f for f in findings if f.check_id == "BUG-APK-004")
    assert intent_finding.status == CheckStatus.FAILED
    assert "INSTALL_PARSE_FAILED_MANIFEST_MALFORMED" in intent_finding.evidence


def test_unified_bug_finder_coordinator():
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://example.org",
        display_name="example.org",
    )
    context = {
        "html_content": "<html><head><title>Test</title><meta name='viewport' content='width=device-width'></head><body><h1>Heading</h1></body></html>"
    }
    bugs = BugFinder.find_bugs(target, context, probe_network=False)
    assert len(bugs) == 6
    assert all(b.is_bug for b in bugs)


def test_engine_run_bug_finder_mode():
    from charlo.core.engine import ScanEngine
    res = ScanEngine.run_bug_finder("C:\\Windows\\notepad.exe")
    assert res is not None
    assert all(f.check_id.startswith("BUG-") for f in res.findings)
    assert len(res.findings) == 5

