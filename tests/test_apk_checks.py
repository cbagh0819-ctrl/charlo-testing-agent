"""
Tests for Android APK Analyzer and Checks.
"""

import os
import tempfile
import zipfile
from charlo.core.models import TargetType, ScanTarget, CheckStatus
from charlo.analyzers.apk_analyzer import APKAnalyzer
from charlo.checks.apk_checks import (
    APKCheckDebuggable, APKCheckAllowBackup, APKCheckPermissions
)


def test_mock_apk_analysis():
    # Build a test APK (ZIP archive) containing manifest and classes.dex
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        apk_path = tmp.name

    try:
        with zipfile.ZipFile(apk_path, "w") as zf:
            # Simple text/binary manifest with debuggable and allowBackup tokens
            manifest_mock = b"\x03\x00\x08\x00" + b"android:debuggable\x00android:allowBackup\x00android.permission.READ_SMS\x00com.example.vulnerable\x00"
            zf.writestr("AndroidManifest.xml", manifest_mock)
            zf.writestr("classes.dex", b"DEX\n035\x00AIzaSyD-FakeGoogleKey35Characters12345\x00DES/ECB\x00")
            zf.writestr("META-INF/CERT.RSA", b"CN=Android Debug,O=Android,C=US")

        context = APKAnalyzer.analyze(apk_path)
        assert context["valid_apk"] is True
        assert context["file_size"] > 0
        assert context["debuggable"] is True
        assert context["is_debug_signed"] is True

        target = ScanTarget(
            target_type=TargetType.APK,
            target_path=apk_path,
            display_name="vulnerable_test.apk",
            size_bytes=context["file_size"],
            sha256=context["sha256"],
        )

        # Run Debuggable check
        dbg_check = APKCheckDebuggable()
        dbg_finding = dbg_check.run(target, context)
        assert dbg_finding.check_id == "APK-001"
        assert dbg_finding.status == CheckStatus.FAILED  # debuggable=True must fail

        # Run Dangerous permissions check
        perm_check = APKCheckPermissions()
        perm_finding = perm_check.run(target, context)
        assert perm_finding.check_id == "APK-005"
        assert perm_finding.status == CheckStatus.WARNING  # READ_SMS detected

    finally:
        if os.path.exists(apk_path):
            os.remove(apk_path)
