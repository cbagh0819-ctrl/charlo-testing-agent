"""
Dedicated Bug Finder Security & Software Defect Checks for CHARLO Testing Agent.
Registers standalone defect detection checks for Android APKs, Windows EXEs, and Web Applications.
"""

from typing import Dict, Any
from .base import BaseCheck
from ..core.models import (
    TargetType,
    ScanLevel,
    Severity,
    CheckFinding,
    ScanTarget,
)
from ..core.registry import CheckRegistry
from ..analyzers.bug_finder import (
    WebBugFinder,
    EXEBugFinder,
    APKBugFinder,
    WebDefectHTMLParser,
)


# =============================================================================
# WEB APPLICATION BUG FINDER CHECKS (BUG-WEB-001 to BUG-WEB-006)
# =============================================================================

@CheckRegistry.register
class WebCheckBrokenLinks(BaseCheck):
    check_id = "BUG-WEB-001"
    name = "Broken Links & Navigation Dead Ends"
    description = "Audits hyperlinks for 404 dead ends, empty target attributes, and orphaned navigation routes that degrade user experience and SEO."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Software Defect / Navigation"
    default_severity = Severity.LOW
    standards = ["CWE-610", "W3C HTML5 Navigation"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        html = context.get("html_content", "")
        parser = WebDefectHTMLParser(target.target_path)
        if html:
            try:
                parser.feed(html)
            except Exception:
                pass
        return WebBugFinder._check_broken_links(target.target_path, parser.links, probe_network=True)


@CheckRegistry.register
class WebCheckFormDefects(BaseCheck):
    check_id = "BUG-WEB-002"
    name = "Form & Input Validation Defects"
    description = "Audits HTML form elements for input validation constraints, CSRF protections, unbound input controls, and binding defects."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Software Defect / Forms & Input"
    default_severity = Severity.MEDIUM
    standards = ["CWE-352", "CWE-20", "OWASP ASVS 5.1"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        html = context.get("html_content", "")
        parser = WebDefectHTMLParser(target.target_path)
        if html:
            try:
                parser.feed(html)
            except Exception:
                pass
        return WebBugFinder._check_form_defects(target.target_path, parser.forms)


@CheckRegistry.register
class WebCheckStackTraces(BaseCheck):
    check_id = "BUG-WEB-003"
    name = "Stack Trace & Unhandled Debug Exceptions"
    description = "Detects unhandled application exceptions, fatal interpreter errors, and framework debug pages returned directly to client browsers."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Software Defect / Exception Handling"
    default_severity = Severity.CRITICAL
    standards = ["CWE-209", "CWE-215", "OWASP Top 10 A05:2021"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        html = context.get("html_content", "")
        return WebBugFinder._check_stack_traces(target.target_path, html)


@CheckRegistry.register
class WebCheckAssetDefects(BaseCheck):
    check_id = "BUG-WEB-004"
    name = "Broken Media & Missing Script/Style Assets"
    description = "Audits image, script, and stylesheet tags for empty source paths, broken asset references, and accessibility attribute defects."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Software Defect / Assets"
    default_severity = Severity.LOW
    standards = ["W3C WCAG 2.1 1.1.1", "HTML5 Spec §4.8"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        html = context.get("html_content", "")
        parser = WebDefectHTMLParser(target.target_path)
        if html:
            try:
                parser.feed(html)
            except Exception:
                pass
        return WebBugFinder._check_asset_defects(target.target_path, parser.images, parser.scripts, parser.stylesheets)


@CheckRegistry.register
class WebCheckSemanticDefects(BaseCheck):
    check_id = "BUG-WEB-005"
    name = "HTML5 Semantic & Responsive Layout Defects"
    description = "Audits essential HTML5 metadata including document title, responsive viewport configuration, and heading structure."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Software Defect / Semantic & Responsive"
    default_severity = Severity.LOW
    standards = ["W3C HTML5 §4.2.2", "Google Mobile-Friendly Guidelines"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        html = context.get("html_content", "")
        parser = WebDefectHTMLParser(target.target_path)
        if html:
            try:
                parser.feed(html)
            except Exception:
                pass
        return WebBugFinder._check_semantic_defects(target.target_path, parser)


@CheckRegistry.register
class WebCheckMixedContent(BaseCheck):
    check_id = "BUG-WEB-006"
    name = "Insecure Mixed-Content Asset Defects"
    description = "Identifies cleartext HTTP assets (scripts, stylesheets, images) requested from an encrypted HTTPS parent page."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Software Defect / Content Security"
    default_severity = Severity.HIGH
    standards = ["CWE-311", "W3C Mixed Content Level 2"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        html = context.get("html_content", "")
        parser = WebDefectHTMLParser(target.target_path)
        if html:
            try:
                parser.feed(html)
            except Exception:
                pass
        return WebBugFinder._check_mixed_content(target.target_path, parser.mixed_content)


# =============================================================================
# WINDOWS EXE BUG FINDER CHECKS (BUG-EXE-001 to BUG-EXE-005)
# =============================================================================

@CheckRegistry.register
class EXECheckResourceLeaks(BaseCheck):
    check_id = "BUG-EXE-001"
    name = "Memory & Handle Resource Leak Heuristics"
    description = "Audits the Import Address Table for asymmetric resource lifecycle functions, where resources are acquired but no deallocation function is linked."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Software Defect / Resource Management"
    default_severity = Severity.HIGH
    standards = ["CWE-401", "CWE-775", "CERT MEM31-C"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return EXEBugFinder._check_resource_leaks(target.target_path, context)


@CheckRegistry.register
class EXECheckBannedFunctions(BaseCheck):
    check_id = "BUG-EXE-002"
    name = "Defect-Prone Banned C-Runtime Functions"
    description = "Detects legacy C-runtime functions that lack boundary checks, leading to memory corruption, off-by-one errors, and unexpected crashes."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Software Defect / Code Safety"
    default_severity = Severity.HIGH
    standards = ["CWE-120", "CWE-676", "Microsoft Security Development Lifecycle (SDL)"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return EXEBugFinder._check_banned_functions(target.target_path, context)


@CheckRegistry.register
class EXECheckUnquotedPaths(BaseCheck):
    check_id = "BUG-EXE-003"
    name = "Unquoted Execution & Service Path Defects"
    description = "Checks for unquoted file system paths with spaces targeting Program Files, which cause execution hijacking or service launch failures."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Software Defect / Execution"
    default_severity = Severity.MEDIUM
    standards = ["CWE-428", "CAPEC-38"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return EXEBugFinder._check_unquoted_paths(target.target_path, context)


@CheckRegistry.register
class EXECheckExceptionGuards(BaseCheck):
    check_id = "BUG-EXE-004"
    name = "Missing Stack Buffer & Exception Handling Guards"
    description = "Verifies the presence of modern compiler mitigations that prevent corrupted stack buffers from crashing or hijacking the process."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Software Defect / Crash Mitigation"
    default_severity = Severity.MEDIUM
    standards = ["CWE-121", "NIST SP 800-53 SI-16"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return EXEBugFinder._check_exception_guards(target.target_path, context)


@CheckRegistry.register
class EXECheckManifestDefects(BaseCheck):
    check_id = "BUG-EXE-005"
    name = "Application Manifest & High-DPI GUI Defects"
    description = "Audits embedded manifest for DPI scaling, modern controls, and Windows OS compatibility declarations."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Software Defect / GUI & Compatibility"
    default_severity = Severity.LOW
    standards = ["Microsoft Desktop App UX Guidelines"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return EXEBugFinder._check_manifest_defects(target.target_path, context)


# =============================================================================
# ANDROID APK BUG FINDER CHECKS (BUG-APK-001 to BUG-APK-005)
# =============================================================================

@CheckRegistry.register
class APKCheckANRRisks(BaseCheck):
    check_id = "BUG-APK-001"
    name = "Potential ANR & UI Thread Network Blocking"
    description = "Checks for synchronous network invocation methods that can cause NetworkOnMainThreadException or 5-second Application Not Responding (ANR) dialogs."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Software Defect / Performance & ANR"
    default_severity = Severity.MEDIUM
    standards = ["CWE-400", "Android Performance Guide §ANR"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return APKBugFinder._check_anr_risks(target.target_path, context)


@CheckRegistry.register
class APKCheckCursorLeaks(BaseCheck):
    check_id = "BUG-APK-002"
    name = "Unclosed SQLite Cursor & Stream Resource Leaks"
    description = "Checks for database queries without corresponding Cursor.close() calls that cause memory leaks in Android CursorWindow shared memory."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Software Defect / Resource Leaks"
    default_severity = Severity.HIGH
    standards = ["CWE-775", "Android Database Guidelines"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return APKBugFinder._check_cursor_leaks(target.target_path, context)


@CheckRegistry.register
class APKCheckReflectionHazards(BaseCheck):
    check_id = "BUG-APK-003"
    name = "Dynamic Reflection & Class Loading Hazards"
    description = "Audits usage of Java reflection and dynamic class loading that is fragile under R8 / ProGuard obfuscation and prone to ClassNotFoundException crashes."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Software Defect / Reflection & Obfuscation"
    default_severity = Severity.MEDIUM
    standards = ["CWE-470", "Android ProGuard Guidelines"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return APKBugFinder._check_reflection_hazards(target.target_path, context)


@CheckRegistry.register
class APKCheckIntentDefects(BaseCheck):
    check_id = "BUG-APK-004"
    name = "Misconfigured Intent-Filters & Activity Export Defects"
    description = "Checks for compliance with Android 12+ (API 31) component export mandates to prevent INSTALL_PARSE_FAILED_MANIFEST_MALFORMED crashes."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Software Defect / Manifest & Components"
    default_severity = Severity.HIGH
    standards = ["Android 12 Behavior Changes §Exported Components"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return APKBugFinder._check_intent_defects(target.target_path, context)


@CheckRegistry.register
class APKCheckLifecycleDefects(BaseCheck):
    check_id = "BUG-APK-005"
    name = "Deprecated Lifecycle & State Retention Defects"
    description = "Audits bytecode for fragile lifecycle calls such as commitAllowingStateLoss and deprecated startActivityForResult that lose UI state on rotation."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Software Defect / Lifecycle & Fragments"
    default_severity = Severity.LOW
    standards = ["Android Architecture Components Guidelines"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        return APKBugFinder._check_lifecycle_defects(target.target_path, context)
