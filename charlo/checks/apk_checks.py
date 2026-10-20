"""
Advanced Deep Android APK Security Checks for CHARLO Testing Agent.
High-accuracy checks evaluating manifest boundaries, permissions, cryptographic bytecode,
WebView configurations, and dynamic code execution.
"""

from typing import Dict, Any
from .base import BaseCheck
from ..core.models import (
    TargetType,
    ScanLevel,
    Severity,
    CheckStatus,
    CheckFinding,
    ScanTarget,
)
from ..core.registry import CheckRegistry


@CheckRegistry.register
class APKCheckDebuggable(BaseCheck):
    check_id = "APK-001"
    name = "Android Debuggable Flag Enabled"
    description = "Verifies that android:debuggable is false. An application with debuggable=true allows arbitrary code execution via JDWP debugger attachments on unrooted devices."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Manifest Security"
    default_severity = Severity.CRITICAL
    standards = ["CWE-215", "OWASP Mobile M1:2024", "MASVS-RESILIENCE-1"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK parsing failed.")

        if context.get("debuggable", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.CRITICAL,
                title="CRITICAL: android:debuggable='true' Detected in Release Manifest",
                affected_component="AndroidManifest.xml -> <application>",
                evidence="android:debuggable flag set to 'true'. JDWP runtime debugger can be attached over ADB without root privileges.",
                impact="An attacker can attach jdb or frida over USB debugging, dump process heap memory, read encryption keys, and execute arbitrary code in the app context.",
                remediation="In build.gradle, ensure debuggable is set to false in release builds:\nandroid {\n    buildTypes {\n        release {\n            debuggable false\n        }\n    }\n}",
                code_example="android {\n    buildTypes {\n        release {\n            debuggable false\n            minifyEnabled true\n        }\n    }\n}",
                verification_step="Run: aapt dump badging app-release.apk | grep debuggable\nExpected: No output or debuggable='0'.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: android:debuggable is Disabled",
            evidence="android:debuggable is false or omitted (hardened against JDWP attachment).",
        )


@CheckRegistry.register
class APKCheckAllowBackup(BaseCheck):
    check_id = "APK-002"
    name = "Application Auto-Backup Insecurity"
    description = "Checks android:allowBackup configuration. When true, private application data can be extracted using adb backup."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Data Storage"
    default_severity = Severity.MEDIUM
    standards = ["CWE-538", "OWASP Mobile M2:2024", "MASVS-STORAGE-1"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        if context.get("allow_backup", True):
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title="MEDIUM: android:allowBackup Allows Local Data Sandbox Extraction",
                affected_component="AndroidManifest.xml -> <application android:allowBackup>",
                evidence="android:allowBackup is enabled or omitted. ADB backup infrastructure can extract app private data sandbox.",
                impact="Anyone with temporary physical access to the device can execute 'adb backup' to dump app databases, SharedPreferences, and cached auth tokens.",
                remediation="Explicitly disable allowBackup in AndroidManifest.xml or configure a secure BackupAgent with strict rules.",
                code_example='<application\n    android:allowBackup="false"\n    android:fullBackupContent="false"\n    ... >',
                verification_step="Verify android:allowBackup='false' in manifest.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: android:allowBackup is explicitly disabled",
            evidence="android:allowBackup='false' prevents unauthorized ADB sandbox extraction.",
        )


@CheckRegistry.register
class APKCheckCleartext(BaseCheck):
    check_id = "APK-003"
    name = "Cleartext HTTP Traffic Allowed"
    description = "Checks android:usesCleartextTraffic. If true, the app transmits sensitive traffic over unencrypted HTTP."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Network Security"
    default_severity = Severity.HIGH
    standards = ["CWE-319", "OWASP Mobile M5:2024", "MASVS-NETWORK-1"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        if context.get("uses_cleartext_traffic", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title="HIGH: Cleartext HTTP Communication Permitted",
                affected_component="AndroidManifest.xml -> <application android:usesCleartextTraffic>",
                evidence="android:usesCleartextTraffic='true' allows insecure unencrypted HTTP socket and WebView communication.",
                impact="Network eavesdroppers and rogue Wi-Fi access points can perform MitM attacks to sniff passwords, session cookies, and inject malicious scripts.",
                remediation="Set android:usesCleartextTraffic='false' and enforce HTTPS for all API endpoints.",
                code_example='<application\n    android:usesCleartextTraffic="false"\n    android:networkSecurityConfig="@xml/network_security_config"\n    ... >',
                verification_step="Verify all network communications use TLS 1.3 endpoints exclusively.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Cleartext HTTP traffic is blocked",
            evidence="android:usesCleartextTraffic is not enabled.",
        )


@CheckRegistry.register
class APKCheckExportedComponents(BaseCheck):
    check_id = "APK-004"
    name = "Insecure Exported Components"
    description = "Checks for Activities, Services, and BroadcastReceivers exported without restrictive permissions or signature protection."
    target_type = TargetType.APK
    level = ScanLevel.INTERMEDIATE
    category = "Access Control"
    default_severity = Severity.HIGH
    standards = ["CWE-926", "OWASP Mobile M1:2024", "MASVS-PLATFORM-1"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        unprotected = context.get("unprotected_exported_components", [])
        if unprotected:
            comp_names = [f"{c['type']}: {c['name']}" for c in unprotected[:4]]
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.HIGH,
                title=f"HIGH: {len(unprotected)} Unprotected Component(s) Exported to External Applications",
                affected_component="AndroidManifest.xml -> <activity> / <service> / <receiver>",
                evidence=f"Exported components: {', '.join(comp_names)}",
                impact="Rogue apps on the same device can trigger sensitive internal activities, bypass authentication screens, or inject malformed intents.",
                remediation="Explicitly mark internal components with android:exported='false' unless they are designated public entry points.",
                code_example='<activity\n    android:name=".InternalDashboardActivity"\n    android:exported="false" />',
                verification_step="Audit all declared components with android:exported='true'.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No overly permissive exported components found",
            evidence="All declared components enforce strict boundary isolation.",
        )


@CheckRegistry.register
class APKCheckPermissions(BaseCheck):
    check_id = "APK-005"
    name = "Excessive Sensitive Permissions Requested"
    description = "Audits requested Android permissions against principle of least privilege, flagging high-risk permissions."
    target_type = TargetType.APK
    level = ScanLevel.BASIC
    category = "Authorization & Permissions"
    default_severity = Severity.MEDIUM
    standards = ["CWE-250", "OWASP Mobile M1:2024", "MASVS-PLATFORM-2"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        dangerous = context.get("dangerous_permissions", [])
        if dangerous:
            perm_list = ", ".join([p["permission"].replace("android.permission.", "") for p in dangerous[:5]])
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title=f"MEDIUM: {len(dangerous)} High-Risk Permission(s) Requested ({perm_list})",
                affected_component="AndroidManifest.xml -> <uses-permission>",
                evidence=f"Dangerous permissions: {[p['permission'] for p in dangerous]}",
                impact="Excessive permissions expand the blast radius if the app is compromised, and trigger Google Play compliance scrutiny.",
                remediation="Remove unused permissions from AndroidManifest.xml and request dangerous permissions dynamically at runtime only when needed.",
                code_example='<!-- Remove unnecessary permissions like READ_SMS or WRITE_CALL_LOG -->',
                verification_step="Ensure runtime permission checks accompany all sensitive APIs.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No excessive high-risk permissions detected",
            evidence="Application requests standard Android permissions.",
        )


@CheckRegistry.register
class APKCheckHardcodedSecrets(BaseCheck):
    check_id = "APK-006"
    name = "Hardcoded API Keys & Tokens in Bytecode"
    description = "Scans compiled classes.dex bytecode and asset bundles for hardcoded cloud credentials, AWS keys, and private tokens."
    target_type = TargetType.APK
    level = ScanLevel.INTERMEDIATE
    category = "Credentials & Secrets"
    default_severity = Severity.HIGH
    standards = ["CWE-798", "OWASP Mobile M1:2024", "MASVS-CRYPTO-1"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        secrets = context.get("detected_secrets", [])
        if secrets:
            sample = secrets[0]
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title=f"HIGH: Embedded Hardcoded Secret Detected ({sample['type']})",
                affected_component=f"{sample.get('location', 'Bytecode')} -> String Table",
                evidence=f"Detected pattern '{sample['type']}' with sample: {sample['sample']}",
                impact="Decompiling the APK using JADX exposes backend credentials, allowing unauthorized API access, billing charges, or database exfiltration.",
                remediation="Store API secrets on a secure backend proxy. For client-side mobile authentication, use short-lived OAuth 2.0 PKCE tokens.",
                code_example='// Use backend token exchange service with Play Integrity API',
                verification_step="Decompile classes.dex and grep for private API strings.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No obvious hardcoded credentials identified in bytecode",
            evidence="Scanned DEX string tables; no known AWS, Google, Stripe, or private token patterns detected.",
        )


@CheckRegistry.register
class APKCheckWeakCrypto(BaseCheck):
    check_id = "APK-007"
    name = "Weak Cryptographic Ciphers & Modes"
    description = "Detects usage of broken cryptographic primitives (DES, RC4, MD5, ECB cipher mode)."
    target_type = TargetType.APK
    level = ScanLevel.INTERMEDIATE
    category = "Cryptography"
    default_severity = Severity.HIGH
    standards = ["CWE-327", "OWASP Mobile M5:2024", "MASVS-CRYPTO-2"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        indicators = context.get("weak_crypto_indicators", [])
        if indicators:
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title=f"HIGH: Insecure Cryptographic Cipher Reference ({', '.join(indicators)})",
                affected_component="DEX Bytecode -> Cipher Suite Implementations",
                evidence=f"Found references to broken cryptography: {indicators}",
                impact="Broken algorithms like DES/RC4 or AES in ECB mode do not provide semantic security and are susceptible to pattern revelation or plaintext recovery.",
                remediation="Migrate all symmetric encryption to AES-256-GCM or ChaCha20-Poly1305 with random IVs via Google Tink or AndroidX Security Crypto.",
                code_example='val masterKey = MasterKey.Builder(context)\n    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)\n    .build()',
                verification_step="Ensure Cipher.getInstance() specifies 'AES/GCM/NoPadding'.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No broken cryptographic algorithm signatures detected",
            evidence="No references to DES, RC4, or ECB modes found in bytecode.",
        )


@CheckRegistry.register
class APKCheckWorldReadableStorage(BaseCheck):
    check_id = "APK-012"
    name = "World-Readable / Writable Shared Preferences"
    description = "Flags usage of deprecated MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE flags in SharedPreferences."
    target_type = TargetType.APK
    level = ScanLevel.INTERMEDIATE
    category = "Data Storage"
    default_severity = Severity.HIGH
    standards = ["CWE-732", "OWASP Mobile M2:2024", "MASVS-STORAGE-1"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        if context.get("has_world_readable_storage", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title="HIGH: Insecure World-Readable / Writable Storage Mode Referenced",
                affected_component="DEX Bytecode -> SharedPreferences Storage Configuration",
                evidence="Bytecode references MODE_WORLD_READABLE (0x0001) or MODE_WORLD_WRITEABLE (0x0002).",
                impact="Files created with world-readable permissions can be read or modified by any other application installed on the device.",
                remediation="Use MODE_PRIVATE (0x0000) or EncryptedSharedPreferences from the AndroidX Security library.",
                code_example="context.getSharedPreferences(\"app_prefs\", Context.MODE_PRIVATE);",
                verification_step="Verify SharedPreferences are created with Context.MODE_PRIVATE.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No world-readable storage modes identified",
            evidence="Private sandbox file modes enforced.",
        )


@CheckRegistry.register
class APKCheckWebViewFileAccess(BaseCheck):
    check_id = "APK-015"
    name = "Insecure WebView File Access"
    description = "Checks setAllowFileAccess and setAllowUniversalAccessFromFileURLs on Android WebViews."
    target_type = TargetType.APK
    level = ScanLevel.INTERMEDIATE
    category = "WebView Security"
    default_severity = Severity.HIGH
    standards = ["CWE-749", "OWASP Mobile M1:2024", "MASVS-PLATFORM-4"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        if context.get("has_webview_file_access", False):
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.HIGH,
                title="HIGH: Insecure WebView File Access Enabled",
                affected_component="DEX Bytecode -> WebSettings Configuration",
                evidence="Found calls enabling setAllowFileAccess or setAllowUniversalAccessFromFileURLs.",
                impact="If a WebView loads untrusted web content, attackers can read private local files from the app sandbox via file:// URI schemes.",
                remediation="Explicitly disable file access on all WebViews: webSettings.setAllowFileAccess(false); webSettings.setAllowContentAccess(false);",
                code_example="webSettings.setAllowFileAccess(false);\nwebSettings.setAllowUniversalAccessFromFileURLs(false);",
                verification_step="Audit all WebSettings instances for setAllowFileAccess(false).",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: WebView file schemes restricted",
            evidence="No insecure WebView file access settings detected in bytecode.",
        )


@CheckRegistry.register
class APKCheckDynamicCodeLoading(BaseCheck):
    check_id = "APK-017"
    name = "Dynamic Code Loading (DexClassLoader)"
    description = "Detects runtime loading of secondary DEX or APK files from writable storage locations."
    target_type = TargetType.APK
    level = ScanLevel.ADVANCED
    category = "Code Execution"
    default_severity = Severity.HIGH
    standards = ["CWE-94", "OWASP Mobile M1:2024", "MASVS-CODE-2"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_apk"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="APK could not be parsed.")

        if context.get("has_dynamic_code_loading", False):
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.HIGH,
                title="HIGH: Dynamic Bytecode Loading (DexClassLoader) Identified",
                affected_component="DEX Bytecode -> ClassLoader Invocations",
                evidence="Found references to dalvik.system.DexClassLoader or PathClassLoader.",
                impact="Dynamically loaded DEX files stored in writable application storage or downloaded over the network can be intercepted or substituted by local malware.",
                remediation="Bundle all application code within the signed APK or verify digital signatures before dynamically executing secondary bytecode.",
                code_example="// Avoid dynamic class loading from writable paths (/data/data/... or external storage)",
                verification_step="Verify all executable code is packaged directly in classes.dex.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No dynamic DexClassLoader invocations detected",
            evidence="Bytecode does not dynamically load external DEX files.",
        )
