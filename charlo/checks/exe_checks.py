"""
Advanced Deep Windows PE Security Checks for CHARLO Testing Agent.
High-accuracy exploit mitigations, LoadConfig security cookies, CFG bitmaps,
embedded UAC manifest policies, and MITRE ATT&CK API classifications.
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
class EXECheckASLR(BaseCheck):
    check_id = "EXE-001"
    name = "Address Space Layout Randomization (ASLR)"
    description = "Verifies IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE. ASLR randomizes executable and library memory offsets."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Exploit Mitigations"
    default_severity = Severity.HIGH
    standards = ["CWE-119", "NIST SP 800-53", "MS-SECURITY-ASLR"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        if not context.get("is_aslr_enabled", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title="HIGH: Address Space Layout Randomization (ASLR) is Disabled",
                affected_component="PE Header -> OptionalHeader.DllCharacteristics",
                evidence="IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) is NOT set.",
                impact="Memory addresses for code, stack, and heap remain at predictable static offsets across executions, simplifying ROP gadget chaining.",
                remediation="Compile with /DYNAMICBASE in MSVC or -Wl,--dynamicbase in MinGW/GCC.",
                code_example="cl.exe /DYNAMICBASE main.cpp /link /DYNAMICBASE",
                verification_step="Run: dumpbin /headers target.exe | findstr 'Dynamic base'",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: ASLR (Dynamic Base) is Enabled",
            evidence="IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is set.",
        )


@CheckRegistry.register
class EXECheckDEP(BaseCheck):
    check_id = "EXE-002"
    name = "Data Execution Prevention (DEP / NX)"
    description = "Verifies IMAGE_DLLCHARACTERISTICS_NX_COMPAT. DEP marks memory regions as non-executable."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Exploit Mitigations"
    default_severity = Severity.HIGH
    standards = ["CWE-119", "NIST SP 800-53", "MS-SECURITY-DEP"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        if not context.get("is_dep_enabled", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title="HIGH: Data Execution Prevention (DEP / NX) is Disabled",
                affected_component="PE Header -> OptionalHeader.DllCharacteristics",
                evidence="IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100) is NOT set.",
                impact="Non-executable memory regions (stack and heap) can execute arbitrary CPU instructions if an attacker hijacks control flow.",
                remediation="Compile with /NXCOMPAT in MSVC or -Wl,--nxcompat in GCC/MinGW.",
                code_example="cl.exe /NXCOMPAT main.cpp /link /NXCOMPAT",
                verification_step="Run: dumpbin /headers target.exe | findstr 'NX compatible'",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: DEP / NX Protection is Enabled",
            evidence="IMAGE_DLLCHARACTERISTICS_NX_COMPAT is set.",
        )


@CheckRegistry.register
class EXECheckSignature(BaseCheck):
    check_id = "EXE-003"
    name = "Authenticode Digital Signature"
    description = "Checks PE Security Directory for valid Authenticode certificate."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Code Signing & Integrity"
    default_severity = Severity.MEDIUM
    standards = ["CWE-347", "NIST SP 800-53", "MS-AUTHENTICODE"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        if not context.get("is_digitally_signed", False):
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title="MEDIUM: Executable is Not Digitally Signed (Missing Authenticode)",
                affected_component="PE Header -> IMAGE_DIRECTORY_ENTRY_SECURITY",
                evidence="No digital certificate found in Data Directory index 4.",
                impact="Unsigned binaries trigger Windows SmartScreen blocking warnings, cannot be verified for publisher identity, and are vulnerable to silent binary patching.",
                remediation="Sign the binary using Microsoft SignTool with a valid EV code-signing certificate.",
                code_example="signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f certificate.pfx /p <password> target.exe",
                verification_step="Run: signtool.exe verify /pa /v target.exe",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Executable contains Authenticode digital signature directory",
            evidence=f"Authenticode certificate table present (Size: {context.get('signature_details', {}).get('size', 0)} bytes).",
        )


@CheckRegistry.register
class EXECheckWXSections(BaseCheck):
    check_id = "EXE-004"
    name = "Writable and Executable (W^X) Section Flag"
    description = "Flags PE sections configured with both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE."
    target_type = TargetType.EXE
    level = ScanLevel.INTERMEDIATE
    category = "Memory Protection"
    default_severity = Severity.CRITICAL
    standards = ["CWE-732", "NIST SP 800-53", "MITRE ATT&CK T1055"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        wx_sections = context.get("wx_sections", [])
        if wx_sections:
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.CRITICAL,
                title=f"CRITICAL: Memory Section Violation (W^X) in Section '{', '.join(wx_sections)}'",
                affected_component=f"PE Section Table -> {', '.join(wx_sections)}",
                evidence=f"Section(s) {wx_sections} have both MEM_WRITE and MEM_EXECUTE characteristics set.",
                impact="Writable and Executable memory completely breaks hardware DEP enforcement, enabling self-modifying code injection and in-memory shellcode execution.",
                remediation="Ensure code sections (.text) are read-only + executable, and data sections (.data, .bss) are read-write + non-executable.",
                code_example="#pragma section(\".text\", read, execute)  // Never include write",
                verification_step="Audit section flags using dumpbin /headers target.exe",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Strict W^X separation enforced across all PE sections",
            evidence="No sections possess simultaneous Write and Execute permissions.",
        )


@CheckRegistry.register
class EXECheckEntropy(BaseCheck):
    check_id = "EXE-005"
    name = "High Entropy / Packed Executable Detection"
    description = "Calculates section Shannon entropy and sliding-window block entropy to identify packers or encrypted shellcode."
    target_type = TargetType.EXE
    level = ScanLevel.INTERMEDIATE
    category = "Obfuscation & Packing"
    default_severity = Severity.MEDIUM
    standards = ["CWE-506", "MITRE ATT&CK T1027", "NIST SP 800-53"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        packed = context.get("packed_sections", [])
        max_ent = context.get("max_entropy", 0.0)
        sliding_blocks = context.get("sliding_window_high_entropy_blocks", 0)

        if packed or sliding_blocks > 5:
            sec_details = [f"{p['name']} (H={p['entropy']})" for p in packed]
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title=f"MEDIUM: High Entropy Obfuscation Detected (Max H={max_ent})",
                affected_component="PE Section Table -> Entropy Analysis",
                evidence=f"Max entropy {max_ent}/8.0 across sections: {sec_details}. Sliding-window high-entropy 1KB blocks: {sliding_blocks}.",
                impact="High entropy indicates that code or data is compressed or encrypted (UPX, Themida, VMProtect). Packed binaries impede security auditing and trigger AV heuristics.",
                remediation="Distribute clean, unpacked binaries for legitimate enterprise software.",
                verification_step="Analyze section entropy using pefile or Detect It Easy (DIE).",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Section entropy within normal operational parameters",
            evidence=f"Maximum section entropy is {max_ent}/8.0 (Uncompressed range).",
        )


@CheckRegistry.register
class EXECheckCFG(BaseCheck):
    check_id = "EXE-008"
    name = "Control Flow Guard (CFG) Verification"
    description = "Verifies IMAGE_DLLCHARACTERISTICS_GUARD_CF and LoadConfig GuardCFFunctionTable bitmap."
    target_type = TargetType.EXE
    level = ScanLevel.INTERMEDIATE
    category = "Exploit Mitigations"
    default_severity = Severity.LOW
    standards = ["CWE-691", "MS-SECURITY-CFG"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        has_flag = context.get("is_cfg_enabled", False)
        has_table = context.get("has_cfg_table", False)

        if not has_flag and not has_table:
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.LOW,
                title="LOW: Control Flow Guard (CFG) is Not Enabled",
                affected_component="PE Header & IMAGE_LOAD_CONFIG_DIRECTORY",
                evidence="IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is absent and no GuardCFFunctionTable found.",
                impact="Indirect function pointer calls and vtables lack runtime bitmap verification, leaving application susceptible to forward-edge control-flow hijacking.",
                remediation="Enable Control Flow Guard in MSVC project properties or compile with /guard:cf.",
                code_example="cl.exe /guard:cf main.cpp /link /guard:cf",
                verification_step="Check dumpbin /loadconfig target.exe for CFG table bitmap.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Control Flow Guard (CFG) is Enabled",
            evidence=f"CFG flag present (Table in LoadConfig: {has_table}).",
        )


@CheckRegistry.register
class EXECheckSafeSEH(BaseCheck):
    check_id = "EXE-009"
    name = "SafeSEH / Structured Exception Handler Hardening"
    description = "Verifies SafeSEH table in 32-bit executables, preventing malicious SEH overwrite attack chains."
    target_type = TargetType.EXE
    level = ScanLevel.INTERMEDIATE
    category = "Exploit Mitigations"
    default_severity = Severity.MEDIUM
    standards = ["CWE-119", "MS-SECURITY-SAFESEH"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        if context.get("is_64bit", False):
            return self.create_finding(
                CheckStatus.NOT_APPLICABLE,
                severity=Severity.INFO,
                title="NOT APPLICABLE: SafeSEH is only applicable to 32-bit x86 binaries (64-bit uses table-based SEH)",
                evidence="Target binary is 64-bit architecture.",
            )

        if not context.get("is_safeseh_enabled", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.MEDIUM,
                title="MEDIUM: SafeSEH Exception Handler Table Missing in 32-bit Binary",
                affected_component="IMAGE_LOAD_CONFIG_DIRECTORY -> SEHandlerTable",
                evidence="SafeSEH handler list is not present in Load Config directory.",
                impact="Classic SEH overwrite attacks allow buffer overflows to overwrite the exception handler record pointer on the stack, diverting execution flow on triggered exception.",
                remediation="Compile with /SAFESEH linker option in 32-bit MSVC builds.",
                code_example="link.exe /SAFESEH target.obj",
                verification_step="Run: dumpbin /loadconfig target.exe | findstr 'Safe SEH'",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: SafeSEH protection is enabled",
            evidence="SafeSEH table is verified in Load Config directory.",
        )


@CheckRegistry.register
class EXECheckUACExecutionLevel(BaseCheck):
    check_id = "EXE-012"
    name = "UAC Execution Level (requireAdministrator)"
    description = "Audits embedded RT_MANIFEST requestedExecutionLevel (asInvoker vs requireAdministrator)."
    target_type = TargetType.EXE
    level = ScanLevel.BASIC
    category = "Privilege & UAC"
    default_severity = Severity.MEDIUM
    standards = ["CWE-250", "MITRE ATT&CK T1548"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        uac_level = context.get("requested_execution_level", "asInvoker")
        if uac_level.lower() == "requireadministrator":
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title="MEDIUM: Executable Enforces requireAdministrator Execution Level",
                affected_component="RT_MANIFEST (Resource 24) -> requestedExecutionLevel",
                evidence="Manifest requestedExecutionLevel is set to 'requireAdministrator'.",
                impact="The application mandates elevated UAC administrator tokens on every launch, expanding security risks if software defects exist.",
                remediation="Unless creating drivers or system utilities, configure requestedExecutionLevel='asInvoker' to run under standard user rights.",
                code_example='<requestedExecutionLevel level="asInvoker" uiAccess="false"/>',
                verification_step="Audit manifest using mt.exe or Visual Studio Resource Viewer.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Executable adheres to least privilege (asInvoker)",
            evidence=f"UAC level configured as '{uac_level}'.",
        )


@CheckRegistry.register
class EXECheckUIPIBypass(BaseCheck):
    check_id = "EXE-013"
    name = "UIPI (uiAccess) Desktop Isolation Bypass"
    description = "Checks uiAccess=true attribute in manifest which allows bypassing User Interface Privilege Isolation (UIPI)."
    target_type = TargetType.EXE
    level = ScanLevel.INTERMEDIATE
    category = "Privilege & UAC"
    default_severity = Severity.HIGH
    standards = ["CWE-269", "MS-UAC-UIPI"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        if context.get("ui_access", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title="HIGH: UIPI Desktop Isolation Bypass Enabled (uiAccess='true')",
                affected_component="RT_MANIFEST (Resource 24) -> uiAccess",
                evidence="uiAccess attribute is set to 'true'.",
                impact="Applications with uiAccess='true' can inject window messages and hook inputs into higher-privileged desktop windows, bypassing UIPI security boundaries.",
                remediation="Set uiAccess='false' unless developing specialized accessibility tools that must be installed in Program Files.",
                code_example='<requestedExecutionLevel level="asInvoker" uiAccess="false"/>',
                verification_step="Confirm uiAccess='false' in application manifest.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: UIPI desktop isolation boundaries enforced (uiAccess='false')",
            evidence="uiAccess is not enabled.",
        )


@CheckRegistry.register
class EXECheckSecurityCookie(BaseCheck):
    check_id = "EXE-014"
    name = "Security Cookie / Stack Canary (/GS Flag)"
    description = "Checks presence of __security_cookie in LoadConfig protecting stack frames from buffer overflow corruption."
    target_type = TargetType.EXE
    level = ScanLevel.INTERMEDIATE
    category = "Exploit Mitigations"
    default_severity = Severity.HIGH
    standards = ["CWE-121", "MS-COMPILER-GS"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        if not context.get("has_security_cookie", False):
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.HIGH,
                title="HIGH: Missing Security Cookie / Stack Canary Protection (/GS Flag)",
                affected_component="IMAGE_LOAD_CONFIG_DIRECTORY -> SecurityCookie",
                evidence="No SecurityCookie pointer found in LoadConfig directory.",
                impact="Stack frames lack random canary cookies, allowing contiguous buffer overflows to overwrite return pointers and frame base pointers directly.",
                remediation="Compile with /GS flag in MSVC (enabled by default in modern Visual Studio releases).",
                code_example="cl.exe /GS main.cpp",
                verification_step="Run: dumpbin /loadconfig target.exe | findstr 'Security Cookie'",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Stack cookie canary protection (/GS) is active",
            evidence="SecurityCookie pointer verified in LoadConfig directory.",
        )


@CheckRegistry.register
class EXECheckBannedAPIs(BaseCheck):
    check_id = "EXE-034"
    name = "Unsafe CRT Functions (strcpy, sprintf)"
    description = "Detects imports of banned C runtime string manipulation functions lacking buffer boundary checks."
    target_type = TargetType.EXE
    level = ScanLevel.INTERMEDIATE
    category = "Code Quality"
    default_severity = Severity.MEDIUM
    standards = ["CWE-120", "MS-BANNED-FUNCTIONS"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_pe"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="PE parsing failed.")

        banned = context.get("banned_apis_found", [])
        if banned:
            names = [b["api"] for b in banned]
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title=f"MEDIUM: Banned Legacy CRT String Functions Imported ({', '.join(names)})",
                affected_component="Import Address Table (IAT) -> CRT Functions",
                evidence=f"Imported banned functions: {names}",
                impact="Unbounded string copy and formatting routines are frequent causes of buffer overflow vulnerabilities.",
                remediation="Replace with secure bounded CRT functions: strcpy_s, sprintf_s, or modern C++ std::string.",
                code_example="strcpy_s(dest, sizeof(dest), src);",
                verification_step="Ensure no legacy strcpy, strcat, or sprintf symbols appear in IAT.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No banned legacy string manipulation functions detected",
            evidence="No references to strcpy, strcat, or sprintf in IAT.",
        )
