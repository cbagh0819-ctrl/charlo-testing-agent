"""
AI-Powered Threat Modeling and Attack Surface Synthesizer for CHARLO Testing Agent.
Translates technical security check findings into executive attack scenarios,
risk matrices, and prioritized remediation roadmaps.
"""

from typing import Dict, Any, List
from .models import ScanResult, TargetType, Severity, CheckStatus


class ThreatModelGenerator:
    """
    Synthesizes executive attack vector narratives and actionable threat models.
    """

    @classmethod
    def generate_threat_model(cls, result: ScanResult) -> Dict[str, Any]:
        target = result.target
        target_name = target.display_name if target else "Unknown Target"
        target_type = target.target_type if target else TargetType.EXE
        metrics = result.metrics

        failed_ids = {f.check_id: f for f in result.findings if f.status in (CheckStatus.FAILED, CheckStatus.WARNING)}

        plausible_attacks: List[Dict[str, str]] = []
        investigation_risks: List[Dict[str, str]] = []
        roadmap: List[str] = []

        # =====================================================================
        # 1. WEB ATTACK SURFACE SYNTHESIS
        # =====================================================================
        if target_type == TargetType.WEB:
            # XSS / CSP
            if "WEB-003" in failed_ids:
                plausible_attacks.append({
                    "name": "Cross-Site Scripting (XSS) Amplification",
                    "priority": "High Priority",
                    "finding_ref": "WEB-003 — Missing / Permissive Content-Security-Policy (CSP)",
                    "scenario": (
                        "If an input reflection or stored vulnerability exists on any page, the absence of a strict CSP "
                        "allows injected scripts to execute unimpeded. Attackers could steal session cookies, deface pages, "
                        "or perform unauthorized actions on behalf of authenticated users."
                    ),
                    "caveat": "Missing CSP amplifies the impact of XSS vulnerabilities; it does not prove that an injection point currently exists.",
                })
                roadmap.append("Deploy a Content-Security-Policy (CSP). Begin in 'Content-Security-Policy-Report-Only' mode to audit legitimate scripts, then enforce a strict whitelist or nonce-based policy.")

            # SSL Stripping / HSTS
            if "WEB-002" in failed_ids:
                plausible_attacks.append({
                    "name": "SSL Stripping & MitM Downgrade Attacks",
                    "priority": "Medium Priority",
                    "finding_ref": "WEB-002 — Missing Strict-Transport-Security (HSTS)",
                    "scenario": (
                        "An attacker on the victim's local network (e.g. coffee shop Wi-Fi or compromised router) can intercept "
                        "the user's initial unencrypted HTTP connection before redirection completes, downgrading subsequent communication to cleartext."
                    ),
                    "caveat": "The site enforces HTTPS, which is positive, but HSTS is required so browsers remember to never attempt unencrypted HTTP.",
                })
                roadmap.append("Enable HTTP Strict-Transport-Security (HSTS) with a max-age of at least 31536000 seconds (1 year) and includeSubDomains.")

            # Clickjacking
            if "WEB-004" in failed_ids:
                plausible_attacks.append({
                    "name": "Clickjacking / UI Redressing",
                    "priority": "Medium Priority",
                    "finding_ref": "WEB-004 — Missing Framing Protection (X-Frame-Options / frame-ancestors)",
                    "scenario": (
                        "A malicious third-party site can render this website inside a transparent <iframe>, overlay deceptive UI controls, "
                        "and trick authenticated users into clicking sensitive administrative actions or submitting unintended forms."
                    ),
                    "caveat": "Impact is greatest if logged-in users visit untrusted external sites while maintaining an active session.",
                })
                roadmap.append("Configure X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'self') to prevent external websites from embedding your portal.")

            # Cookie Security
            if "WEB-007" in failed_ids:
                f_cookie = failed_ids["WEB-007"]
                plausible_attacks.append({
                    "name": "Session Hijacking & Cross-Site Request Forgery (CSRF)",
                    "priority": "Medium Priority",
                    "finding_ref": "WEB-007 — Insecure Cookie Attributes",
                    "scenario": (
                        f"Cookies flagged in audit ({f_cookie.evidence[:100]}...) lack HttpOnly, Secure, or proper SameSite directives. "
                        "Missing HttpOnly permits client-side script cookie theft; missing SameSite facilitates cross-origin request forging."
                    ),
                    "caveat": "Examine the specific cookie purpose; non-sensitive analytics cookies have lower risk than primary session tokens.",
                })
                roadmap.append("Audit all Set-Cookie directives to enforce 'Secure; HttpOnly; SameSite=Lax' (or Strict) on all session identifiers.")

            # Critical .git / .env exposures
            if "WEB-017" in failed_ids:
                plausible_attacks.append({
                    "name": "Full Source Code & Repository Reconstruction",
                    "priority": "Critical Priority",
                    "finding_ref": "WEB-017 — Exposed .git Repository Metadata",
                    "scenario": (
                        "Publicly accessible .git repository allows attackers to reconstruct the entire application source code, "
                        "commit histories, internal endpoints, and sensitive credentials."
                    ),
                    "caveat": "High severity threat; immediately block .git in reverse proxy or web server configuration.",
                })
                roadmap.insert(0, "IMMEDIATE ACTION: Restrict public access to /.git and all hidden dotfiles in web server rules.")

            if "WEB-018" in failed_ids:
                plausible_attacks.append({
                    "name": "Direct Database & Production Credential Compromise",
                    "priority": "Critical Priority",
                    "finding_ref": "WEB-018 — Exposed .env Environment Configuration",
                    "scenario": (
                        "Exposed .env configuration directly leaks database connection strings, API secrets, and server encryption keys."
                    ),
                    "caveat": "Immediate exposure risk; rotate all exposed secrets immediately after securing the endpoint.",
                })
                roadmap.insert(0, "IMMEDIATE ACTION: Block public access to /.env and rotate all production database credentials.")

            if "WEB-020" in failed_ids:
                f_tls = failed_ids["WEB-020"]
                plausible_attacks.append({
                    "name": "Cryptographic Interception / TLS Certificate Failure",
                    "priority": "High Priority",
                    "finding_ref": "WEB-020 — Weak / Deprecated TLS Ciphers or Expired Certificate",
                    "scenario": (
                        f"TLS audit flagged cryptographic weaknesses ({f_tls.evidence[:100]}). "
                        "Expired certificates block legitimate traffic; deprecated TLS 1.0/1.1 protocols allow traffic decryption."
                    ),
                    "caveat": "Enforce TLS 1.2+ exclusively and configure automated certificate renewal.",
                })
                roadmap.append("Modernize TLS configuration to enforce TLS 1.2 and TLS 1.3 with AES-GCM or ChaCha20 ciphers.")

            # Administrative Reconnaissance
            if "WEB-010" in failed_ids:
                f_robots = failed_ids["WEB-010"]
                plausible_attacks.append({
                    "name": "Administrative Path Reconnaissance & Brute-Force",
                    "priority": "Low to Medium",
                    "finding_ref": "WEB-010 — Sensitive Route Disclosed in robots.txt",
                    "scenario": (
                        f"Robots.txt discloses administrative or internal paths ({f_robots.evidence[:80]}). "
                        "Attackers use automated scanners to locate these management portals and initiate credential stuffing or exploit unpatched CMS plugins."
                    ),
                    "caveat": "Disclosure in robots.txt is not a direct breach; effective multi-factor authentication (MFA) and IP whitelisting protect the interface.",
                })
                roadmap.append("Review whether administrative routes in robots.txt should be removed, and enforce IP restrictions or MFA on administrative logins.")

            # Technology Leakage
            if "WEB-008" in failed_ids:
                roadmap.append("Suppress server identification banners (Server, X-Powered-By) to prevent automated fingerprinting of web server software versions.")

            # General investigation table
            investigation_risks = [
                {"threat": "Phishing using the organization's identity", "finding": "Not tested by this audit; domain reputation and email DMARC/SPF/DKIM should be reviewed separately."},
                {"threat": "DDoS / Service Disruption", "finding": "Not established; static rate-limiting check reflects header policies, not network-level CDN/WAF volumetric capacity."},
                {"threat": "SQL Injection & Backend Injection", "finding": "No error indicators detected in passive responses; dynamic parameterized query audits are recommended on staging."},
                {"threat": "Administrative Account Takeover", "finding": "Administrative endpoints were identified; login brute-force protections, CAPTCHA, and MFA should be verified."},
                {"threat": "Sensitive Data Leakage", "finding": "Headers like Referrer-Policy were flagged, but actual confidential database leakage was not demonstrated."},
            ]

        # =====================================================================
        # 2. WINDOWS EXE ATTACK SURFACE SYNTHESIS
        # =====================================================================
        elif target_type == TargetType.EXE:
            if "EXE-004" in failed_ids:
                plausible_attacks.append({
                    "name": "Arbitrary Shellcode Execution via W^X Memory Violation",
                    "priority": "Critical Priority",
                    "finding_ref": "EXE-004 — Writable and Executable Section Flagged",
                    "scenario": "A PE section possesses both Write and Execute permissions. Exploits can write raw shellcode directly into memory without requiring VirtualProtect API calls.",
                    "caveat": "Often associated with custom packers or unpackers; requires validation in isolated sandbox.",
                })
                roadmap.append("Immediately recompile or unpack binary to ensure strict W^X separation: code sections must be Read-Only + Executable.")

            if "EXE-001" in failed_ids or "EXE-002" in failed_ids:
                plausible_attacks.append({
                    "name": "Buffer Overflow & ROP Chain Exploitation",
                    "priority": "High Priority",
                    "finding_ref": "EXE-001/EXE-002 — Missing ASLR or DEP/NX Protection",
                    "scenario": "Without ASLR, memory addresses remain static across runs. Without DEP, stack memory can execute instructions, enabling classic buffer overflow exploits.",
                    "caveat": "Requires an existing memory corruption bug in the binary logic to be triggered.",
                })
                roadmap.append("Recompile with /DYNAMICBASE (ASLR) and /NXCOMPAT (DEP) enabled in the MSVC compiler/linker flags.")

            if "EXE-003" in failed_ids:
                plausible_attacks.append({
                    "name": "Binary Tampering & SmartScreen Impersonation",
                    "priority": "Medium Priority",
                    "finding_ref": "EXE-003 — Missing Authenticode Digital Signature",
                    "scenario": "Unsigned binaries cannot guarantee author authenticity. Threat actors can patch binary bytes or substitute trojanized versions without invalidating signatures.",
                    "caveat": "Binary functions normally on developer systems, but triggers Windows SmartScreen warnings on client machines.",
                })
                roadmap.append("Sign the production executable using Microsoft SignTool with a verified Authenticode code-signing certificate.")

            if "EXE-006" in failed_ids:
                plausible_attacks.append({
                    "name": "Process Injection & Memory Tampering",
                    "priority": "High Priority",
                    "finding_ref": "EXE-006 — Suspicious Process Injection APIs Imported",
                    "scenario": "Imported functions (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) can be abused to inject payloads into external processes.",
                    "caveat": "Legitimate profilers and security tools use these APIs; check if this binary is an administrative or monitoring tool.",
                })
                roadmap.append("Audit usage of cross-process memory manipulation APIs and restrict memory operations to the application's own virtual address space.")

            if "EXE-010" in failed_ids:
                plausible_attacks.append({
                    "name": "Static Credential Harvesting",
                    "priority": "High Priority",
                    "finding_ref": "EXE-010 — Hardcoded Secrets in Binary Strings",
                    "scenario": "Embedded passwords, tokens, or private keys can be extracted by any user with a hex editor or strings utility.",
                    "caveat": "Secrets detected by pattern heuristics should be manually verified to confirm active credential validity.",
                })
                roadmap.append("Extract hardcoded credentials and migrate to Windows Credential Manager (CredRead) or an enterprise secret vault.")

            if "EXE-013" in failed_ids:
                plausible_attacks.append({
                    "name": "UIPI Desktop Window Hooking & Privilege Bypass",
                    "priority": "High Priority",
                    "finding_ref": "EXE-013 — uiAccess='true' in Embedded Manifest",
                    "scenario": "Manifest permits bypassing User Interface Privilege Isolation, allowing keystroke injection into higher-privileged applications.",
                    "caveat": "Only authorized for digitally signed accessibility binaries installed in secure directories.",
                })
                roadmap.append("Set uiAccess='false' in application manifest.")

            if "EXE-014" in failed_ids:
                plausible_attacks.append({
                    "name": "Contiguous Stack Frame Overwrite (/GS Canary Missing)",
                    "priority": "High Priority",
                    "finding_ref": "EXE-014 — Missing Security Cookie Canary",
                    "scenario": "Stack frames lack random canary cookies, allowing contiguous buffer overflows to overwrite return pointers directly.",
                    "caveat": "Exploitation requires a vulnerable input parsing buffer in binary code.",
                })
                roadmap.append("Compile with /GS security cookie flag in MSVC.")

            if "EXE-034" in failed_ids:
                f_banned = failed_ids["EXE-034"]
                plausible_attacks.append({
                    "name": "Buffer Overflow via Banned CRT Functions",
                    "priority": "Medium Priority",
                    "finding_ref": "EXE-034 — Unsafe Legacy CRT APIs (strcpy, sprintf)",
                    "scenario": f"Binary imports bounded-check-deficient C runtime routines ({f_banned.evidence[:80]}).",
                    "caveat": "Audit source code to confirm whether destination buffers have predetermined maximum bounds.",
                })
                roadmap.append("Replace legacy CRT functions with secure equivalents (strcpy_s, sprintf_s).")

            investigation_risks = [
                {"threat": "Malware Persistence Mechanisms", "finding": "Evaluated static imports; dynamic runtime registry/service installation was not triggered."},
                {"threat": "EDR Evasion / Direct Syscalls", "finding": "Static imports inspected; kernel driver and direct assembly hooks require isolated VM sandbox trace."},
                {"threat": "DLL Hijacking / Side-Loading", "finding": "Audited import table; verify application directory DLL search order (SetDefaultDllDirectories)."},
            ]

        # =====================================================================
        # 3. ANDROID APK ATTACK SURFACE SYNTHESIS
        # =====================================================================
        elif target_type == TargetType.APK:
            if "APK-001" in failed_ids:
                plausible_attacks.append({
                    "name": "JDWP Runtime Debugger Code Execution",
                    "priority": "Critical Priority",
                    "finding_ref": "APK-001 — android:debuggable='true' in Release Manifest",
                    "scenario": "An attacker with physical or ADB USB access can attach jdb or frida to the live app process, dump memory, and execute arbitrary code in app sandbox.",
                    "caveat": "Applicable on any unlocked device with USB debugging enabled, without requiring root privileges.",
                })
                roadmap.append("Set android:debuggable='false' in release build configuration in build.gradle.")

            if "APK-002" in failed_ids:
                plausible_attacks.append({
                    "name": "Local Sandbox Data Extraction via ADB Backup",
                    "priority": "Medium Priority",
                    "finding_ref": "APK-002 — android:allowBackup='true'",
                    "scenario": "Anyone with temporary physical access can run 'adb backup' to copy private SharedPreferences, SQLite databases, and auth tokens to a PC.",
                    "caveat": "Requires physical access and device unlock to approve the backup prompt on older Android versions.",
                })
                roadmap.append("Explicitly declare android:allowBackup='false' in AndroidManifest.xml or implement strict BackupAgent rules.")

            if "APK-003" in failed_ids:
                plausible_attacks.append({
                    "name": "Cleartext MitM Interception",
                    "priority": "High Priority",
                    "finding_ref": "APK-003 — Cleartext HTTP Traffic Permitted",
                    "scenario": "Communications over port 80 allow local network eavesdroppers to intercept session tokens, passwords, and inject modified API payloads.",
                    "caveat": "Requires the user to connect to an untrusted Wi-Fi or transit network where MitM proxying is active.",
                })
                roadmap.append("Enforce android:usesCleartextTraffic='false' and implement custom network_security_config.xml enforcing TLS 1.3.")

            if "APK-004" in failed_ids:
                plausible_attacks.append({
                    "name": "Component Hijacking & Intent Spoofing",
                    "priority": "High Priority",
                    "finding_ref": "APK-004 — Insecure Exported Activities / Components",
                    "scenario": "Rogue apps installed on the same device can fire intents directly into exported activities, bypassing login screens and internal checks.",
                    "caveat": "Only reachable by other malicious applications co-located on the same mobile device.",
                })
                roadmap.append("Explicitly mark internal activities, services, and receivers with android:exported='false'.")

            if "APK-006" in failed_ids:
                plausible_attacks.append({
                    "name": "Cloud API Key & Token Exfiltration",
                    "priority": "High Priority",
                    "finding_ref": "APK-006 — Hardcoded Secrets in Bytecode",
                    "scenario": "Decompiling classes.dex reveals static cloud keys (AWS, Google, Firebase), allowing unauthorized API usage and billing abuse.",
                    "caveat": "Some public client tokens (e.g. Firebase Android App ID) are non-secret identifiers, but private service keys must be revoked.",
                })
                roadmap.append("Remove hardcoded service account credentials and proxy sensitive API requests through an authenticated backend server.")

            if "APK-012" in failed_ids:
                plausible_attacks.append({
                    "name": "Local Sandbox Cross-Application Data Theft",
                    "priority": "High Priority",
                    "finding_ref": "APK-012 — World-Readable / Writable Storage Flags",
                    "scenario": "Files created with MODE_WORLD_READABLE can be accessed directly by other apps on the device.",
                    "caveat": "Deprecated flags; check if legacy file modes are actively accessed.",
                })
                roadmap.append("Enforce Context.MODE_PRIVATE on all SharedPreferences and internal database stores.")

            if "APK-015" in failed_ids:
                plausible_attacks.append({
                    "name": "Private File Theft via WebView File Schemes",
                    "priority": "High Priority",
                    "finding_ref": "APK-015 — Insecure WebView File Access",
                    "scenario": "WebViews with setAllowFileAccess(true) allow untrusted web content to read private files via file:// URI schemes.",
                    "caveat": "Risk manifests when WebViews load external untrusted websites.",
                })
                roadmap.append("Disable file scheme access on all WebViews (setAllowFileAccess(false)).")

            if "APK-017" in failed_ids:
                plausible_attacks.append({
                    "name": "Malicious Secondary Bytecode Execution (Dropper Risk)",
                    "priority": "High Priority",
                    "finding_ref": "APK-017 — Dynamic Bytecode Loading (DexClassLoader)",
                    "scenario": "Dynamically executing secondary DEX files from writable paths allows malware to substitute payloads at runtime.",
                    "caveat": "Check if secondary DEX files are cryptographically signed before execution.",
                })
                roadmap.append("Avoid runtime DexClassLoader execution from writable device storage.")

            investigation_risks = [
                {"threat": "Dynamic Code Loading (Droppers)", "finding": "Inspected bytecode strings; runtime DexClassLoader calls require dynamic sandbox observation."},
                {"threat": "Root & Hooking Bypass", "finding": "Evaluated static anti-tamper heuristics; testing with Frida/Magisk is recommended on rooted test devices."},
            ]

        # Executive narrative synthesis
        grade = metrics.posture_grade
        score = metrics.security_score
        crit_count = metrics.critical_count
        high_count = metrics.high_count
        med_count = metrics.medium_count

        executive_summary = (
            f"The assessment evaluated target '{target_name}' across defense-in-depth configurations, assigning a "
            f"security posture grade of '{grade}' with a score of {score}/100. "
            f"The audit flagged {crit_count} Critical, {high_count} High, and {med_count} Medium severity areas of concern. "
            "These findings highlight architectural and configuration gaps that increase potential attack surfaces. "
            "Importantly, findings indicate missing security mitigations rather than confirmed ongoing breaches; "
            "remediation should follow a risk-prioritized defensive approach."
        )

        return {
            "target_name": target_name,
            "target_type": target_type.value.upper(),
            "grade": grade,
            "score": score,
            "executive_summary": executive_summary,
            "plausible_attacks": plausible_attacks,
            "investigation_risks": investigation_risks,
            "methodology_disclaimer": (
                f"This assessment was generated via non-destructive static inspection and safe transport probing (duration: {result.duration_seconds}s). "
                "Evidence reflects observable headers, binary structures, and configuration files. "
                "A clean check does not prove complete immunity from zero-day defects or business-logic flaws, "
                "nor does a failed check prove active exploitation. Defensive testing must only be conducted against authorized assets."
            ),
            "roadmap": roadmap,
        }
