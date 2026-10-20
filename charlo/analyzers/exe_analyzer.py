"""
Advanced Deep Windows PE Executable Analyzer for CHARLO Testing Agent.
Deep PE inspection engine with LoadConfig exploit mitigations, sliding-window entropy,
embedded XML manifest extraction, Authenticode parsing, and MITRE API classification.
"""

import os
import math
import re
import hashlib
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Set, Optional
import pefile


class EXEAnalyzer:
    """
    Deep static analysis engine for Windows PE executables (.exe, .dll).
    """

    INJECTION_APIS = {
        "VirtualAllocEx": "Allocates memory within a remote process space.",
        "WriteProcessMemory": "Writes arbitrary bytes into target process memory.",
        "CreateRemoteThread": "Executes remote thread inside an external process.",
        "QueueUserAPC": "Queues asynchronous procedure call to target process thread.",
        "SetThreadContext": "Modifies CPU registers of target process thread.",
        "NtUnmapViewOfSection": "Unmaps section, commonly used in Process Hollowing.",
        "ZwUnmapViewOfSection": "Kernel equivalent for section unmapping / hollowing.",
    }

    EVASION_APIS = {
        "IsDebuggerPresent": "Queries PEB BeingDebugged flag.",
        "CheckRemoteDebuggerPresent": "Checks if external debugger is attached.",
        "NtQueryInformationProcess": "Direct NT query for ProcessDebugPort / ProcessDebugFlags.",
        "OutputDebugStringA": "Tests debugger attachment via structured exception signaling.",
        "GetTickCount": "Timing check often abused for anti-sandbox sleep evasion.",
        "QueryPerformanceCounter": "High-precision timer often abused for debugging detection.",
    }

    HOOKING_APIS = {
        "SetWindowsHookExA": "Installs global application hook (keylogger/mouse monitor).",
        "SetWindowsHookExW": "Installs global application hook (keylogger/mouse monitor).",
        "GetAsyncKeyState": "Direct asynchronous keystroke querying API.",
        "GetKeyboardState": "Dumps virtual key states of the calling thread.",
    }

    PRIVILEGE_APIS = {
        "AdjustTokenPrivileges": "Enables or disables privileges in access token (e.g. SeDebugPrivilege).",
        "OpenProcessToken": "Opens access token associated with a process.",
        "ImpersonateNamedPipeClient": "Impersonates client of named pipe (Potato attack vector).",
        "CreateServiceW": "Creates or registers a Windows service requiring administrative rights.",
    }

    BANNED_CRT_APIS = {
        "strcpy": "Unsafe CRT string copy without buffer boundary verification.",
        "strcat": "Unsafe CRT string concatenation prone to buffer overflow.",
        "sprintf": "Unsafe formatted output lacking destination length limits.",
        "gets": "Deprecated and banned input reading function.",
    }

    SECRET_PATTERNS = {
        "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
        "Generic Secret Token": re.compile(r"(?:password|secret|apikey|token|auth_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{12,})['\"]", re.IGNORECASE),
        "Database Connection String": re.compile(r"(?:Server|Data Source|Uid|User Id)=.*(?:Password|Pwd)=", re.IGNORECASE),
        "Private Key Header": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "Internal UNC Path": re.compile(r"\\\\[a-zA-Z0-9_\-\.]+\\[a-zA-Z0-9_\-\.\$\\]+"),
    }

    @classmethod
    def analyze(cls, exe_path: str) -> Dict[str, Any]:
        """
        Conducts deep static PE analysis.
        """
        context: Dict[str, Any] = {
            "valid_pe": False,
            "file_size": 0,
            "sha256": "",
            "machine_arch": "unknown",
            "subsystem": "unknown",
            "compile_time": "",
            "is_64bit": False,
            # Exploit Mitigations
            "is_aslr_enabled": False,
            "is_high_entropy_aslr": False,
            "is_dep_enabled": False,
            "is_cfg_enabled": False,
            "has_cfg_table": False,
            "is_safeseh_enabled": False,
            "has_security_cookie": False,
            "has_load_config": False,
            "has_cet_shadow_stack": False,
            # Authenticode Digital Signature
            "is_digitally_signed": False,
            "signature_details": {},
            # Section & Memory Protection
            "sections": [],
            "wx_sections": [],
            "packed_sections": [],
            "max_entropy": 0.0,
            "sliding_window_high_entropy_blocks": 0,
            # Manifest & UAC
            "has_embedded_manifest": False,
            "requested_execution_level": "asInvoker",
            "ui_access": False,
            # Imports & MITRE Mapping
            "imported_dlls": [],
            "imported_functions": [],
            "injection_apis_found": [],
            "evasion_apis_found": [],
            "hooking_apis_found": [],
            "privilege_apis_found": [],
            "banned_apis_found": [],
            # Secrets & Strings
            "detected_secrets": [],
            "errors": [],
        }

        if not os.path.exists(exe_path):
            context["errors"].append(f"File not found: {exe_path}")
            return context

        context["file_size"] = os.path.getsize(exe_path)

        # Compute SHA256
        sha256 = hashlib.sha256()
        with open(exe_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        context["sha256"] = sha256.hexdigest()

        try:
            pe = pefile.PE(exe_path, fast_load=False)
            context["valid_pe"] = True

            # 1. Machine Architecture
            machine = pe.FILE_HEADER.Machine
            if machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
                context["machine_arch"] = "x86 (32-bit)"
                context["is_64bit"] = False
            elif machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
                context["machine_arch"] = "x64 (64-bit)"
                context["is_64bit"] = True
            elif machine == pefile.MACHINE_TYPE.get("IMAGE_FILE_MACHINE_ARM64", 0xAA64):
                context["machine_arch"] = "ARM64"
                context["is_64bit"] = True
            else:
                context["machine_arch"] = f"Unknown ({hex(machine)})"

            # 2. Optional Header DllCharacteristics
            if hasattr(pe, "OPTIONAL_HEADER"):
                dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
                context["is_aslr_enabled"] = bool(dll_char & 0x0040)          # DYNAMIC_BASE
                context["is_high_entropy_aslr"] = bool(dll_char & 0x0020)     # HIGH_ENTROPY_VA
                context["is_dep_enabled"] = bool(dll_char & 0x0100)           # NX_COMPAT
                context["is_cfg_enabled"] = bool(dll_char & 0x4000)           # GUARD_CF

            # 3. Deep LoadConfig Directory Audit (Security Cookie, CFG Table, SafeSEH)
            cls._audit_load_config(pe, context)

            # 4. Authenticode Signature Audit
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            if security_dir.VirtualAddress != 0 and security_dir.Size > 0:
                context["is_digitally_signed"] = True
                context["signature_details"] = {
                    "offset": security_dir.VirtualAddress,
                    "size": security_dir.Size,
                }

            # 5. Section Analysis & Sliding-Window Entropy
            cls._audit_sections(pe, context)

            # 6. Embedded XML Manifest (RT_MANIFEST) Extraction
            cls._extract_embedded_manifest(pe, context)

            # 7. Import Address Table (IAT) Deep Audit
            cls._audit_imports(pe, context)

            # 8. Printable Strings & Secrets Audit
            cls._scan_strings(exe_path, context)

            pe.close()

        except Exception as e:
            context["errors"].append(f"PE parsing error: {str(e)}")

        return context

    @classmethod
    def _audit_load_config(cls, pe: pefile.PE, context: Dict[str, Any]):
        """
        Inspects IMAGE_LOAD_CONFIG_DIRECTORY for SafeSEH, /GS Stack Cookies, and CFG tables.
        """
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
                context["has_load_config"] = True
                lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct

                # Security Cookie (__security_cookie pointer)
                if hasattr(lc, "SecurityCookie") and lc.SecurityCookie != 0:
                    context["has_security_cookie"] = True

                # Control Flow Guard Table
                if hasattr(lc, "GuardCFFunctionTable") and lc.GuardCFFunctionTable != 0:
                    context["has_cfg_table"] = True

                # SafeSEH Table (for 32-bit x86)
                if not context["is_64bit"]:
                    if hasattr(lc, "SEHandlerTable") and lc.SEHandlerTable != 0 and hasattr(lc, "SEHandlerCount") and lc.SEHandlerCount > 0:
                        context["is_safeseh_enabled"] = True
                    elif bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400):  # NO_SEH flag
                        context["is_safeseh_enabled"] = True

                # CET Shadow Stack Flags
                if hasattr(lc, "GuardFlags"):
                    # Check IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT (0x00010000) or CET flags
                    if lc.GuardFlags & 0x00010000:
                        context["has_cet_shadow_stack"] = True
        except Exception:
            pass

    @classmethod
    def _audit_sections(cls, pe: pefile.PE, context: Dict[str, Any]):
        """
        Audits section permissions (W^X) and sliding-window Shannon entropy.
        """
        max_entropy = 0.0
        for sec in pe.sections:
            sec_name = sec.Name.decode("ascii", errors="ignore").strip("\x00")
            entropy = sec.get_entropy()
            if entropy > max_entropy:
                max_entropy = entropy

            is_readable = bool(sec.Characteristics & 0x40000000)
            is_writable = bool(sec.Characteristics & 0x80000000)
            is_executable = bool(sec.Characteristics & 0x20000000)

            sec_info = {
                "name": sec_name,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": round(entropy, 2),
                "is_writable": is_writable,
                "is_executable": is_executable,
            }
            context["sections"].append(sec_info)

            # Strict W^X Check: Simultaneous Write and Execute
            if is_writable and is_executable:
                context["wx_sections"].append(sec_name)

            # Packed / Obfuscated Section Indicator
            if entropy > 7.2 and sec.SizeOfRawData > 2048:
                context["packed_sections"].append({
                    "name": sec_name,
                    "entropy": round(entropy, 2),
                })

            # Sliding Window High-Entropy Scan (1KB blocks)
            sec_data = sec.get_data()
            if len(sec_data) >= 1024:
                high_blocks = 0
                for offset in range(0, min(len(sec_data), 65536), 1024):
                    block = sec_data[offset:offset + 1024]
                    if len(block) == 1024:
                        ent = cls._calculate_entropy(block)
                        if ent >= 7.6:
                            high_blocks += 1
                if high_blocks > 0:
                    context["sliding_window_high_entropy_blocks"] += high_blocks

        context["max_entropy"] = round(max_entropy, 2)

    @classmethod
    def _calculate_entropy(cls, data: bytes) -> float:
        if not data:
            return 0.0
        occ = {}
        for b in data:
            occ[b] = occ.get(b, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in occ.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def _extract_embedded_manifest(cls, pe: pefile.PE, context: Dict[str, Any]):
        """
        Locates and extracts RT_MANIFEST (Resource Type 24) to audit UAC levels and uiAccess.
        """
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == 24:  # RT_MANIFEST
                        for resource_id in resource_type.directory.entries:
                            for resource_lang in resource_id.directory.entries:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                manifest_bytes = pe.get_data(data_rva, size)
                                context["has_embedded_manifest"] = True

                                manifest_str = manifest_bytes.decode("utf-8", errors="ignore")
                                context["embedded_manifest_str"] = manifest_str
                                if "requestedExecutionLevel" in manifest_str:
                                    m_level = re.search(r'level=["\']([^"\']+)["\']', manifest_str)
                                    if m_level:
                                        context["requested_execution_level"] = m_level.group(1)
                                if "uiAccess" in manifest_str:
                                    m_ui = re.search(r'uiAccess=["\']true["\']', manifest_str, re.IGNORECASE)
                                    if m_ui:
                                        context["ui_access"] = True
        except Exception:
            pass

    @classmethod
    def _audit_imports(cls, pe: pefile.PE, context: Dict[str, Any]):
        """
        Maps imported APIs against MITRE ATT&CK techniques.
        """
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("ascii", errors="ignore")
                context["imported_dlls"].append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("ascii", errors="ignore")
                        context["imported_functions"].append(func_name)

                        if func_name in cls.INJECTION_APIS:
                            context["injection_apis_found"].append({
                                "api": func_name,
                                "dll": dll_name,
                                "reason": cls.INJECTION_APIS[func_name],
                            })
                        if func_name in cls.EVASION_APIS:
                            context["evasion_apis_found"].append({
                                "api": func_name,
                                "dll": dll_name,
                                "reason": cls.EVASION_APIS[func_name],
                            })
                        if func_name in cls.HOOKING_APIS:
                            context["hooking_apis_found"].append({
                                "api": func_name,
                                "dll": dll_name,
                                "reason": cls.HOOKING_APIS[func_name],
                            })
                        if func_name in cls.PRIVILEGE_APIS:
                            context["privilege_apis_found"].append({
                                "api": func_name,
                                "dll": dll_name,
                                "reason": cls.PRIVILEGE_APIS[func_name],
                            })
                        if func_name in cls.BANNED_CRT_APIS:
                            context["banned_apis_found"].append({
                                "api": func_name,
                                "dll": dll_name,
                                "reason": cls.BANNED_CRT_APIS[func_name],
                            })

    @classmethod
    def _scan_strings(cls, exe_path: str, context: Dict[str, Any]):
        """
        High-accuracy regex string extraction for embedded secrets.
        """
        try:
            with open(exe_path, "rb") as f:
                content = f.read(5 * 1024 * 1024)
                for match in re.finditer(rb"[A-Za-z0-9_.\-/:@$+=]{8,}", content):
                    try:
                        s = match.group(0).decode("ascii")
                        for sec_type, pattern in cls.SECRET_PATTERNS.items():
                            if pattern.search(s):
                                masked = s[:4] + "*" * (len(s) - 8) + s[-4:] if len(s) > 12 else "****"
                                finding_item = {
                                    "type": sec_type,
                                    "sample": masked,
                                }
                                if finding_item not in context["detected_secrets"] and len(context["detected_secrets"]) < 10:
                                    context["detected_secrets"].append(finding_item)
                    except Exception:
                        pass
        except Exception:
            pass
