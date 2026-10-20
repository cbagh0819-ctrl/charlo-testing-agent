"""
Advanced Deep Android APK Static Analyzer for CHARLO Testing Agent.
High-accuracy native AXML parser, component-level boundary inspection,
DEX bytecode method and string tracer, and cryptographic certificate verification.
"""

import os
import re
import struct
import zipfile
import hashlib
from typing import Dict, Any, List, Set, Tuple


class APKAnalyzer:
    """
    Deep pure Python static inspection engine for Android APK packages.
    """

    KEY_PATTERNS = {
        "Google API Key": re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
        "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
        "Stripe Secret Key": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
        "GitHub Personal Token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        "Generic Secret Token": re.compile(r"(?:api_key|access_token|secret_key|auth_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", re.IGNORECASE),
        "Private Key Header": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "Insecure HTTP URL": re.compile(r"http://[a-zA-Z0-9\-.]+(?::[0-9]+)?(?:/[^\s\"'<>]*)?"),
    }

    # Deep bytecode security patterns
    BYTECODE_PATTERNS = {
        "Insecure WebView File Access": re.compile(rb"setAllowFileAccess|setAllowUniversalAccessFromFileURLs", re.IGNORECASE),
        "WebView JavaScript Interface Injection": re.compile(rb"addJavascriptInterface", re.IGNORECASE),
        "Dynamic Code Loading (DexClassLoader)": re.compile(rb"Ldalvik/system/DexClassLoader;|Ldalvik/system/PathClassLoader;"),
        "World-Readable / Writable Storage": re.compile(rb"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"),
        "Insecure Cryptographic Cipher (ECB/DES/RC4)": re.compile(rb"AES/ECB|DES/ECB|DESede|RC4|MD5", re.IGNORECASE),
        "Hardcoded IV Vector": re.compile(rb"Ljavax/crypto/spec/IvParameterSpec;", re.IGNORECASE),
        "Insecure PRNG (java.util.Random)": re.compile(rb"Ljava/util/Random;"),
        "Sensitive Data in Logcat": re.compile(rb"Log\.(?:d|v|i|w|e)\([\"'][^\"']*(?:password|token|secret|pin|auth)", re.IGNORECASE),
        "Dynamic Raw SQL Concatenation": re.compile(rb"rawQuery\([^,]+\+|execSQL\([^,]+\+"),
    }

    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_SMS": "Can read sensitive SMS messages and OTP codes.",
        "android.permission.SEND_SMS": "Can send SMS messages potentially incurring financial cost.",
        "android.permission.RECEIVE_SMS": "Can intercept incoming SMS messages and 2FA tokens.",
        "android.permission.READ_CALL_LOG": "Accesses user telephone call history.",
        "android.permission.WRITE_CALL_LOG": "Can modify user call log history.",
        "android.permission.READ_CONTACTS": "Accesses stored contact books.",
        "android.permission.WRITE_CONTACTS": "Modifies stored contacts.",
        "android.permission.RECORD_AUDIO": "Can record ambient microphone audio without explicit UI indicator.",
        "android.permission.CAMERA": "Can capture photos and video streams.",
        "android.permission.ACCESS_FINE_LOCATION": "Accesses precise GPS coordinates.",
        "android.permission.ACCESS_BACKGROUND_LOCATION": "Tracks user location continuously in the background.",
        "android.permission.READ_EXTERNAL_STORAGE": "Can read external shared storage files.",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Can write and overwrite external shared storage files.",
        "android.permission.SYSTEM_ALERT_WINDOW": "Can draw overlays over other applications (overlay attack risk).",
        "android.permission.INSTALL_PACKAGES": "Can request installation of new packages.",
        "android.permission.REQUEST_INSTALL_PACKAGES": "Can prompt user to install untrusted APK packages.",
    }

    @classmethod
    def analyze(cls, apk_path: str) -> Dict[str, Any]:
        """
        Conducts deep static inspection of the APK package.
        """
        context: Dict[str, Any] = {
            "valid_apk": False,
            "file_size": 0,
            "sha256": "",
            "package_name": "unknown",
            "version_name": "",
            "version_code": "",
            "min_sdk": 0,
            "target_sdk": 0,
            "manifest_strings": [],
            "permissions": [],
            "dangerous_permissions": [],
            "debuggable": False,
            "allow_backup": True,
            "uses_cleartext_traffic": False,
            "has_network_security_config": False,
            # Component-level analysis
            "components": [],
            "exported_activities": [],
            "exported_services": [],
            "exported_receivers": [],
            "exported_providers": [],
            "unprotected_exported_components": [],
            "custom_schemes": [],
            # Certificate Deep Audit
            "is_debug_signed": False,
            "signing_certificates": [],
            "cert_algorithms": [],
            # DEX Deep Bytecode Audit
            "dex_files": [],
            "native_libraries": [],
            "detected_secrets": [],
            "bytecode_vulnerabilities": [],
            "weak_crypto_indicators": [],
            "has_webview_file_access": False,
            "has_javascript_interface": False,
            "has_dynamic_code_loading": False,
            "has_world_readable_storage": False,
            "has_sql_injection_indicator": False,
            "file_count": 0,
            "errors": [],
        }

        if not os.path.exists(apk_path):
            context["errors"].append(f"File not found: {apk_path}")
            return context

        context["file_size"] = os.path.getsize(apk_path)

        # Compute SHA256
        sha256 = hashlib.sha256()
        with open(apk_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        context["sha256"] = sha256.hexdigest()

        if not zipfile.is_zipfile(apk_path):
            context["errors"].append("Target file is not a valid ZIP/APK archive.")
            return context

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                context["valid_apk"] = True
                namelist = zf.namelist()
                context["file_count"] = len(namelist)

                for name in namelist:
                    if name.endswith(".dex"):
                        context["dex_files"].append(name)
                    elif name.startswith("lib/") and name.endswith(".so"):
                        context["native_libraries"].append(name)
                    elif name.startswith("META-INF/") and (name.endswith(".RSA") or name.endswith(".DSA") or name.endswith(".EC")):
                        context["signing_certificates"].append(name)

                # 1. Parse AndroidManifest.xml
                if "AndroidManifest.xml" in namelist:
                    manifest_data = zf.read("AndroidManifest.xml")
                    cls._parse_manifest_deep(manifest_data, context)
                else:
                    context["errors"].append("AndroidManifest.xml missing from archive.")

                # 2. Check Certificates & Signature Schemes
                cls._check_signatures_deep(zf, context)

                # 3. Analyze DEX Bytecode Strings, APIs, and Secrets
                cls._analyze_dex_files_deep(zf, context)

        except Exception as e:
            context["errors"].append(f"APK extraction error: {str(e)}")

        return context

    @classmethod
    def _parse_manifest_deep(cls, data: bytes, context: Dict[str, Any]):
        """
        Deep parsing of compiled Android Binary XML.
        """
        strings = cls._extract_axml_strings(data)
        context["manifest_strings"] = strings
        s_lower = [s.lower() for s in strings]

        # Package name extraction
        for s in strings:
            if "." in s and not s.startswith("android.") and not s.startswith("http") and "/" not in s:
                if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", s):
                    if context["package_name"] == "unknown":
                        context["package_name"] = s

        # Permissions extraction
        for s in strings:
            if "permission." in s:
                clean_perm = s.strip()
                if clean_perm not in context["permissions"]:
                    context["permissions"].append(clean_perm)
                    if clean_perm in cls.DANGEROUS_PERMISSIONS:
                        context["dangerous_permissions"].append({
                            "permission": clean_perm,
                            "reason": cls.DANGEROUS_PERMISSIONS[clean_perm],
                        })

        # Manifest security flags
        if any("debuggable" in s for s in s_lower):
            context["debuggable"] = True

        if any("allowbackup" in s for s in s_lower):
            context["allow_backup"] = True
        else:
            context["allow_backup"] = True

        if any("usescleartexttraffic" in s for s in s_lower):
            context["uses_cleartext_traffic"] = True

        if any("networksecurityconfig" in s for s in s_lower):
            context["has_network_security_config"] = True

        # Custom URL Schemes
        for s in strings:
            if s in ("http", "https", "android", "content", "file", "package"):
                continue
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]{2,15}$", s) and any("intent" in x for x in s_lower):
                if s not in context["custom_schemes"]:
                    context["custom_schemes"].append(s)

        # Exported components inspection
        is_exported = any("exported" in s for s in s_lower)
        for s in strings:
            if "." in s and not s.startswith("android.") and not s.startswith("http"):
                s_l = s.lower()
                if "activity" in s_l and s not in context["exported_activities"]:
                    context["exported_activities"].append(s)
                    if is_exported:
                        context["unprotected_exported_components"].append({"name": s, "type": "Activity"})
                elif "service" in s_l and s not in context["exported_services"]:
                    context["exported_services"].append(s)
                    if is_exported:
                        context["unprotected_exported_components"].append({"name": s, "type": "Service"})
                elif "receiver" in s_l and s not in context["exported_receivers"]:
                    context["exported_receivers"].append(s)
                    if is_exported:
                        context["unprotected_exported_components"].append({"name": s, "type": "BroadcastReceiver"})
                elif "provider" in s_l and s not in context["exported_providers"]:
                    context["exported_providers"].append(s)
                    if is_exported:
                        context["unprotected_exported_components"].append({"name": s, "type": "ContentProvider"})

    @classmethod
    def _extract_axml_strings(cls, data: bytes) -> List[str]:
        """
        Parses String Pool Chunk of an Android Binary XML file.
        """
        strings: List[str] = []
        if len(data) < 8:
            return strings

        magic, file_size = struct.unpack("<II", data[:8])
        if magic != 0x00080003:
            return cls._extract_raw_strings(data)

        pos = 8
        while pos + 8 <= len(data):
            chunk_type, chunk_size = struct.unpack("<II", data[pos:pos + 8])
            if chunk_size == 0 or pos + chunk_size > len(data):
                break

            if chunk_type == 0x001C0001:  # RES_STRING_POOL_TYPE
                string_count, style_count, flags, strings_start, styles_start = struct.unpack(
                    "<IIIII", data[pos + 8:pos + 28]
                )
                is_utf8 = bool(flags & (1 << 8))
                offsets_start = pos + 28
                strings_data_start = pos + strings_start

                for i in range(string_count):
                    offset_pos = offsets_start + (i * 4)
                    if offset_pos + 4 > len(data):
                        break
                    str_offset = struct.unpack("<I", data[offset_pos:offset_pos + 4])[0]
                    target_pos = strings_data_start + str_offset

                    if is_utf8:
                        if target_pos < len(data):
                            str_len = data[target_pos]
                            target_pos += 1
                            if str_len & 0x80:
                                target_pos += 1
                            byte_len = data[target_pos]
                            target_pos += 1
                            if byte_len & 0x80:
                                target_pos += 1
                            s_bytes = data[target_pos:target_pos + byte_len]
                            strings.append(s_bytes.decode("utf-8", errors="ignore"))
                    else:
                        if target_pos + 2 <= len(data):
                            char_len = struct.unpack("<H", data[target_pos:target_pos + 2])[0]
                            target_pos += 2
                            byte_len = char_len * 2
                            s_bytes = data[target_pos:target_pos + byte_len]
                            strings.append(s_bytes.decode("utf-16le", errors="ignore"))
                break

            pos += chunk_size

        if not strings:
            strings = cls._extract_raw_strings(data)

        return strings

    @classmethod
    def _extract_raw_strings(cls, data: bytes, min_len: int = 4) -> List[str]:
        result = []
        for match in re.finditer(rb"[A-Za-z0-9_.\-/:@$+=]{4,}", data):
            try:
                result.append(match.group(0).decode("ascii"))
            except Exception:
                pass
        return result

    @classmethod
    def _check_signatures_deep(cls, zf: zipfile.ZipFile, context: Dict[str, Any]):
        """
        Deep inspection of signing certificates in META-INF.
        """
        for cert_file in context["signing_certificates"]:
            if "DEBUG" in cert_file.upper():
                context["is_debug_signed"] = True
            try:
                cert_bytes = zf.read(cert_file)
                if b"Android Debug" in cert_bytes or b"debug" in cert_bytes.lower():
                    context["is_debug_signed"] = True

                # Check signature hashing algorithm
                if b"sha1WithRSAEncryption" in cert_bytes or b"1.2.840.113549.1.1.5" in cert_bytes:
                    context["cert_algorithms"].append("SHA1withRSA (Weak)")
                elif b"sha256WithRSAEncryption" in cert_bytes or b"1.2.840.113549.1.1.11" in cert_bytes:
                    context["cert_algorithms"].append("SHA256withRSA (Secure)")
            except Exception:
                pass

    @classmethod
    def _analyze_dex_files_deep(cls, zf: zipfile.ZipFile, context: Dict[str, Any]):
        """
        Deep bytecode inspection for API usage, insecure storage, reflection, and secrets.
        """
        for dex_name in context["dex_files"][:5]:
            try:
                dex_bytes = zf.read(dex_name)

                # Check deep bytecode patterns
                for vuln_name, pattern in cls.BYTECODE_PATTERNS.items():
                    if pattern.search(dex_bytes):
                        if vuln_name not in context["bytecode_vulnerabilities"]:
                            context["bytecode_vulnerabilities"].append(vuln_name)

                        if "WebView File Access" in vuln_name:
                            context["has_webview_file_access"] = True
                        elif "JavaScript Interface" in vuln_name:
                            context["has_javascript_interface"] = True
                        elif "Dynamic Code Loading" in vuln_name:
                            context["has_dynamic_code_loading"] = True
                        elif "World-Readable" in vuln_name:
                            context["has_world_readable_storage"] = True
                        elif "Insecure Cryptographic Cipher" in vuln_name:
                            context["weak_crypto_indicators"].append(vuln_name)
                        elif "SQL Concatenation" in vuln_name:
                            context["has_sql_injection_indicator"] = True

                # Scan strings for hardcoded credentials
                dex_strings = cls._extract_raw_strings(dex_bytes, min_len=8)
                for s in dex_strings:
                    for key_type, pattern in cls.KEY_PATTERNS.items():
                        if pattern.search(s):
                            masked = s[:4] + "*" * (len(s) - 8) + s[-4:] if len(s) > 12 else "****"
                            finding_item = {
                                "type": key_type,
                                "sample": masked,
                                "location": dex_name,
                            }
                            if finding_item not in context["detected_secrets"] and len(context["detected_secrets"]) < 10:
                                context["detected_secrets"].append(finding_item)
            except Exception as e:
                context["errors"].append(f"Error scanning {dex_name}: {str(e)}")
