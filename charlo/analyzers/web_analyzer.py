"""
Advanced Deep Website and Web Application Security Analyzer for CHARLO Testing Agent.
Safe, non-destructive deep HTTP/TLS inspection engine with direct socket handshake,
zero-false-positive file signature verification, and rigorous CSP parsing.
"""

import socket
import ssl
import datetime
import urllib.parse
import re
from typing import Dict, Any, List, Optional
import requests


class WebAnalyzer:
    """
    Executes deep, safe, non-destructive web application security audits.
    """

    USER_AGENT = "CHARLO-Security-Agent/2.0 (High-Accuracy-Lab; Windows)"

    @classmethod
    def analyze(cls, target_url: str) -> Dict[str, Any]:
        """
        Conducts multi-layered deep auditing:
        1. TLS Handshake & Cipher Suite verification
        2. Certificate validity and expiration analysis
        3. Comprehensive HTTP security header & CSP policy parsing
        4. Cookie security attributes scrutiny
        5. Verified content-signature probing (no soft-404 false positives)
        6. CORS & Sensitive route auditing
        """
        context: Dict[str, Any] = {
            "valid_url": False,
            "original_url": target_url,
            "normalized_url": "",
            "hostname": "",
            "port": 443,
            "is_https": False,
            "http_redirects_to_https": False,
            "status_code": 0,
            "headers": {},
            "raw_headers_list": [],
            "cookies": [],
            "insecure_cookies": [],
            # TLS & Crypto Deep Findings
            "tls_version": None,
            "cipher_suite": None,
            "cipher_bits": 0,
            "cert_subject": {},
            "cert_issuer": {},
            "cert_expiry_date": None,
            "cert_days_remaining": 0,
            "cert_is_expired": False,
            "is_deprecated_tls": False,
            # Security Headers Deep Findings
            "hsts_present": False,
            "hsts_value": "",
            "hsts_max_age": 0,
            "hsts_includes_subdomains": False,
            "hsts_preload": False,
            "csp_present": False,
            "csp_value": "",
            "csp_directives": {},
            "csp_has_unsafe_inline": False,
            "csp_has_unsafe_eval": False,
            "csp_has_wildcard": False,
            "csp_missing_object_src": False,
            "csp_missing_base_uri": False,
            "x_frame_options": None,
            "has_frame_ancestors": False,
            "x_content_type_options": None,
            "referrer_policy": None,
            "permissions_policy": None,
            "cache_control": None,
            # Technology Leakage
            "server_header": None,
            "powered_by_header": None,
            "aspnet_header": None,
            # CORS Deep Verification
            "cors_allow_origin": None,
            "cors_allow_credentials": False,
            "cors_wildcard_with_credentials": False,
            # High-Accuracy File Exposures (Verified by Content Signature)
            "robots_txt_found": False,
            "robots_sensitive_paths": [],
            "security_txt_found": False,
            "git_exposed": False,
            "git_evidence": "",
            "env_exposed": False,
            "env_evidence": "",
            "errors": [],
        }

        url = target_url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                context["errors"].append(f"Invalid target URL: {target_url}")
                return context

            hostname = parsed.netloc.split(":")[0]
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            context["valid_url"] = True
            context["normalized_url"] = url
            context["hostname"] = hostname
            context["port"] = port
            context["is_https"] = parsed.scheme == "https"

            # -----------------------------------------------------------------
            # 1. DIRECT TLS / SSL SOCKET HANDSHAKE (Deep Cryptographic Audit)
            # -----------------------------------------------------------------
            if parsed.scheme == "https":
                cls._audit_tls_socket(hostname, port, context)

            # -----------------------------------------------------------------
            # 2. SAFE HTTP REQUEST & HEADER AUDIT
            # -----------------------------------------------------------------
            session = requests.Session()
            session.headers.update({"User-Agent": cls.USER_AGENT})

            try:
                resp = session.get(url, timeout=7, allow_redirects=True, verify=True)
                context["status_code"] = resp.status_code
                context["is_https"] = resp.url.startswith("https://")
                context["final_url"] = resp.url
                context["html_content"] = resp.text[:1000000] if resp.text else ""

                # Store headers in lowercase
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                context["headers"] = headers_lower
                context["raw_headers_list"] = [(k, v) for k, v in resp.headers.items()]

                # HSTS Deep Evaluation
                if "strict-transport-security" in headers_lower:
                    hsts_val = headers_lower["strict-transport-security"]
                    context["hsts_present"] = True
                    context["hsts_value"] = hsts_val
                    # Extract max-age
                    m = re.search(r"max-age\s*=\s*([0-9]+)", hsts_val, re.IGNORECASE)
                    if m:
                        context["hsts_max_age"] = int(m.group(1))
                    context["hsts_includes_subdomains"] = "includesubdomains" in hsts_val.lower()
                    context["hsts_preload"] = "preload" in hsts_val.lower()

                # CSP Deep Evaluation
                if "content-security-policy" in headers_lower:
                    csp_val = headers_lower["content-security-policy"]
                    context["csp_present"] = True
                    context["csp_value"] = csp_val
                    cls._parse_csp_policy(csp_val, context)

                # Framing / Clickjacking
                if "x-frame-options" in headers_lower:
                    context["x_frame_options"] = headers_lower["x-frame-options"]

                # MIME Sniffing
                if "x-content-type-options" in headers_lower:
                    context["x_content_type_options"] = headers_lower["x-content-type-options"]

                # Referrer Policy
                if "referrer-policy" in headers_lower:
                    context["referrer_policy"] = headers_lower["referrer-policy"]

                # Permissions Policy
                if "permissions-policy" in headers_lower:
                    context["permissions_policy"] = headers_lower["permissions-policy"]
                elif "feature-policy" in headers_lower:
                    context["permissions_policy"] = headers_lower["feature-policy"]

                # Cache Control
                if "cache-control" in headers_lower:
                    context["cache_control"] = headers_lower["cache-control"]

                # Banners & Leakage
                if "server" in headers_lower:
                    context["server_header"] = headers_lower["server"]
                if "x-powered-by" in headers_lower:
                    context["powered_by_header"] = headers_lower["x-powered-by"]
                if "x-aspnet-version" in headers_lower:
                    context["aspnet_header"] = headers_lower["x-aspnet-version"]

                # Cookie Deep Analysis
                cls._audit_cookies(resp, context)

            except requests.exceptions.SSLError as ssl_err:
                context["errors"].append(f"TLS/SSL Certificate Verification Error: {str(ssl_err)}")
            except requests.exceptions.ConnectionError as conn_err:
                context["errors"].append(f"Connection Failed: {str(conn_err)}")
            except Exception as req_err:
                context["errors"].append(f"HTTP Request failed: {str(req_err)}")

            # -----------------------------------------------------------------
            # 3. HTTP TO HTTPS REDIRECT VERIFICATION
            # -----------------------------------------------------------------
            try:
                http_url = f"http://{hostname}"
                http_resp = session.get(http_url, timeout=4, allow_redirects=False)
                if http_resp.is_redirect or http_resp.is_permanent_redirect:
                    loc = http_resp.headers.get("location", "")
                    if loc.startswith("https://"):
                        context["http_redirects_to_https"] = True
            except Exception:
                pass

            # -----------------------------------------------------------------
            # 4. CORS AUDIT WITH CROSS-ORIGIN PROBE
            # -----------------------------------------------------------------
            try:
                cors_headers = {"Origin": "https://untrusted-audit-probe.example.org"}
                cors_resp = session.get(url, headers=cors_headers, timeout=4)
                allow_orig = cors_resp.headers.get("Access-Control-Allow-Origin")
                allow_cred = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                context["cors_allow_origin"] = allow_orig
                context["cors_allow_credentials"] = allow_cred

                if (allow_orig == "*" or "untrusted-audit-probe" in str(allow_orig)) and allow_cred:
                    context["cors_wildcard_with_credentials"] = True
            except Exception:
                pass

            # -----------------------------------------------------------------
            # 5. HIGH-ACCURACY VERIFIED FILE PROBING (No soft-404 false positives)
            # -----------------------------------------------------------------
            cls._probe_sensitive_files(session, parsed.scheme, hostname, context)

        except Exception as e:
            context["errors"].append(f"Web analysis error: {str(e)}")

        return context

    @classmethod
    def _audit_tls_socket(cls, hostname: str, port: int, context: Dict[str, Any]):
        """
        Establishes direct SSL socket handshake to inspect TLS cipher and certificate.
        """
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_ver = ssock.version()
                    cipher_info = ssock.cipher()
                    cert = ssock.getpeercert()

                    context["tls_version"] = tls_ver
                    if cipher_info:
                        context["cipher_suite"] = cipher_info[0]
                        context["cipher_bits"] = cipher_info[2]

                    if tls_ver in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        context["is_deprecated_tls"] = True

                    # Certificate expiration check
                    if cert and "notAfter" in cert:
                        # e.g. 'Oct 25 12:00:00 2026 GMT'
                        expiry_str = cert["notAfter"]
                        try:
                            expiry_dt = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                            expiry_dt = expiry_dt.replace(tzinfo=datetime.timezone.utc)
                            now_dt = datetime.datetime.now(datetime.timezone.utc)
                            delta = expiry_dt - now_dt
                            context["cert_days_remaining"] = delta.days
                            context["cert_expiry_date"] = expiry_dt.strftime("%Y-%m-%d")
                            if delta.days <= 0:
                                context["cert_is_expired"] = True
                        except Exception:
                            pass
        except Exception as e:
            context["errors"].append(f"Direct TLS handshake observation error: {str(e)}")

    @classmethod
    def _parse_csp_policy(cls, csp_val: str, context: Dict[str, Any]):
        """
        Parses Content-Security-Policy into structured directives and flags vulnerabilities.
        """
        directives: Dict[str, List[str]] = {}
        for part in csp_val.split(";"):
            tokens = part.strip().split()
            if tokens:
                d_name = tokens[0].lower()
                d_vals = [t.lower() for t in tokens[1:]]
                directives[d_name] = d_vals

        context["csp_directives"] = directives

        # Check frame-ancestors
        if "frame-ancestors" in directives:
            context["has_frame_ancestors"] = True

        # Check script-src / default-src
        script_sources = directives.get("script-src", directives.get("default-src", []))

        if "'unsafe-inline'" in script_sources:
            context["csp_has_unsafe_inline"] = True
        if "'unsafe-eval'" in script_sources:
            context["csp_has_unsafe_eval"] = True
        if "*" in script_sources:
            context["csp_has_wildcard"] = True

        # Check missing object-src
        if "object-src" not in directives and "default-src" not in directives:
            context["csp_missing_object_src"] = True
        elif "object-src" in directives and "'none'" not in directives["object-src"]:
            context["csp_missing_object_src"] = True

        # Check missing base-uri
        if "base-uri" not in directives:
            context["csp_missing_base_uri"] = True

    @classmethod
    def _audit_cookies(cls, resp: requests.Response, context: Dict[str, Any]):
        """
        Deep cookie evaluation for Secure, HttpOnly, SameSite, and prefix security.
        """
        for cookie in resp.cookies:
            httponly = bool(cookie.has_nonstandard_attr("HttpOnly"))
            samesite = cookie.get_nonstandard_attr("SameSite")
            is_secure = cookie.secure

            c_info = {
                "name": cookie.name,
                "secure": is_secure,
                "httponly": httponly,
                "samesite": samesite,
            }
            context["cookies"].append(c_info)

            issues = []
            if not is_secure and context["is_https"]:
                issues.append("Missing Secure flag (can leak over HTTP)")
            if not httponly:
                issues.append("Missing HttpOnly flag (accessible to JavaScript / XSS)")
            if not samesite or str(samesite).lower() in ("none", "null"):
                issues.append("Missing or permissive SameSite (CSRF exposure)")

            if issues:
                c_info["issues"] = issues
                context["insecure_cookies"].append(c_info)

    @classmethod
    def _probe_sensitive_files(cls, session: requests.Session, scheme: str, hostname: str, context: Dict[str, Any]):
        """
        High-accuracy signature-verified checks to prevent soft-404 false positives.
        """
        base_url = f"{scheme}://{hostname}"

        # 1. robots.txt
        try:
            r_resp = session.get(f"{base_url}/robots.txt", timeout=3)
            if r_resp.status_code == 200 and "user-agent" in r_resp.text.lower() and not cls._is_html(r_resp.text):
                context["robots_txt_found"] = True
                sensitive_keywords = ["admin", "wp-admin", "login", "internal", "backup", "secret", "config", "db", "portal"]
                for line in r_resp.text.splitlines():
                    clean = line.strip().lower()
                    if clean.startswith("disallow:"):
                        for kw in sensitive_keywords:
                            if kw in clean and line.strip() not in context["robots_sensitive_paths"]:
                                context["robots_sensitive_paths"].append(line.strip())
        except Exception:
            pass

        # 2. security.txt
        try:
            s_resp = session.get(f"{base_url}/.well-known/security.txt", timeout=3)
            if s_resp.status_code == 200 and "contact:" in s_resp.text.lower() and not cls._is_html(s_resp.text):
                context["security_txt_found"] = True
        except Exception:
            pass

        # 3. .git/HEAD signature verification (Strict signature: must start with 'ref: refs/' or 40 hex chars)
        try:
            g_resp = session.get(f"{base_url}/.git/HEAD", timeout=3)
            if g_resp.status_code == 200 and not cls._is_html(g_resp.text):
                g_text = g_resp.text.strip()
                if g_text.startswith("ref: refs/") or (len(g_text) == 40 and re.match(r"^[0-9a-f]{40}$", g_text)):
                    context["git_exposed"] = True
                    context["git_evidence"] = g_text[:60]
        except Exception:
            pass

        # 4. .env signature verification (Strict signature: must match KEY=VALUE and contain known environment keys)
        try:
            env_resp = session.get(f"{base_url}/.env", timeout=3)
            if env_resp.status_code == 200 and not cls._is_html(env_resp.text):
                env_text = env_resp.text
                if any(k in env_text for k in ["APP_ENV=", "DB_PASSWORD=", "AWS_SECRET=", "DATABASE_URL=", "SECRET_KEY="]):
                    context["env_exposed"] = True
                    context["env_evidence"] = "Exposed environment configuration with sensitive keys identified."
        except Exception:
            pass

    @classmethod
    def _is_html(cls, text: str) -> bool:
        """Determines if returned content is an HTML webpage (e.g. custom soft 404)."""
        t = text.lstrip().lower()
        return t.startswith("<!doctype html") or t.startswith("<html") or "<body" in t or "<div" in t
