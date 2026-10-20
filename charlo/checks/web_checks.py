"""
Advanced Deep Website and Web Application Security Checks for CHARLO Testing Agent.
High-accuracy checks evaluating transport security, CSP directives, cookie attributes,
zero-false-positive file exposure signatures, and CORS headers.
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
class WebCheckHTTPS(BaseCheck):
    check_id = "WEB-001"
    name = "Missing HTTPS Enforcement"
    description = "Verifies that communication requires HTTPS and unencrypted HTTP requests automatically redirect to secure HTTPS."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Transport Encryption"
    default_severity = Severity.HIGH
    standards = ["CWE-319", "OWASP Top 10 A02:2021", "NIST SP 800-52"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Invalid target URL or connection failed.")

        if not context.get("is_https", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title="HIGH: Website Serves Content Over Insecure Cleartext HTTP",
                affected_component=f"Transport Layer -> {context.get('normalized_url')}",
                evidence=f"Active connection established via unencrypted HTTP. Status code: {context.get('status_code')}",
                impact="Cleartext transmission allows Man-in-the-Middle (MitM) attackers on local Wi-Fi to eavesdrop on user credentials and inject malicious scripts.",
                remediation="Configure web server to enforce 301 Permanent Redirects to HTTPS with valid TLS certificates.",
                code_example="return 301 https://$host$request_uri;",
                verification_step="Request http://target.com using curl -I and verify HTTP 301 redirect to https://.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: HTTPS is enforced",
            evidence=f"Secure HTTPS TLS connection verified on {context.get('normalized_url')}.",
        )


@CheckRegistry.register
class WebCheckHSTS(BaseCheck):
    check_id = "WEB-002"
    name = "Missing Strict-Transport-Security (HSTS)"
    description = "Verifies presence of Strict-Transport-Security with max-age >= 31536000 and includeSubDomains to prevent SSL stripping."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Security Headers"
    default_severity = Severity.MEDIUM
    standards = ["CWE-319", "OWASP Top 10 A05:2021", "RFC 6797"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Web audit failed.")

        if not context.get("hsts_present", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.MEDIUM,
                title="MEDIUM: Missing HTTP Strict-Transport-Security (HSTS) Header",
                affected_component="HTTP Response Headers -> Strict-Transport-Security",
                evidence="Header 'Strict-Transport-Security' not returned by web server.",
                impact="Browsers visiting the site via initial http:// bookmarks or links remain susceptible to SSL stripping attacks before redirection completes.",
                remediation="Add Strict-Transport-Security header with a minimum 1-year max-age (31536000) and includeSubDomains directive.",
                code_example="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                verification_step="Inspect response headers using curl -I https://target.com | grep -i strict-transport-security",
            )

        val = context.get("hsts_value", "")
        max_age = context.get("hsts_max_age")
        if max_age is None:
            import re
            m = re.search(r"max-age\s*=\s*([0-9]+)", val, re.IGNORECASE)
            max_age = int(m.group(1)) if m else 0

        has_sub = context.get("hsts_includes_subdomains")
        if has_sub is None:
            has_sub = "includesubdomains" in val.lower()

        if max_age < 31536000 or not has_sub:
            sub_note = "includes includeSubDomains" if has_sub else "missing includeSubDomains"
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.LOW,
                title="LOW: Suboptimal HSTS Configuration (Short max-age or Missing includeSubDomains)",
                affected_component="HTTP Response Headers -> Strict-Transport-Security",
                evidence=f"HSTS configured with max-age={max_age} seconds ({sub_note}). Value: {context.get('hsts_value')}",
                impact="HSTS durations under 1 year or missing subdomain coverage leave subdomains vulnerable to SSL stripping.",
                remediation="Increase max-age to 31536000 (1 year) and include the includeSubDomains directive.",
                code_example="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                verification_step="Verify max-age >= 31536000.",
            )

        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Robust HSTS policy enforced (>= 1 Year + includeSubDomains)",
            evidence=f"Strict-Transport-Security: {context.get('hsts_value')}",
        )


@CheckRegistry.register
class WebCheckCSP(BaseCheck):
    check_id = "WEB-003"
    name = "Missing or Permissive Content-Security-Policy (CSP)"
    description = "Audits Content-Security-Policy header. Absence or usage of 'unsafe-inline' / 'unsafe-eval' exposes site to Cross-Site Scripting (XSS)."
    target_type = TargetType.WEB
    level = ScanLevel.INTERMEDIATE
    category = "Security Headers"
    default_severity = Severity.HIGH
    standards = ["CWE-1021", "OWASP Top 10 A03:2021", "W3C CSP Level 3"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Web audit failed.")

        if not context.get("csp_present", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title="HIGH: Missing Content-Security-Policy (CSP) Header",
                affected_component="HTTP Response Headers -> Content-Security-Policy",
                evidence="Content-Security-Policy header is absent.",
                impact="Without a CSP, the browser will execute any injected JavaScript or external resources, leaving users vulnerable to Stored and Reflected XSS attacks.",
                remediation="Deploy a strict Content-Security-Policy restricting script sources to trusted nonces or self.",
                code_example="Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'; object-src 'none'; base-uri 'self';",
                verification_step="Verify header using Google CSP Evaluator (csp-evaluator.withgoogle.com).",
            )

        flaws = []
        if context.get("csp_has_unsafe_inline", False):
            flaws.append("'unsafe-inline'")
        if context.get("csp_has_unsafe_eval", False):
            flaws.append("'unsafe-eval'")
        if context.get("csp_has_wildcard", False):
            flaws.append("wildcard '*' source")
        if context.get("csp_missing_object_src", False):
            flaws.append("missing object-src 'none'")
        if context.get("csp_missing_base_uri", False):
            flaws.append("missing base-uri 'self'")

        if flaws:
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title=f"MEDIUM: CSP Contains Insecure Directives ({', '.join(flaws)})",
                affected_component="HTTP Response Headers -> Content-Security-Policy",
                evidence=f"Policy contains deficiencies: {', '.join(flaws)}. Raw CSP: {context.get('csp_value', '')[:120]}...",
                impact="Permitting 'unsafe-inline', wildcards, or missing object-src neutralizes modern XSS protections by allowing inline scripts and plugin injection.",
                remediation="Refactor inline scripts to external bundle files and utilize cryptographic nonces ('nonce-...') with object-src 'none'.",
                code_example="Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; object-src 'none'; base-uri 'self';",
                verification_step="Ensure no 'unsafe-inline' appears in script-src.",
            )

        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Strict Content-Security-Policy is enforced",
            evidence=f"CSP configured: {context.get('csp_value', '')[:80]}...",
        )


@CheckRegistry.register
class WebCheckXFrameOptions(BaseCheck):
    check_id = "WEB-004"
    name = "Missing X-Frame-Options Clickjacking Defense"
    description = "Checks for X-Frame-Options: DENY or SAMEORIGIN preventing iframe overlay clickjacking attacks."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Security Headers"
    default_severity = Severity.MEDIUM
    standards = ["CWE-1021", "OWASP Top 10 A05:2021"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Web audit failed.")

        xfo = context.get("x_frame_options")
        has_fa = context.get("has_frame_ancestors", False)

        if not xfo and not has_fa:
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.MEDIUM,
                title="MEDIUM: Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                affected_component="HTTP Response Headers -> X-Frame-Options",
                evidence="Neither X-Frame-Options nor CSP frame-ancestors is present.",
                impact="An attacker can frame this site inside an invisible iframe on a malicious webpage, tricking authenticated users into clicking sensitive controls.",
                remediation="Configure web server to return X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'.",
                code_example="X-Frame-Options: SAMEORIGIN\n# Or via CSP:\nContent-Security-Policy: frame-ancestors 'self';",
                verification_step="Test embedding target URL in an HTML iframe on a distinct domain.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: Clickjacking protection is active",
            evidence=f"Framing protection verified ({xfo or 'frame-ancestors'}).",
        )


@CheckRegistry.register
class WebCheckContentTypeOptions(BaseCheck):
    check_id = "WEB-005"
    name = "Missing X-Content-Type-Options Header"
    description = "Verifies X-Content-Type-Options: nosniff to prevent browsers from MIME-sniffing responses away from the declared content-type."
    target_type = TargetType.WEB
    level = ScanLevel.BASIC
    category = "Security Headers"
    default_severity = Severity.LOW
    standards = ["CWE-430", "OWASP Top 10 A05:2021"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Web audit failed.")

        xcto = context.get("x_content_type_options")
        if not xcto or "nosniff" not in xcto.lower():
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.LOW,
                title="LOW: Missing X-Content-Type-Options: nosniff Header",
                affected_component="HTTP Response Headers -> X-Content-Type-Options",
                evidence=f"Header is missing or not set to 'nosniff' (Value: {xcto}).",
                impact="Browsers may attempt to MIME-sniff file downloads, potentially executing uploaded text or SVG files as JavaScript.",
                remediation="Add X-Content-Type-Options: nosniff header to all HTTP responses.",
                code_example="X-Content-Type-Options: nosniff",
                verification_step="Inspect HTTP response headers for 'X-Content-Type-Options: nosniff'.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: X-Content-Type-Options: nosniff is configured",
            evidence="Header verified.",
        )


@CheckRegistry.register
class WebCheckCookies(BaseCheck):
    check_id = "WEB-007"
    name = "Insecure Cookie Flags (Secure, HttpOnly, SameSite)"
    description = "Audits Set-Cookie headers for Secure, HttpOnly, and SameSite attributes."
    target_type = TargetType.WEB
    level = ScanLevel.INTERMEDIATE
    category = "Session & Cookies"
    default_severity = Severity.MEDIUM
    standards = ["CWE-614", "CWE-1004", "OWASP Top 10 A07:2021"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Web audit failed.")

        insecure = context.get("insecure_cookies", [])
        if insecure:
            details = [f"{c['name']} ({', '.join(c.get('issues', []))})" for c in insecure[:3]]
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.MEDIUM,
                title=f"MEDIUM: Insecure Cookie Flags Detected on {len(insecure)} Cookie(s)",
                affected_component="HTTP Response Headers -> Set-Cookie",
                evidence=f"Cookies with missing security flags: {', '.join(details)}",
                impact="Missing HttpOnly permits JavaScript access to session cookies (facilitating XSS token theft); missing Secure permits transmission over cleartext; missing SameSite facilitates CSRF.",
                remediation="Configure all cookies with Secure; HttpOnly; SameSite=Lax (or Strict).",
                code_example="Set-Cookie: session_id=abc123xyz; Secure; HttpOnly; SameSite=Lax; Path=/",
                verification_step="Inspect Set-Cookie headers in browser developer tools.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: All observed cookies have secure attributes configured",
            evidence=f"Audited {len(context.get('cookies', []))} cookies; no flag deficiencies identified.",
        )


@CheckRegistry.register
class WebCheckGitExposure(BaseCheck):
    check_id = "WEB-017"
    name = "Exposed Git Repository Metadata (.git/HEAD)"
    description = "Safe check for publicly accessible .git/ folder allowing source code reconstruction."
    target_type = TargetType.WEB
    level = ScanLevel.INTERMEDIATE
    category = "Information Disclosure"
    default_severity = Severity.CRITICAL
    standards = ["CWE-538", "OWASP Top 10 A05:2021"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Web audit failed.")

        if context.get("git_exposed", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.CRITICAL,
                title="CRITICAL: Publicly Accessible .git/ Repository Identified",
                affected_component="Web Root -> /.git/HEAD",
                evidence=f"Verified Git signature in response: {context.get('git_evidence')}",
                impact="Attackers can download the entire .git repository using tools like git-dumper, reconstructing the entire application source code, commit history, and embedded credentials.",
                remediation="Block access to .git and all hidden files (.dotfiles) in web server configuration.",
                code_example="# Nginx:\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}",
                verification_step="Request /.git/HEAD and verify HTTP 404 or 403 response.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No exposed .git repository metadata detected",
            evidence="/.git/HEAD is not publicly accessible.",
        )


@CheckRegistry.register
class WebCheckEnvExposure(BaseCheck):
    check_id = "WEB-018"
    name = "Exposed Environment Configuration (.env)"
    description = "Safe check for publicly accessible .env configuration files containing database and API credentials."
    target_type = TargetType.WEB
    level = ScanLevel.INTERMEDIATE
    category = "Credentials & Secrets"
    default_severity = Severity.CRITICAL
    standards = ["CWE-538", "OWASP Top 10 A05:2021"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url"):
            return self.create_finding(CheckStatus.INCONCLUSIVE, evidence="Web audit failed.")

        if context.get("env_exposed", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.CRITICAL,
                title="CRITICAL: Publicly Accessible .env Environment File Disclosed",
                affected_component="Web Root -> /.env",
                evidence=context.get("env_evidence", "Verified valid environment file signature."),
                impact="Exposed .env files leak production database passwords, AWS secret keys, mail credentials, and private application secrets directly to the internet.",
                remediation="Store .env files outside of the web server document root and block all dotfile requests in web server configuration.",
                code_example="# Nginx:\nlocation ~ /\\.(?!well-known).* {\n    deny all;\n}",
                verification_step="Request /.env and confirm HTTP 404/403.",
            )
        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title="PASSED: No exposed .env configuration file detected",
            evidence="/.env is not accessible.",
        )


@CheckRegistry.register
class WebCheckTLSVersion(BaseCheck):
    check_id = "WEB-020"
    name = "Weak / Deprecated TLS Ciphers & Protocol Version"
    description = "Audits TLS handshake for deprecated TLS 1.0/1.1 protocols and expired certificates."
    target_type = TargetType.WEB
    level = ScanLevel.INTERMEDIATE
    category = "Transport Encryption"
    default_severity = Severity.HIGH
    standards = ["CWE-326", "NIST SP 800-52"]

    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        if not context.get("valid_url") or not context.get("is_https"):
            return self.create_finding(CheckStatus.NOT_APPLICABLE, evidence="Target does not serve HTTPS.")

        tls_ver = context.get("tls_version", "Unknown")
        cipher = context.get("cipher_suite", "Unknown")
        days_left = context.get("cert_days_remaining", 0)

        if context.get("cert_is_expired", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.CRITICAL,
                title="CRITICAL: SSL/TLS Certificate Has Expired",
                affected_component="TLS Layer -> Certificate Expiration",
                evidence=f"Certificate expired on {context.get('cert_expiry_date')} ({days_left} days ago).",
                impact="Expired certificates trigger prominent browser security warnings, breaking user trust and blocking access for most visitors.",
                remediation="Immediately renew and deploy a valid TLS certificate.",
                verification_step="Check certificate validity dates via openssl s_client.",
            )

        if context.get("is_deprecated_tls", False):
            return self.create_finding(
                CheckStatus.FAILED,
                severity=Severity.HIGH,
                title=f"HIGH: Deprecated Legacy Transport Protocol Negotiated ({tls_ver})",
                affected_component="TLS Handshake -> Protocol Version",
                evidence=f"Negotiated deprecated protocol {tls_ver} with cipher {cipher}.",
                impact="TLS 1.0 and 1.1 are cryptographically broken and deprecated by all modern browsers (PCI-DSS compliance violation).",
                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 in web server configuration; enforce TLS 1.2 and TLS 1.3 only.",
                code_example="ssl_protocols TLSv1.2 TLSv1.3;",
                verification_step="Verify TLS 1.2/1.3 negotiation with openssl s_client -tls1_3.",
            )

        if days_left > 0 and days_left <= 14:
            return self.create_finding(
                CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                title=f"MEDIUM: SSL/TLS Certificate Expiring Soon ({days_left} Days Remaining)",
                affected_component="TLS Layer -> Certificate Expiration",
                evidence=f"Certificate expires on {context.get('cert_expiry_date')} ({days_left} days left).",
                impact="If not renewed promptly, the website will trigger blocking browser security alerts.",
                remediation="Automate certificate renewal via ACME / Let's Encrypt or deploy renewed certificate.",
                verification_step="Ensure automated renewal cron or certbot timer is running.",
            )

        return self.create_finding(
            CheckStatus.PASSED,
            severity=Severity.INFO,
            title=f"PASSED: Modern TLS ({tls_ver}) and Cipher Active",
            evidence=f"Negotiated {tls_ver} with cipher {cipher} ({context.get('cipher_bits')} bits). Certificate valid for {days_left} days.",
        )
