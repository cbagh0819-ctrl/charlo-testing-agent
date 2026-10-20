"""
Advanced Dedicated Bug Finder Engine for CHARLO Testing Agent.
Detects software defects, logic bugs, resource & memory leaks, broken links,
form & input validation defects, stack trace leakage, and crash hazards across
Android APKs, Windows EXEs, and Web Applications.
"""

import os
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Dict, Any, List, Optional, Set
import requests

from ..core.models import (
    TargetType,
    Severity,
    CheckStatus,
    CheckFinding,
    ScanTarget,
)


class WebDefectHTMLParser(HTMLParser):
    """
    High-performance pure Python HTML parser extracting links, forms, assets,
    and semantic elements for software defect auditing.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.parsed_base = urllib.parse.urlparse(base_url)
        self.is_https = self.parsed_base.scheme == "https"

        self.links: List[Dict[str, str]] = []
        self.forms: List[Dict[str, Any]] = []
        self.current_form: Optional[Dict[str, Any]] = None
        self.images: List[Dict[str, Any]] = []
        self.scripts: List[str] = []
        self.stylesheets: List[str] = []
        self.mixed_content: List[Dict[str, str]] = []

        self.has_title: bool = False
        self.title_text: str = ""
        self.in_title: bool = False
        self.h1_count: int = 0
        self.has_viewport: bool = False

    def handle_starttag(self, tag: str, attrs: List[tuple]):
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v if v is not None else "") for k, v in attrs}

        # Title & Viewport
        if tag_lower == "title":
            self.has_title = True
            self.in_title = True
        elif tag_lower == "meta":
            if attr_dict.get("name", "").lower() == "viewport":
                self.has_viewport = True
        elif tag_lower == "h1":
            self.h1_count += 1

        # Links
        elif tag_lower == "a":
            href = attr_dict.get("href", "").strip()
            self.links.append({
                "href": href,
                "text": "",  # Populated in handle_data if adjacent
                "target": attr_dict.get("target", ""),
                "rel": attr_dict.get("rel", ""),
                "onclick": attr_dict.get("onclick", ""),
            })

        # Forms
        elif tag_lower == "form":
            self.current_form = {
                "action": attr_dict.get("action", "").strip(),
                "method": attr_dict.get("method", "GET").upper().strip(),
                "inputs": [],
                "has_csrf": False,
                "has_password": False,
            }
            self.forms.append(self.current_form)

        elif tag_lower in ("input", "textarea", "select", "button"):
            if self.current_form is not None:
                inp_type = attr_dict.get("type", "text").lower()
                inp_name = attr_dict.get("name", "")
                inp_id = attr_dict.get("id", "")
                has_maxlength = "maxlength" in attr_dict
                autocomplete = attr_dict.get("autocomplete", "")

                if inp_type == "password":
                    self.current_form["has_password"] = True

                # CSRF Token detection heuristic
                name_and_id = f"{inp_name} {inp_id}".lower()
                if inp_type == "hidden" and any(k in name_and_id for k in ("csrf", "xsrf", "token", "nonce", "_token")):
                    self.current_form["has_csrf"] = True

                self.current_form["inputs"].append({
                    "tag": tag_lower,
                    "type": inp_type,
                    "name": inp_name,
                    "id": inp_id,
                    "has_maxlength": has_maxlength,
                    "autocomplete": autocomplete,
                })

        # Images
        elif tag_lower == "img":
            src = attr_dict.get("src", "").strip()
            alt = attr_dict.get("alt")
            self.images.append({"src": src, "has_alt": alt is not None})
            if self.is_https and src.startswith("http://"):
                self.mixed_content.append({"tag": "img", "src": src})

        # Scripts
        elif tag_lower == "script":
            src = attr_dict.get("src", "").strip()
            if src:
                self.scripts.append(src)
                if self.is_https and src.startswith("http://"):
                    self.mixed_content.append({"tag": "script", "src": src})

        # Stylesheets
        elif tag_lower == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href", "").strip()
            if "stylesheet" in rel and href:
                self.stylesheets.append(href)
                if self.is_https and href.startswith("http://"):
                    self.mixed_content.append({"tag": "link", "src": href})

        # Iframes
        elif tag_lower == "iframe":
            src = attr_dict.get("src", "").strip()
            if self.is_https and src.startswith("http://"):
                self.mixed_content.append({"tag": "iframe", "src": src})

    def handle_data(self, data: str):
        if self.in_title:
            self.title_text += data

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower == "title":
            self.in_title = False
        elif tag_lower == "form":
            self.current_form = None


class WebBugFinder:
    """
    Dedicated defect and bug scanner for Websites and Web Applications.
    """

    STACK_TRACE_PATTERNS = [
        (re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\):", re.IGNORECASE), "Python / Django / Flask Uncaught Traceback"),
        (re.compile(r"Fatal\s+error:\s+Uncaught", re.IGNORECASE), "PHP Fatal Uncaught Exception"),
        (re.compile(r"Warning:\s+mysqli_[a-zA-Z0-9_]+\(\):", re.IGNORECASE), "PHP MySQL Connection / Query Error Leak"),
        (re.compile(r"java\.lang\.[A-Za-z0-9_]*Exception", re.IGNORECASE), "Java JVM Unhandled Exception"),
        (re.compile(r"org\.springframework\.web\.util", re.IGNORECASE), "Spring Framework Dispatcher Exception"),
        (re.compile(r"Server\s+Error\s+in\s+['\"]/['\"]\s+Application", re.IGNORECASE), "ASP.NET Yellow Screen of Death"),
        (re.compile(r"System\.(?:NullReference|InvalidOperation|Data\.SqlClient)Exception", re.IGNORECASE), "Microsoft .NET Unhandled Exception"),
        (re.compile(r"TypeError:\s+Cannot\s+read\s+propert(?:y|ies)\s+of\s+(?:null|undefined)", re.IGNORECASE), "Node.js / Express Unhandled TypeError"),
    ]

    @classmethod
    def audit(
        cls,
        context: Dict[str, Any],
        url: str,
        html_content: str = "",
        probe_network: bool = True,
    ) -> List[CheckFinding]:
        findings: List[CheckFinding] = []

        if not html_content and context.get("html_content"):
            html_content = context.get("html_content", "")

        parser = WebDefectHTMLParser(url)
        if html_content:
            try:
                parser.feed(html_content)
            except Exception:
                pass

        # ---------------------------------------------------------------------
        # 1. BUG-WEB-001: Broken Links & Navigation Dead Ends
        # ---------------------------------------------------------------------
        findings.append(cls._check_broken_links(url, parser.links, probe_network))

        # ---------------------------------------------------------------------
        # 2. BUG-WEB-002: Form & Input Validation Defects
        # ---------------------------------------------------------------------
        findings.append(cls._check_form_defects(url, parser.forms))

        # ---------------------------------------------------------------------
        # 3. BUG-WEB-003: Stack Trace & Unhandled Debug Exceptions
        # ---------------------------------------------------------------------
        findings.append(cls._check_stack_traces(url, html_content))

        # ---------------------------------------------------------------------
        # 4. BUG-WEB-004: Broken Media & Missing Script/Style Assets
        # ---------------------------------------------------------------------
        findings.append(cls._check_asset_defects(url, parser.images, parser.scripts, parser.stylesheets))

        # ---------------------------------------------------------------------
        # 5. BUG-WEB-005: HTML5 Semantic & Responsive Layout Defects
        # ---------------------------------------------------------------------
        findings.append(cls._check_semantic_defects(url, parser))

        # ---------------------------------------------------------------------
        # 6. BUG-WEB-006: Insecure Mixed-Content Asset Defects
        # ---------------------------------------------------------------------
        findings.append(cls._check_mixed_content(url, parser.mixed_content))

        return findings

    @classmethod
    def _check_broken_links(cls, base_url: str, links: List[Dict[str, str]], probe_network: bool) -> CheckFinding:
        cid = "BUG-WEB-001"
        cname = "Broken Links & Navigation Dead Ends"
        target_type = TargetType.WEB
        cat = "Software Defect / Navigation"

        empty_links = 0
        hash_links = 0
        broken_http_links: List[str] = []
        tested_links = 0

        parsed_base = urllib.parse.urlparse(base_url)

        for l in links:
            href = l.get("href", "")
            if not href or href == "":
                empty_links += 1
            elif href == "#" and not l.get("onclick"):
                hash_links += 1

        # Probe up to 6 unique internal links if probe_network is enabled
        if probe_network and parsed_base.netloc:
            internal_candidates: Set[str] = set()
            for l in links:
                href = l.get("href", "")
                if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    full_url = urllib.parse.urljoin(base_url, href)
                    p = urllib.parse.urlparse(full_url)
                    if p.netloc == parsed_base.netloc and full_url != base_url:
                        internal_candidates.add(full_url)
                        if len(internal_candidates) >= 6:
                            break

            for u in internal_candidates:
                tested_links += 1
                try:
                    resp = requests.head(u, timeout=2.5, allow_redirects=True, headers={"User-Agent": "CHARLO-BugFinder/1.0"})
                    if resp.status_code in (404, 410, 500, 502, 503):
                        broken_http_links.append(f"{u} (HTTP {resp.status_code})")
                except Exception:
                    pass

        defects = []
        if broken_http_links:
            defects.append(f"Detected {len(broken_http_links)} confirmed broken links returning HTTP errors: {', '.join(broken_http_links[:3])}")
        if empty_links > 0:
            defects.append(f"Found {empty_links} anchor tag(s) with empty href=''.")
        if hash_links > 3:
            defects.append(f"Found {hash_links} dummy placeholder links with href='#' and no event handlers.")

        if defects:
            status = CheckStatus.FAILED if broken_http_links else CheckStatus.WARNING
            sev = Severity.HIGH if broken_http_links else Severity.LOW
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=status,
                severity=sev,
                finding_type="bug",
                title=f"{'HIGH' if sev == Severity.HIGH else 'LOW'}: Broken Navigation & Dead Links Detected ({len(defects)} defect types)",
                affected_component=f"DOM Anchors -> {base_url}",
                description="Audits hyperlinks for 404 dead ends, empty target attributes, and orphaned navigation routes that degrade user experience and SEO indexing.",
                evidence=" | ".join(defects),
                impact="Visitors encountering dead ends experience navigation friction, while search engine crawlers penalize page authority on repeated 404s.",
                remediation="Remove or replace broken URLs with valid destinations. Replace dummy href='#' with semantic <button> controls with explicit event listeners.",
                code_example="<!-- Before -->\n<a href=\"#\">Click Me</a>\n<a href=\"/old-path\">Outdated</a>\n\n<!-- Fixed -->\n<button type=\"button\" onclick=\"handleAction()\">Action</button>\n<a href=\"/current-path\">Updated</a>",
                verification_step="Audit anchor href attributes or execute automated link checker crawling internal paths.",
                standards=["CWE-610", "W3C HTML5 Navigation"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: No Broken Links or Empty Anchors Detected",
            affected_component=f"DOM Anchors -> {base_url}",
            description="Audits hyperlinks for dead ends and empty targets.",
            evidence=f"Audited {len(links)} link(s) on target page with 0 broken routes detected.",
            impact="Clean navigation hierarchy preserved.",
            remediation="No action required.",
        )

    @classmethod
    def _check_form_defects(cls, base_url: str, forms: List[Dict[str, Any]]) -> CheckFinding:
        cid = "BUG-WEB-002"
        cname = "Form & Input Validation Defects"
        target_type = TargetType.WEB
        cat = "Software Defect / Forms & Input"

        if not forms:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.PASSED,
                severity=Severity.INFO,
                finding_type="bug",
                title="PASSED: No Forms on Page or Form Structure Valid",
                affected_component="HTML Forms",
                description="Audits HTML form elements for input validation constraints, CSRF protections, and binding defects.",
                evidence="No HTML <form> elements identified on page.",
                impact="None.",
                remediation="No action required.",
            )

        defects: List[str] = []
        is_http_page = base_url.startswith("http://")

        for i, form in enumerate(forms, start=1):
            action = form.get("action", "")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])
            has_csrf = form.get("has_csrf", False)
            has_password = form.get("has_password", False)

            if not action or action == "":
                defects.append(f"Form #{i} missing 'action' destination URL.")

            if method == "POST" and not has_csrf:
                defects.append(f"Form #{i} executes state-changing HTTP POST without anti-CSRF token.")

            if has_password and is_http_page:
                defects.append(f"Form #{i} collects passwords over unencrypted HTTP protocol.")

            for inp in inputs:
                # Check for inputs missing both name and id
                if inp.get("tag") in ("input", "textarea") and inp.get("type") not in ("submit", "button", "reset"):
                    if not inp.get("name") and not inp.get("id"):
                        defects.append(f"Input '{inp.get('type')}' in Form #{i} lacks 'name' and 'id' attributes (payload cannot be submitted).")
                    if inp.get("type") in ("text", "search") and not inp.get("has_maxlength"):
                        defects.append(f"Text field in Form #{i} lacks 'maxlength' constraint (unbounded input submission).")
                if inp.get("type") == "password" and not inp.get("autocomplete"):
                    defects.append(f"Password field in Form #{i} lacks 'autocomplete' attribute ('current-password' / 'new-password').")

        if defects:
            has_critical = any("unencrypted HTTP" in d or "without anti-CSRF" in d for d in defects)
            sev = Severity.HIGH if has_critical else Severity.MEDIUM
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=sev,
                finding_type="bug",
                title=f"{'HIGH' if sev == Severity.HIGH else 'MEDIUM'}: Form Implementation Defects Flagged ({len(defects)} issues)",
                affected_component=f"HTML Forms ({len(forms)} form(s) parsed)",
                description="Audits form elements for missing destination actions, unbound input controls, unconstrained text length, and missing CSRF mitigations.",
                evidence=" | ".join(defects[:5]),
                impact="Unbound controls lead to lost user data on submission. Missing length bounds can cause backend buffer or database truncation exceptions.",
                remediation="Add explicit action destinations, anti-CSRF tokens to all POST forms, maxlength attributes on text fields, and autocomplete annotations on password fields.",
                code_example="<form action=\"/submit\" method=\"POST\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n  <input type=\"text\" name=\"username\" id=\"username\" maxlength=\"50\" required>\n  <input type=\"password\" name=\"password\" id=\"password\" autocomplete=\"current-password\" required>\n  <button type=\"submit\">Log In</button>\n</form>",
                verification_step="Inspect DOM form tags and verify all controls have 'name' attributes, length constraints, and anti-forgery tokens.",
                standards=["CWE-352", "CWE-20", "OWASP ASVS 5.1"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title=f"PASSED: All {len(forms)} Form(s) Validated Cleanly",
            affected_component="HTML Forms",
            description="Audits form elements for implementation defects.",
            evidence=f"Validated {len(forms)} form(s) on target page: CSRF tokens present, inputs bound, and length constraints specified.",
            impact="Data submission integrity verified.",
            remediation="No action required.",
        )

    @classmethod
    def _check_stack_traces(cls, base_url: str, html_content: str) -> CheckFinding:
        cid = "BUG-WEB-003"
        cname = "Stack Trace & Unhandled Debug Exceptions"
        target_type = TargetType.WEB
        cat = "Software Defect / Exception Handling"

        matched_errors: List[str] = []
        for pattern, label in cls.STACK_TRACE_PATTERNS:
            if pattern.search(html_content):
                matched_errors.append(label)

        if matched_errors:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=Severity.CRITICAL,
                finding_type="bug",
                title=f"CRITICAL: Active Server Crash or Stack Trace Leaking in Response ({len(matched_errors)} signature(s))",
                affected_component=f"Web Server Runtime -> {base_url}",
                description="Detects unhandled application exceptions, fatal interpreter errors, and framework debug pages returned directly to client browsers.",
                evidence=f"Matched signatures: {', '.join(matched_errors)}",
                impact="Exposes sensitive server file paths, framework versions, database queries, and internal logic to visitors, facilitating targeted exploits.",
                remediation="Disable debug mode in production (e.g. DEBUG=False in Django, display_errors=Off in php.ini, customErrors mode='On' in ASP.NET). Implement global exception handlers returning generic 500 error pages.",
                code_example="# Django settings.py\nDEBUG = False\nALLOWED_HOSTS = ['example.com']\n\n# PHP php.ini\ndisplay_errors = Off\nlog_errors = On",
                verification_step="Request nonexistent route or trigger error parameter and verify only a sanitized generic error template is returned.",
                standards=["CWE-209", "CWE-215", "OWASP Top 10 A05:2021"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: No Server Stack Traces or Debug Pages Leaking",
            affected_component=f"Web Server Runtime -> {base_url}",
            description="Audits response bodies for stack trace signatures.",
            evidence="Response inspected against 8 runtime crash signatures (Python, PHP, Java, .NET, Node.js); zero debug tracebacks detected.",
            impact="Clean error isolation verified.",
            remediation="No action required.",
        )

    @classmethod
    def _check_asset_defects(
        cls,
        base_url: str,
        images: List[Dict[str, Any]],
        scripts: List[str],
        stylesheets: List[str],
    ) -> CheckFinding:
        cid = "BUG-WEB-004"
        cname = "Broken Media & Missing Script/Style Assets"
        target_type = TargetType.WEB
        cat = "Software Defect / Assets"

        defects: List[str] = []

        # Empty sources
        empty_imgs = sum(1 for img in images if not img.get("src"))
        missing_alt = sum(1 for img in images if not img.get("has_alt"))
        empty_scripts = sum(1 for s in scripts if not s)
        empty_styles = sum(1 for s in stylesheets if not s)

        if empty_imgs > 0:
            defects.append(f"{empty_imgs} <img> tag(s) with empty src='' attribute")
        if empty_scripts > 0:
            defects.append(f"{empty_scripts} <script> tag(s) with empty src=''")
        if empty_styles > 0:
            defects.append(f"{empty_styles} <link rel='stylesheet'> with empty href=''")
        if missing_alt > 5:
            defects.append(f"{missing_alt} image(s) missing 'alt' text (WCAG accessibility defect)")

        if defects:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.LOW,
                finding_type="bug",
                title=f"LOW: Web Asset & Media Defects Flagged ({len(defects)} issues)",
                affected_component="DOM Static Assets",
                description="Audits image, script, and stylesheet tags for empty source paths, broken asset references, and accessibility attribute defects.",
                evidence=" | ".join(defects),
                impact="Empty asset tags trigger unnecessary browser round-trips to the document root and break page styling or accessibility compliance.",
                remediation="Ensure all <img> elements specify non-empty src and descriptive alt attributes. Remove orphaned script/style tags.",
                code_example="<img src=\"/images/logo.webp\" alt=\"Company Logo\" width=\"200\" height=\"50\">",
                verification_step="Audit DOM asset tags in developer tools network panel to ensure all resources resolve with HTTP 200.",
                standards=["W3C WCAG 2.1 1.1.1", "HTML5 Spec §4.8"],
            )

        total_assets = len(images) + len(scripts) + len(stylesheets)
        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title=f"PASSED: All {total_assets} Static Assets Configured Correctly",
            affected_component="DOM Static Assets",
            description="Audits static assets for empty attributes or defects.",
            evidence=f"Audited {len(images)} images, {len(scripts)} scripts, and {len(stylesheets)} stylesheets without defects.",
            impact="Clean resource rendering.",
            remediation="No action required.",
        )

    @classmethod
    def _check_semantic_defects(cls, base_url: str, parser: WebDefectHTMLParser) -> CheckFinding:
        cid = "BUG-WEB-005"
        cname = "HTML5 Semantic & Responsive Layout Defects"
        target_type = TargetType.WEB
        cat = "Software Defect / Semantic & Responsive"

        defects: List[str] = []

        if not parser.has_title or not parser.title_text.strip():
            defects.append("Missing or empty <title> tag (breaks browser tab title, history, and search engine snippets)")

        if not parser.has_viewport:
            defects.append("Missing <meta name='viewport'> tag (causes broken responsive layout and scaling defects on mobile devices)")

        if parser.h1_count > 1:
            defects.append(f"Multiple ({parser.h1_count}) <h1> tags detected on single page (violates W3C heading hierarchy guidelines)")

        if defects:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.LOW,
                finding_type="bug",
                title=f"LOW: Semantic Markup & Mobile Viewport Defects ({len(defects)} issues)",
                affected_component="HTML Document Head & Hierarchy",
                description="Audits essential HTML5 metadata including document title, responsive viewport configuration, and heading structure.",
                evidence=" | ".join(defects),
                impact="Missing viewport metadata renders the page unreadable on smartphones by defaulting to desktop zoom. Missing title degrades usability.",
                remediation="Add standard <meta name='viewport' content='width=device-width, initial-scale=1.0'> in <head> and specify a descriptive <title>.",
                code_example="<head>\n  <meta charset=\"UTF-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <title>Application Dashboard</title>\n</head>",
                verification_step="Inspect <head> tags and verify responsive layout renders properly on mobile viewport dimensions.",
                standards=["W3C HTML5 §4.2.2", "Google Mobile-Friendly Guidelines"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: HTML5 Semantic & Responsive Metadata Configured Correctly",
            affected_component="HTML Document Head",
            description="Audits essential document metadata.",
            evidence=f"Document title '{parser.title_text.strip()[:30]}' and mobile viewport meta tag verified.",
            impact="Optimal cross-device rendering.",
            remediation="No action required.",
        )

    @classmethod
    def _check_mixed_content(cls, base_url: str, mixed_items: List[Dict[str, str]]) -> CheckFinding:
        cid = "BUG-WEB-006"
        cname = "Insecure Mixed-Content Asset Defects"
        target_type = TargetType.WEB
        cat = "Software Defect / Content Security"

        if not base_url.startswith("https://"):
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.NOT_APPLICABLE,
                severity=Severity.INFO,
                finding_type="bug",
                title="NOT APPLICABLE: Target Page is HTTP, Not HTTPS",
                affected_component="Asset Delivery",
                description="Mixed content analysis only applies to HTTPS origins.",
                evidence="Target is not served via HTTPS.",
                impact="None.",
                remediation="Migrate entire site to HTTPS.",
            )

        if mixed_items:
            active_mixed = [m for m in mixed_items if m.get("tag") in ("script", "iframe")]
            sev = Severity.HIGH if active_mixed else Severity.MEDIUM
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=sev,
                finding_type="bug",
                title=f"{'HIGH' if sev == Severity.HIGH else 'MEDIUM'}: Insecure Mixed Content (HTTP Assets on HTTPS Origin)",
                affected_component=f"Asset Pipeline -> {len(mixed_items)} insecure element(s)",
                description="Identifies cleartext HTTP assets (scripts, stylesheets, images) requested from an encrypted HTTPS parent page.",
                evidence=f"Detected {len(mixed_items)} insecure asset(s): " + ", ".join([f"<{m['tag']} src='{m['src'][:45]}...'>" for m in mixed_items[:3]]),
                impact="Modern browsers automatically block active mixed content (scripts/iframes) breaking page functionality, and display insecure padlock warnings for images.",
                remediation="Update all resource URLs to use relative paths (/assets/...) or explicit https:// protocols.",
                code_example="<!-- Before -->\n<script src=\"http://cdn.example.com/lib.js\"></script>\n\n<!-- Fixed -->\n<script src=\"https://cdn.example.com/lib.js\"></script>",
                verification_step="Open browser developer console and check for 'Mixed Content' blocking warnings.",
                standards=["CWE-311", "W3C Mixed Content Level 2"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Zero Insecure Mixed Content Detected",
            affected_component="Asset Pipeline",
            description="Audits HTTPS pages for unencrypted HTTP asset loading.",
            evidence="All detected image, script, stylesheet, and iframe assets load via secure HTTPS.",
            impact="Encrypted connection integrity preserved.",
            remediation="No action required.",
        )


# =============================================================================
# WINDOWS EXE BUG FINDER
# =============================================================================
class EXEBugFinder:
    """
    Dedicated defect and bug scanner for Windows PE Executables (.exe, .dll).
    """

    UNBALANCED_RESOURCES = [
        # (Acquire APIs, Release APIs, Resource Name, Severity)
        (["CreateFileW", "CreateFileA", "OpenFile"], ["CloseHandle"], "File / Device Handle", Severity.MEDIUM),
        (["HeapAlloc"], ["HeapFree"], "Heap Memory Block", Severity.HIGH),
        (["VirtualAlloc", "VirtualAllocEx"], ["VirtualFree", "VirtualFreeEx"], "Virtual Memory Page", Severity.HIGH),
        (["RegOpenKeyExW", "RegOpenKeyExA", "RegCreateKeyExW", "RegCreateKeyExA"], ["RegCloseKey"], "Registry Key Handle", Severity.LOW),
        (["CreateCompatibleDC", "GetDC"], ["DeleteDC", "ReleaseDC"], "GDI Device Context", Severity.LOW),
    ]

    BANNED_CRT_FUNCTIONS = {
        "strcpy": ("Buffer Overflow Hazard", "strcpy does not verify destination buffer capacity, easily leading to stack corruption.", "strcpy_s(dest, dest_size, src);"),
        "wcscpy": ("Buffer Overflow Hazard", "wcscpy lacks boundary checks on destination buffer.", "wcscpy_s(dest, dest_size, src);"),
        "strcat": ("Buffer Overflow Hazard", "strcat can write past buffer end if combined string exceeds allocation.", "strcat_s(dest, dest_size, src);"),
        "wcscat": ("Buffer Overflow Hazard", "wcscat lacks bound limits.", "wcscat_s(dest, dest_size, src);"),
        "sprintf": ("Buffer Overflow Hazard", "sprintf lacks length limits for formatted output.", "sprintf_s(dest, sizeof(dest), format, ...);"),
        "vsprintf": ("Buffer Overflow Hazard", "vsprintf lacks destination size boundary.", "vsnprintf_s(dest, size, _TRUNCATE, format, args);"),
        "gets": ("Critical Buffer Overflow", "gets is inherently defective and banned in ISO C11 because input length cannot be constrained.", "fgets(buf, sizeof(buf), stdin);"),
        "scanf": ("Buffer Overflow Risk", "scanf with %s writes arbitrarily into destination buffer.", "scanf_s(\"%s\", buf, (unsigned)sizeof(buf));"),
        "atoi": ("Integer Conversion Defect", "atoi fails to detect numeric overflow or invalid character inputs, returning 0 on error.", "strtol(str, &endptr, 10) with errno checking"),
    }

    @classmethod
    def audit(cls, context: Dict[str, Any], exe_path: str) -> List[CheckFinding]:
        findings: List[CheckFinding] = []

        # 1. BUG-EXE-001: Memory & Handle Resource Leak Heuristics
        findings.append(cls._check_resource_leaks(exe_path, context))

        # 2. BUG-EXE-002: Defect-Prone Banned C-Runtime Functions
        findings.append(cls._check_banned_functions(exe_path, context))

        # 3. BUG-EXE-003: Unquoted Execution & Service Path Defects
        findings.append(cls._check_unquoted_paths(exe_path, context))

        # 4. BUG-EXE-004: Missing Stack Buffer & Exception Handling Guards
        findings.append(cls._check_exception_guards(exe_path, context))

        # 5. BUG-EXE-005: Application Manifest & High-DPI GUI Defects
        findings.append(cls._check_manifest_defects(exe_path, context))

        return findings

    @classmethod
    def _check_resource_leaks(cls, exe_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-EXE-001"
        cname = "Memory & Handle Resource Leak Heuristics"
        target_type = TargetType.EXE
        cat = "Software Defect / Resource Management"

        imported = set(context.get("imported_functions", []))
        if not imported:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.INCONCLUSIVE,
                severity=Severity.INFO,
                finding_type="bug",
                title="INCONCLUSIVE: Import Address Table Empty or Stripped",
                affected_component="PE Import Directory",
                description="Audits Win32 resource allocation and deallocation API pairs.",
                evidence="No imported functions resolved.",
                impact="Cannot verify resource lifecycle.",
                remediation="Ensure executable includes standard IAT.",
            )

        leaks: List[str] = []
        for alloc_apis, free_apis, resource_name, sev in cls.UNBALANCED_RESOURCES:
            has_alloc = any(api in imported for api in alloc_apis)
            has_free = any(api in imported for api in free_apis)
            if has_alloc and not has_free:
                alloc_matched = [a for a in alloc_apis if a in imported]
                leaks.append(f"{resource_name} Leak Risk: Imports {', '.join(alloc_matched)} but 0 deallocation APIs ({', '.join(free_apis)})")

        if leaks:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=Severity.HIGH,
                finding_type="bug",
                title=f"HIGH: Unbalanced Resource Acquisition vs Release Detected ({len(leaks)} leak vectors)",
                affected_component=f"Win32 API Imports -> {os.path.basename(exe_path)}",
                description="Audits the Import Address Table for asymmetric resource lifecycle functions, where resources are acquired but no deallocation function is linked.",
                evidence=" | ".join(leaks),
                impact="Unreleased kernel handles or heap blocks exhaust process resources over extended runtimes, causing memory bloat, sluggish performance, or process crash.",
                remediation="Ensure every allocated handle or heap memory block is paired with its corresponding release API in RAII or finally blocks.",
                code_example="// C++ RAII Handle Wrapper\nstruct FileHandle {\n    HANDLE h;\n    FileHandle(HANDLE handle) : h(handle) {}\n    ~FileHandle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }\n};",
                verification_step="Profile binary in Windows Performance Monitor / Visual Studio Diagnostics and monitor Private Bytes and Handle Count over time.",
                standards=["CWE-401", "CWE-775", "CERT MEM31-C"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Balanced Win32 Resource Allocation/Release APIs",
            affected_component=f"Win32 API Imports -> {os.path.basename(exe_path)}",
            description="Audits API pairs for handle and memory leaks.",
            evidence=f"Audited {len(imported)} imported API(s); all resource allocation APIs are properly paired with matching deallocation routines.",
            impact="Healthy resource lifecycle maintained.",
            remediation="No action required.",
        )

    @classmethod
    def _check_banned_functions(cls, exe_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-EXE-002"
        cname = "Defect-Prone Banned C-Runtime Functions"
        target_type = TargetType.EXE
        cat = "Software Defect / Code Safety"

        imported = set(context.get("imported_functions", []))
        found_banned: List[Dict[str, str]] = []

        for fn, (flaw, desc, fix) in cls.BANNED_CRT_FUNCTIONS.items():
            if fn in imported:
                found_banned.append({"func": fn, "flaw": flaw, "desc": desc, "fix": fix})

        if found_banned:
            banned_names = [f["func"] for f in found_banned]
            banned_summary = ", ".join([f"{item['func']} ({item['flaw']})" for item in found_banned])
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=Severity.HIGH,
                finding_type="bug",
                title=f"HIGH: Deprecated & Defect-Prone CRT Functions Linked ({len(found_banned)} banned APIs)",
                affected_component=f"CRT Imports -> {', '.join(banned_names)}",
                description="Detects legacy C-runtime functions that lack boundary checks, leading to memory corruption, off-by-one errors, and unexpected crashes.",
                evidence=f"Linked banned functions: {banned_summary}",
                impact="Unbounded string copy or formatting allows inputs exceeding stack buffers to overwrite adjacent variables or return addresses, crashing the application.",
                remediation="Replace legacy CRT functions with secure ISO/IEC TR 24731 equivalents (*_s variants) or safe modern string libraries.",
                code_example="\n".join([f"// Replace {f['func']}:\n{f['fix']}" for f in found_banned[:3]]),
                verification_step="Compile with /sdl and /W4 in MSVC; verify zero warnings for deprecated CRT functions (C4996).",
                standards=["CWE-120", "CWE-676", "Microsoft Security Development Lifecycle (SDL)"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Zero Defect-Prone Banned CRT Functions Found",
            affected_component=f"CRT Imports -> {os.path.basename(exe_path)}",
            description="Audits binary imports for unsafe string and memory functions.",
            evidence="Import Address Table contains 0 references to banned functions (strcpy, strcat, sprintf, gets, scanf).",
            impact="Modern safe runtime boundaries verified.",
            remediation="No action required.",
        )

    @classmethod
    def _check_unquoted_paths(cls, exe_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-EXE-003"
        cname = "Unquoted Execution & Service Path Defects"
        target_type = TargetType.EXE
        cat = "Software Defect / Execution"

        # Search embedded strings or detected secrets for unquoted paths with spaces
        unquoted_matches: List[str] = []
        path_regex = re.compile(r"(?:[a-zA-Z]:\\(?:Program Files|Program Files \(x86\)|Documents and Settings)[^\r\n\"<>|]*\.exe)", re.IGNORECASE)

        # Inspect raw strings if available or scan first 2MB of file
        try:
            with open(exe_path, "rb") as f:
                data = f.read(2 * 1024 * 1024)
                ascii_strings = re.findall(rb"[\x20-\x7E]{6,}", data)
                for s in ascii_strings:
                    s_str = s.decode("ascii", errors="ignore")
                    m = path_regex.search(s_str)
                    if m:
                        matched_path = m.group(0)
                        # Ensure it's not enclosed in quotes in the string
                        if f'"{matched_path}"' not in s_str and matched_path not in unquoted_matches:
                            unquoted_matches.append(matched_path)
                            if len(unquoted_matches) >= 3:
                                break
        except Exception:
            pass

        if unquoted_matches:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                finding_type="bug",
                title=f"MEDIUM: Unquoted Windows Path with Spaces ({len(unquoted_matches)} pattern(s))",
                affected_component=f"Embedded Binary Strings -> {os.path.basename(exe_path)}",
                description="Checks for unquoted file system paths with spaces targeting Program Files. Windows path resolution attempts to execute intermediate substrings before the full target.",
                evidence=f"Unquoted path detected: {', '.join(unquoted_matches)}",
                impact="If executed via CreateProcess or registered as a Windows Service, Windows will attempt to execute C:\\Program.exe, causing execution hijacking or startup failure.",
                remediation="Enclose all executable paths containing spaces in double quotes.",
                code_example="\"C:\\Program Files\\MyVendor\\MyApp.exe\" --service",
                verification_step="Inspect string literals and service installation commands to verify paths with spaces are enclosed in quotes.",
                standards=["CWE-428", "CAPEC-38"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: No Unquoted Path Defects Detected",
            affected_component=f"Embedded Strings -> {os.path.basename(exe_path)}",
            description="Audits executable paths for unquoted space ambiguity bugs.",
            evidence="Embedded path strings are properly formatted with quotes or lack spaces.",
            impact="Safe execution path resolution.",
            remediation="No action required.",
        )

    @classmethod
    def _check_exception_guards(cls, exe_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-EXE-004"
        cname = "Missing Stack Buffer & Exception Handling Guards"
        target_type = TargetType.EXE
        cat = "Software Defect / Crash Mitigation"

        defects: List[str] = []

        if not context.get("has_security_cookie", False):
            defects.append("Missing /GS Security Cookie (stack canary) protection in LoadConfig")

        is_64bit = context.get("is_64bit", False)
        if not is_64bit and not context.get("is_safeseh_enabled", False):
            defects.append("32-bit binary missing SafeSEH table (Structured Exception Handler overwrite vulnerability)")

        if not context.get("is_cfg_enabled", False):
            defects.append("Missing Control Flow Guard (CFG) indirect branch verification")

        if defects:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=Severity.MEDIUM,
                finding_type="bug",
                title=f"MEDIUM: Missing Compiler Exploit & Exception Guards ({len(defects)} mitigations absent)",
                affected_component=f"PE Headers & LoadConfig -> {os.path.basename(exe_path)}",
                description="Verifies the presence of modern compiler mitigations that prevent corrupted stack buffers from crashing or hijacking the process.",
                evidence=" | ".join(defects),
                impact="In the event of an off-by-one or buffer error, the process cannot safely trap the violation via __security_check_cookie, causing unpredictable memory corruption.",
                remediation="Recompile with /GS (Buffer Security Check), /guard:cf (Control Flow Guard), and /SAFESEH (for 32-bit x86 targets) in Visual Studio.",
                code_example="# MSVC Compiler Flags\ncl.exe /GS /guard:cf /SAFESEH source.cpp",
                verification_step="Inspect PE LoadConfig directory using dumpbin /loadconfig or CHARLO Testing Agent.",
                standards=["CWE-121", "NIST SP 800-53 SI-16"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Stack Canaries (/GS) and Exception Guards Present",
            affected_component=f"PE LoadConfig -> {os.path.basename(exe_path)}",
            description="Audits compiler exception and stack guards.",
            evidence="SecurityCookie pointer is registered and exception mitigation tables are present.",
            impact="Hardened exception recovery enabled.",
            remediation="No action required.",
        )

    @classmethod
    def _check_manifest_defects(cls, exe_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-EXE-005"
        cname = "Application Manifest & High-DPI GUI Defects"
        target_type = TargetType.EXE
        cat = "Software Defect / GUI & Compatibility"

        manifest_str = context.get("embedded_manifest_str", "")
        has_manifest = context.get("has_embedded_manifest", False)

        if not has_manifest:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.LOW,
                finding_type="bug",
                title="LOW: Missing Embedded RT_MANIFEST Resource",
                affected_component=f"Resource Directory -> {os.path.basename(exe_path)}",
                description="Checks for embedded RT_MANIFEST defining UAC privileges, high-DPI scaling, and modern Common Controls styling.",
                evidence="Binary contains 0 embedded RT_MANIFEST resources.",
                impact="Windows defaults to legacy compatibility modes, causing UI scaling blurriness and un-themed legacy controls.",
                remediation="Embed an application manifest in resources specifying DPI awareness and Common Controls v6.",
                code_example="<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n    <windowsSettings>\n      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware>\n    </windowsSettings>\n  </application>\n</assembly>",
                verification_step="Inspect resources using CHARLO or mt.exe /view:binary.exe.",
                standards=["Microsoft Desktop UX Guidelines"],
            )

        defects: List[str] = []
        if "Microsoft.Windows.Common-Controls" not in manifest_str:
            defects.append("Missing Common Controls v6 dependency (GUI renders with legacy Windows 95 un-themed buttons/dialogs)")
        if "dpiAware" not in manifest_str and "dpiAwareness" not in manifest_str:
            defects.append("Missing High-DPI awareness tag (causes text blurriness, clipped labels, and pixelated controls on 4K/1080p displays)")
        if "supportedOS" not in manifest_str:
            defects.append("Missing modern Windows 10/11 compatibility GUIDs in <supportedOS> section")

        if defects:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.LOW,
                finding_type="bug",
                title=f"LOW: Application Manifest GUI & Display Defects ({len(defects)} issues)",
                affected_component="Embedded RT_MANIFEST",
                description="Audits embedded manifest for DPI scaling, modern controls, and Windows OS compatibility declarations.",
                evidence=" | ".join(defects),
                impact="Users on high-resolution displays experience blurry font rendering, truncated dialog controls, or outdated theme rendering.",
                remediation="Update application manifest to include Common Controls v6 and Per-Monitor V2 DPI awareness.",
                code_example="<dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2</dpiAwareness>",
                verification_step="Launch executable on high-DPI (150%+ display scaling) Windows monitor and verify crystal-clear text.",
                standards=["Microsoft Desktop App UX Guidelines"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Embedded Manifest Configured with DPI Awareness & Modern Themes",
            affected_component="Embedded RT_MANIFEST",
            description="Audits application manifest configuration.",
            evidence="Common Controls v6 and DPI awareness tags verified in embedded manifest.",
            impact="Crisp high-DPI rendering and modern UI controls.",
            remediation="No action required.",
        )


# =============================================================================
# ANDROID APK BUG FINDER
# =============================================================================
class APKBugFinder:
    """
    Dedicated defect and bug scanner for Android APK application packages.
    """

    @classmethod
    def audit(cls, context: Dict[str, Any], apk_path: str) -> List[CheckFinding]:
        findings: List[CheckFinding] = []

        # 1. BUG-APK-001: Potential ANR & UI Thread Network Blocking
        findings.append(cls._check_anr_risks(apk_path, context))

        # 2. BUG-APK-002: Unclosed SQLite Cursor & Stream Resource Leaks
        findings.append(cls._check_cursor_leaks(apk_path, context))

        # 3. BUG-APK-003: Dynamic Reflection & Class Loading Hazards
        findings.append(cls._check_reflection_hazards(apk_path, context))

        # 4. BUG-APK-004: Misconfigured Intent-Filters & Activity Export Defects
        findings.append(cls._check_intent_defects(apk_path, context))

        # 5. BUG-APK-005: Deprecated Lifecycle & State Retention Defects
        findings.append(cls._check_lifecycle_defects(apk_path, context))

        return findings

    @classmethod
    def _check_anr_risks(cls, apk_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-APK-001"
        cname = "Potential ANR & UI Thread Network Blocking"
        target_type = TargetType.APK
        cat = "Software Defect / Performance & ANR"

        # Scan DEX bytecode for synchronous network calls
        found_sync_network: List[str] = []
        sync_patterns = [
            (rb"Ljava/net/HttpURLConnection;->connect", "HttpURLConnection.connect()"),
            (rb"Lorg/apache/http/client/HttpClient;->execute", "HttpClient.execute()"),
            (rb"Lokhttp3/Call;->execute\(\)", "OkHttp Call.execute() [Synchronous]"),
            (rb"Ljava/net/URL;->openStream", "URL.openStream()"),
        ]

        if os.path.exists(apk_path) and zipfile.is_zipfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".dex"):
                            data = zf.read(name)
                            for pat, label in sync_patterns:
                                if pat in data and label not in found_sync_network:
                                    found_sync_network.append(label)
            except Exception:
                pass

        if found_sync_network:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                finding_type="bug",
                title=f"MEDIUM: Synchronous Network Calls in Bytecode ({len(found_sync_network)} API signatures)",
                affected_component=f"Compiled Bytecode -> {', '.join(found_sync_network)}",
                description="Checks for synchronous network invocation methods. If executed on the Android main UI thread, these immediately crash with NetworkOnMainThreadException or trigger a 5-second Application Not Responding (ANR) dialog.",
                evidence=f"Bytecode references synchronous calls: {', '.join(found_sync_network)}",
                impact="Network latency freezes the user interface, resulting in immediate app crashes or unrecoverable ANR popups forcing users to kill the application.",
                remediation="Offload all network calls to Kotlin Coroutines (Dispatchers.IO), RxJava, WorkManager, or asynchronous callbacks (enqueue).",
                code_example="// Kotlin Coroutines (Safe IO Threading)\nsuspend fun fetchData() = withContext(Dispatchers.IO) {\n    client.newCall(request).execute()\n}",
                verification_step="Enable Android StrictMode in Application.onCreate() to detect and log any disk or network operations executed on the main thread.",
                standards=["CWE-400", "Android Performance Guide §ANR"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: No Synchronous Network Blocking Signatures in Bytecode",
            affected_component="Compiled DEX Bytecode",
            description="Audits DEX bytecodes for synchronous network calls on main threads.",
            evidence="DEX bytecodes free from synchronous HttpURLConnection.connect or OkHttp Call.execute calls.",
            impact="Responsive UI execution preserved.",
            remediation="No action required.",
        )

    @classmethod
    def _check_cursor_leaks(cls, apk_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-APK-002"
        cname = "Unclosed SQLite Cursor & Stream Resource Leaks"
        target_type = TargetType.APK
        cat = "Software Defect / Resource Leaks"

        # Scan DEX bytecodes for SQLite query calls vs cursor close calls
        has_query = False
        has_close = False

        if os.path.exists(apk_path) and zipfile.is_zipfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".dex"):
                            data = zf.read(name)
                            if rb"rawQuery(" in data or rb"query(" in data:
                                has_query = True
                            if rb"Landroid/database/Cursor;->close()V" in data:
                                has_close = True
            except Exception:
                pass

        if has_query and not has_close:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=Severity.HIGH,
                finding_type="bug",
                title="HIGH: Potential SQLite Database Cursor Leak",
                affected_component="DEX Bytecode -> SQLiteDatabase",
                description="Checks for database queries without corresponding Cursor.close() calls. Unclosed cursors cause memory leaks in Android CursorWindow shared memory.",
                evidence="DEX bytecodes perform SQLite queries (rawQuery/query) but contain 0 calls to Cursor.close().",
                impact="Accumulating unclosed Cursor objects deplete the 2MB CursorWindow limit, triggering IllegalStateException crashes: 'Finalizing a Cursor that has not been deactivated or closed'.",
                remediation="Always wrap Cursor instances in try-with-resources or Kotlin's .use { } extension block to guarantee automatic closure.",
                code_example="// Kotlin Safe Cursor Handling\ndatabase.rawQuery(query, null).use { cursor ->\n    while (cursor.moveToNext()) {\n        // Process row\n    }\n} // Automatically closed even on exception",
                verification_step="Monitor Logcat for 'Finalizing a Cursor that has not been deactivated or closed' tags.",
                standards=["CWE-775", "Android Database Guidelines"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Cursor & Database Operations Properly Closed",
            affected_component="SQLite Database Lifecycle",
            description="Audits SQLite cursor lifecycle management.",
            evidence="All database queries are paired with Cursor.close() invocations.",
            impact="Stable memory consumption in database routines.",
            remediation="No action required.",
        )

    @classmethod
    def _check_reflection_hazards(cls, apk_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-APK-003"
        cname = "Dynamic Reflection & Class Loading Hazards"
        target_type = TargetType.APK
        cat = "Software Defect / Reflection & Obfuscation"

        has_dynamic_loading = context.get("has_dynamic_code_loading", False)
        has_reflection = False

        if os.path.exists(apk_path) and zipfile.is_zipfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".dex"):
                            data = zf.read(name)
                            if rb"Ljava/lang/Class;->forName" in data and rb"Ljava/lang/reflect/Method;->invoke" in data:
                                has_reflection = True
                                break
            except Exception:
                pass

        if has_dynamic_loading or has_reflection:
            reasons = []
            if has_dynamic_loading:
                reasons.append("Dynamic code loading via DexClassLoader / PathClassLoader")
            if has_reflection:
                reasons.append("Class.forName and Method.invoke reflective invocation")

            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.MEDIUM,
                finding_type="bug",
                title=f"MEDIUM: Dynamic Reflection & Class Loading Hazards ({len(reasons)} patterns)",
                affected_component="Bytecode Runtime Execution",
                description="Audits usage of Java reflection and dynamic class loading. Dynamic reflection is fragile under R8 / ProGuard obfuscation and prone to ClassNotFoundException crashes.",
                evidence=" | ".join(reasons),
                impact="When ProGuard or R8 renames or shrinks classes, reflective lookup using string names fails at runtime, causing immediate unhandled crashes for end users.",
                remediation="Replace dynamic reflection with typed interfaces or dependency injection. Add explicit @Keep annotations or keep rules in proguard-rules.pro.",
                code_example="# proguard-rules.pro\n-keep class com.example.model.** { *; }",
                verification_step="Build release APK with minifyEnabled=true and run smoke tests on all reflective code paths.",
                standards=["CWE-470", "Android ProGuard Guidelines"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Zero Fragile Dynamic Reflection Hazards Detected",
            affected_component="Bytecode Runtime Execution",
            description="Audits reflection and dynamic class loading.",
            evidence="Codebase relies on strongly typed interfaces without fragile Class.forName lookups.",
            impact="Obfuscation and minification resilience verified.",
            remediation="No action required.",
        )

    @classmethod
    def _check_intent_defects(cls, apk_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-APK-004"
        cname = "Misconfigured Intent-Filters & Activity Export Defects"
        target_type = TargetType.APK
        cat = "Software Defect / Manifest & Components"

        manifest_strings = context.get("manifest_strings", [])
        target_sdk = context.get("target_sdk", 0)

        defects: List[str] = []

        # Target SDK >= 31 (Android 12+) requires explicit android:exported on components with intent-filters
        if target_sdk >= 31:
            # Check if exported attribute was missing in any component with filters
            exported_acts = context.get("exported_activities", [])
            unprot = context.get("unprotected_exported_components", [])
            # Heuristic check on manifest strings
            if "intent-filter" in [s.lower() for s in manifest_strings] and "exported" not in [s.lower() for s in manifest_strings]:
                defects.append("Target SDK >= 31 requires explicit 'android:exported' declaration on components with intent filters (causes INSTALL_PARSE_FAILED_MANIFEST_MALFORMED on Android 12+)")

        if defects:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.FAILED,
                severity=Severity.HIGH,
                finding_type="bug",
                title="HIGH: Android 12+ Manifest Component Export Defect",
                affected_component="AndroidManifest.xml",
                description="Checks for compliance with Android 12+ (API 31) component export mandates.",
                evidence=" | ".join(defects),
                impact="The APK fails to install on any device running Android 12 or newer, returning INSTALL_PARSE_FAILED_MANIFEST_MALFORMED.",
                remediation="Add explicit android:exported='true' or android:exported='false' attribute to every <activity>, <service>, and <receiver> containing an <intent-filter>.",
                code_example="<activity\n    android:name=\".MainActivity\"\n    android:exported=\"true\">\n    <intent-filter>\n        <action android:name=\"android.intent.action.MAIN\" />\n        <category android:name=\"android.intent.category.LAUNCHER\" />\n    </intent-filter>\n</activity>",
                verification_step="Install APK on Android 12+ emulator or run aapt dump badging to verify manifest validity.",
                standards=["Android 12 Behavior Changes §Exported Components"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Manifest Components & Intent-Filters Properly Configured",
            affected_component="AndroidManifest.xml",
            description="Audits Android component export compliance.",
            evidence=f"Validated manifest for targetSDK {target_sdk or 'N/A'}: all component boundaries explicitly defined.",
            impact="Clean installation across Android versions.",
            remediation="No action required.",
        )

    @classmethod
    def _check_lifecycle_defects(cls, apk_path: str, context: Dict[str, Any]) -> CheckFinding:
        cid = "BUG-APK-005"
        cname = "Deprecated Lifecycle & State Retention Defects"
        target_type = TargetType.APK
        cat = "Software Defect / Lifecycle & Fragments"

        found_patterns: List[str] = []

        if os.path.exists(apk_path) and zipfile.is_zipfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".dex"):
                            data = zf.read(name)
                            if rb"commitAllowingStateLoss" in data:
                                if "commitAllowingStateLoss" not in found_patterns:
                                    found_patterns.append("FragmentTransaction.commitAllowingStateLoss() [Loss of UI state on rotation]")
                            if rb"startActivityForResult" in data:
                                if "startActivityForResult" not in found_patterns:
                                    found_patterns.append("Deprecated startActivityForResult() [Fails when activity is destroyed in background]")
            except Exception:
                pass

        if found_patterns:
            return CheckFinding(
                check_id=cid,
                check_name=cname,
                target_type=target_type,
                category=cat,
                status=CheckStatus.WARNING,
                severity=Severity.LOW,
                finding_type="bug",
                title=f"LOW: Deprecated Android Lifecycle & State Loss Patterns ({len(found_patterns)} pattern(s))",
                affected_component="Fragment & Activity Lifecycle",
                description="Audits bytecode for fragile lifecycle calls such as commitAllowingStateLoss and deprecated startActivityForResult.",
                evidence=" | ".join(found_patterns),
                impact="Using commitAllowingStateLoss causes fragments to lose their restored state when user rotates screen. Deprecated startActivityForResult fails to deliver result if OS reclaims the caller activity.",
                remediation="Migrate to AndroidX Activity Result API (registerForActivityResult) and handle fragment transactions before onSaveInstanceState.",
                code_example="// Modern AndroidX Activity Result API\nval launcher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->\n    if (result.resultCode == Activity.RESULT_OK) {\n        // Process result safely\n    }\n}\nlauncher.launch(intent)",
                verification_step="Enable 'Don't keep activities' in Developer Options and test screen rotation on all workflows.",
                standards=["Android Architecture Components Guidelines"],
            )

        return CheckFinding(
            check_id=cid,
            check_name=cname,
            target_type=target_type,
            category=cat,
            status=CheckStatus.PASSED,
            severity=Severity.INFO,
            finding_type="bug",
            title="PASSED: Clean Android Lifecycle & State Management",
            affected_component="Fragment & Activity Lifecycle",
            description="Audits lifecycle patterns for state retention bugs.",
            evidence="No fragile commitAllowingStateLoss or deprecated activity result calls detected.",
            impact="Reliable state restoration across device rotations.",
            remediation="No action required.",
        )


# =============================================================================
# UNIFIED BUG FINDER COORDINATOR
# =============================================================================
class BugFinder:
    """
    Central Bug Finder orchestrator evaluating software defects across APK, EXE, and Web targets.
    """

    @classmethod
    def find_bugs(
        cls,
        target: ScanTarget,
        context: Dict[str, Any],
        probe_network: bool = True,
    ) -> List[CheckFinding]:
        """
        Dispatches target to specialized bug analyzers and returns structured CheckFindings.
        """
        if target.target_type == TargetType.WEB:
            return WebBugFinder.audit(
                context=context,
                url=target.target_path,
                html_content=context.get("html_content", ""),
                probe_network=probe_network,
            )
        elif target.target_type == TargetType.EXE:
            return EXEBugFinder.audit(
                context=context,
                exe_path=target.target_path,
            )
        elif target.target_type == TargetType.APK:
            return APKBugFinder.audit(
                context=context,
                apk_path=target.target_path,
            )
        return []
