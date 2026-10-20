"""
CHARLO Testing Agent - Live Interactive PoC Exploit & Sandbox Runner.
Safely dispatches non-destructive verification requests to evaluate
whether a detected vulnerability is live exploitable in the target environment.
"""

import time
import json
import urllib.request
import urllib.error
import urllib.parse
import ssl
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class PocExecutionResult:
    """Telemetry captured from live PoC execution in the sandbox."""
    flaw_id: str
    target_url: str
    method: str
    status_code: Optional[int]
    latency_ms: float
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_headers: Dict[str, str]
    response_body_preview: str
    verification_status: str  # CONFIRMED_VULNERABLE, MITIGATED, INCONCLUSIVE, ERROR
    analysis_summary: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PocRunner:
    """Sandbox dispatcher for validating vulnerabilities against live targets."""

    DEFAULT_TIMEOUT_SEC = 5.0
    USER_AGENT = "CHARLO-Security-Agent/2.4 (Live-PoC-Verification; +https://charlo.security)"

    # Signatures that confirm vulnerability in live responses
    VULN_SIGNATURES = {
        "sql_error": [
            "syntax error in sql", "unclosed quotation mark", "mysql_fetch",
            "pg_query", "ora-00933", "sqlite3.operationalerror", "microsoft oledb provider"
        ],
        "xss_probe": [
            "<charlo_xss_probe>", "javascript:charlo_audit_trigger", "\"><charlo_probe>"
        ],
        "traversal": [
            "root:x:0:0:", "[boot loader]", "[fonts]", "daemon:x:1:1:"
        ],
        "command_exec": [
            "charlo_cmd_eval_success", "uid=0(root)", "windows ip configuration"
        ],
        "info_disclosure": [
            "phpinfo()", "environ[", "django.views.debug", "actionpack/lib/action_dispatch"
        ]
    }

    @classmethod
    def execute_poc(
        cls,
        flaw_id: str,
        target_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        probe_type: Optional[str] = None
    ) -> PocExecutionResult:
        """Dispatches safe live test request and evaluates server response."""
        now_iso = datetime.now().isoformat()
        method = method.upper()
        req_headers = headers.copy() if headers else {}
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = cls.USER_AGENT
        if body and "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/json"

        # Ensure scheme
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        start_time = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Allow audit against staging/self-signed certs

        encoded_body = body.encode("utf-8") if body else None
        req = urllib.request.Request(
            url=target_url,
            data=encoded_body,
            headers=req_headers,
            method=method
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                latency_ms = (time.time() - start_time) * 1000.0
                raw_code = getattr(resp, "status", None)
                if raw_code is None or not isinstance(raw_code, int):
                    raw_code = resp.getcode() if hasattr(resp, "getcode") else 200
                status_code = raw_code
                resp_headers = dict(resp.headers.items()) if hasattr(resp, "headers") and hasattr(resp.headers, "items") else {}
                raw_bytes = resp.read(8192) if hasattr(resp, "read") else b""
                resp_body = raw_bytes.decode("utf-8", errors="replace") if isinstance(raw_bytes, bytes) else str(raw_bytes)

        except urllib.error.HTTPError as e:
            latency_ms = (time.time() - start_time) * 1000.0
            status_code = e.code
            resp_headers = dict(e.headers.items()) if e.headers else {}
            raw_bytes = e.read(8192) if hasattr(e, "read") else b""
            resp_body = raw_bytes.decode("utf-8", errors="replace")

        except urllib.error.URLError as e:
            latency_ms = (time.time() - start_time) * 1000.0
            return PocExecutionResult(
                flaw_id=flaw_id,
                target_url=target_url,
                method=method,
                status_code=None,
                latency_ms=round(latency_ms, 2),
                request_headers=req_headers,
                request_body=body,
                response_headers={},
                response_body_preview="",
                verification_status="ERROR",
                analysis_summary=f"Connection failed: {e.reason}",
                timestamp=now_iso
            )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000.0
            return PocExecutionResult(
                flaw_id=flaw_id,
                target_url=target_url,
                method=method,
                status_code=None,
                latency_ms=round(latency_ms, 2),
                request_headers=req_headers,
                request_body=body,
                response_headers={},
                response_body_preview="",
                verification_status="ERROR",
                analysis_summary=f"Execution exception: {str(e)}",
                timestamp=now_iso
            )

        # Analyze verification status
        verif_status, summary = cls._evaluate_response(
            status_code=status_code,
            resp_body=resp_body,
            resp_headers=resp_headers,
            body_sent=body,
            probe_type=probe_type
        )

        return PocExecutionResult(
            flaw_id=flaw_id,
            target_url=target_url,
            method=method,
            status_code=status_code,
            latency_ms=round(latency_ms, 2),
            request_headers=req_headers,
            request_body=body,
            response_headers=resp_headers,
            response_body_preview=resp_body[:1024],  # 1KB sample
            verification_status=verif_status,
            analysis_summary=summary,
            timestamp=now_iso
        )

    @classmethod
    def _evaluate_response(
        cls,
        status_code: int,
        resp_body: str,
        resp_headers: Dict[str, str],
        body_sent: Optional[str],
        probe_type: Optional[str]
    ) -> Tuple[str, str]:
        """Classifies response telemetry into a verifiable audit finding."""
        body_lower = resp_body.lower()

        # Check explicit database syntax error leakages
        for sig in cls.VULN_SIGNATURES["sql_error"]:
            if sig in body_lower:
                return (
                    "CONFIRMED_VULNERABLE",
                    f"Confirmed SQL injection: Response contains database error signature ('{sig}')."
                )

        # Check path traversal
        for sig in cls.VULN_SIGNATURES["traversal"]:
            if sig in body_lower:
                return (
                    "CONFIRMED_VULNERABLE",
                    f"Confirmed Path Traversal: System file contents revealed ('{sig}')."
                )

        # Check XSS probe unescaped reflection
        for xss_sig in cls.VULN_SIGNATURES["xss_probe"]:
            if xss_sig in resp_body:
                return (
                    "CONFIRMED_VULNERABLE",
                    f"Confirmed Cross-Site Scripting: Probe payload was reflected unescaped in response HTML ('{xss_sig}')."
                )

        if body_sent and ("<script>" in body_sent or "charlo_xss_probe" in body_sent):
            if "charlo_xss_probe" in resp_body:
                return (
                    "CONFIRMED_VULNERABLE",
                    "Confirmed Cross-Site Scripting: Probe payload was reflected unescaped in response HTML."
                )

        # Check CORS Wildcard Exposure with Credentials
        cors_origin = resp_headers.get("access-control-allow-origin", resp_headers.get("Access-Control-Allow-Origin", ""))
        cors_creds = resp_headers.get("access-control-allow-credentials", resp_headers.get("Access-Control-Allow-Credentials", ""))
        if cors_origin == "*" and cors_creds.lower() == "true":
            return (
                "CONFIRMED_VULNERABLE",
                "Confirmed Overly Permissive CORS: Wildcard origin allowed with Allow-Credentials enabled."
            )

        # Check server security rejections (400, 401, 403, 405)
        if status_code in (401, 403):
            return (
                "MITIGATED",
                f"Mitigated / Protected: Target returned HTTP {status_code} Access Denied. WAF or authorization barrier active."
            )

        if status_code == 405:
            return (
                "MITIGATED",
                f"Mitigated: Target returned HTTP 405 Method Not Allowed for flawed sequence."
            )

        if probe_type and probe_type in cls.VULN_SIGNATURES and status_code in (200, 201, 204):
            return (
                "MITIGATED",
                f"Mitigated: Target returned HTTP {status_code} cleanly without triggering probe signature ('{probe_type}')."
            )

        if status_code in (200, 201, 204):
            return (
                "INCONCLUSIVE",
                f"Server returned HTTP {status_code} OK. Request succeeded without explicit error signatures; manual review suggested."
            )

        return (
            "INCONCLUSIVE",
            f"Server returned HTTP {status_code}. Flaw was not triggered or response is masked."
        )
