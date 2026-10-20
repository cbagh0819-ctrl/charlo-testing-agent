"""
Core Scan Execution Engine for CHARLO Testing Agent.
Coordinates analyzers, check execution, progress tracking, and risk calculation.
"""

import os
import time
import datetime
from typing import Optional, Callable, Dict, Any, List
from .models import (
    TargetType,
    ScanLevel,
    ScanTarget,
    ScanResult,
    CheckFinding,
)
from .registry import CheckRegistry
from .scoring import RiskCalculator
from ..analyzers.apk_analyzer import APKAnalyzer
from ..analyzers.exe_analyzer import EXEAnalyzer
from ..analyzers.web_analyzer import WebAnalyzer
from ..analyzers.web_history import WebHistoryAnalyzer
from ..analyzers.attack_simulator import AttackResilienceSimulator, AttackSimulationReport
from ..analyzers.automation_tools import PopularToolsAutomationTester, AutomationReport
from ..analyzers.api_tester import ApiTester, ApiTestReport
from ..analyzers.performance_tester import PerformanceTester, PerformanceTestReport
from ..analyzers.cicd_generator import CiCdGenerator, CiCdPipelineReport
from ..analyzers.database_tester import DatabaseTester, DatabaseTestReport
from ..analyzers.compatibility_tester import CompatibilityTester, CompatibilityReport
from ..analyzers.network_tester import NetworkTester, NetworkTestReport
from ..analyzers.business_logic_tester import BusinessLogicTester, BusinessLogicReport
from ..analyzers.memory_tester import MemoryLeakTester, MemoryLeakReport
from ..analyzers.accessibility_tester import AccessibilityTester, AccessibilityReport
from ..analyzers.graphql_websocket_tester import GraphQLWebSocketTester, GraphQLWebSocketReport

# Ensure all checks are registered
from .. import checks  # noqa: F401


class ScanEngine:
    """
    Orchestrates target ingestion, analyzer dispatch, security checks, and scoring.
    """

    @classmethod
    def detect_target_type(cls, input_str: str) -> TargetType:
        input_clean = input_str.strip().lower()
        if input_clean.startswith("http://") or input_clean.startswith("https://") or "www." in input_clean:
            return TargetType.WEB
        if input_clean.endswith(".apk"):
            return TargetType.APK
        if input_clean.endswith(".exe") or input_clean.endswith(".dll"):
            return TargetType.EXE
        # Check if file exists on disk and examine extension or magic
        if os.path.exists(input_str):
            if input_str.lower().endswith(".apk"):
                return TargetType.APK
            if input_str.lower().endswith(".exe") or input_str.lower().endswith(".dll"):
                return TargetType.EXE
        # Default fallback
        if "." in input_str and "/" not in input_str and "\\" not in input_str:
            return TargetType.WEB
        return TargetType.EXE

    @classmethod
    def run_scan(
        cls,
        target_input: str,
        target_type: Optional[TargetType] = None,
        level: ScanLevel = ScanLevel.BASIC,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
        bugs_only: bool = False,
    ) -> ScanResult:
        """
        Executes a complete security and bug scan.
        progress_callback(percent: int, message: str)
        log_callback(log_line: str)
        """
        start_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start_t0 = time.time()
        logs: List[str] = []

        def log(msg: str):
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            line = f"[{ts}] {msg}"
            logs.append(line)
            if log_callback:
                try:
                    log_callback(line)
                except Exception:
                    pass

        def update_progress(pct: int, msg: str):
            if progress_callback:
                try:
                    progress_callback(pct, msg)
                except Exception:
                    pass

        mode_name = "CHARLO Dedicated Bug Finder" if bugs_only else "CHARLO Security Scan"
        log(f"Initiating {mode_name}...")
        update_progress(5, "Resolving target type and parameters...")

        # 1. Resolve & Normalize Target Type & Level
        if target_type is None:
            target_type = cls.detect_target_type(target_input)
        elif isinstance(target_type, str):
            target_type = TargetType.from_string(target_type)

        if isinstance(level, str):
            level = ScanLevel.from_string(level)
        elif not isinstance(level, ScanLevel):
            level = ScanLevel.BASIC

        type_str = target_type.value if hasattr(target_type, "value") else str(target_type)
        lvl_str = level.value if hasattr(level, "value") else str(level)
        log(f"Target identified: Type={type_str.upper()} | Level={lvl_str.upper()}")

        # 2. Ingest Target
        scan_target = ScanTarget(
            target_type=target_type,
            target_path=target_input,
            display_name=os.path.basename(target_input) if target_type != TargetType.WEB else target_input,
        )

        update_progress(15, f"Analyzing {type_str.upper()} structures...")
        context: Dict[str, Any] = {}

        # 3. Execute Specialized Static Analyzer
        if target_type == TargetType.APK:
            log(f"Parsing APK archive, manifest, and DEX bytecodes: {target_input}")
            context = APKAnalyzer.analyze(target_input)
            scan_target.size_bytes = context.get("file_size", 0)
            scan_target.sha256 = context.get("sha256", "")
            scan_target.metadata = {
                "package_name": context.get("package_name"),
                "file_count": context.get("file_count"),
                "dex_count": len(context.get("dex_files", [])),
                "cert_count": len(context.get("signing_certificates", [])),
            }
            log(f"APK parsed: Package={context.get('package_name')} | Size={scan_target.size_bytes} bytes")

        elif target_type == TargetType.EXE:
            log(f"Parsing Windows PE headers, sections, and import tables: {target_input}")
            context = EXEAnalyzer.analyze(target_input)
            scan_target.size_bytes = context.get("file_size", 0)
            scan_target.sha256 = context.get("sha256", "")
            scan_target.metadata = {
                "machine_arch": context.get("machine_arch"),
                "aslr": context.get("is_aslr_enabled"),
                "dep": context.get("is_dep_enabled"),
                "signed": context.get("is_digitally_signed"),
                "sections": len(context.get("sections", [])),
            }
            log(f"PE parsed: Arch={context.get('machine_arch')} | Signed={context.get('is_digitally_signed')} | ASLR={context.get('is_aslr_enabled')}")

        elif target_type == TargetType.WEB:
            log(f"Auditing website transport security, headers, and endpoints: {target_input}")
            context = WebAnalyzer.analyze(target_input)
            scan_target.sha256 = "N/A (Remote Web Endpoint)"
            scan_target.metadata = {
                "hostname": context.get("hostname"),
                "status_code": context.get("status_code"),
                "is_https": context.get("is_https"),
                "tls_version": context.get("tls_version"),
                "cipher_suite": context.get("cipher_suite"),
                "hsts": context.get("hsts_present"),
                "csp": context.get("csp_present"),
            }
            log(f"Web audited: Host={context.get('hostname')} | TLS={context.get('tls_version') or 'N/A'} | Cipher={context.get('cipher_suite') or 'N/A'} | Status={context.get('status_code')}")

            update_progress(25, "Analyzing domain registration history, RDAP, and archive chronology...")
            log("Querying domain registration chronology, RDAP records, and historical evolution...")
            try:
                history_report = WebHistoryAnalyzer.analyze(target_input, context)
                context["history"] = history_report.to_dict()
                scan_target.metadata["history"] = history_report.to_dict()
                log(f"Domain Chronology: Age={history_report.registration.age_description} | Registrar={history_report.registration.registrar}")
                log(f"Admin Intelligence: {history_report.admin_profile.tier} (Security Score: {history_report.admin_profile.score}/100)")
            except Exception as hist_err:
                log(f"! History analysis note: {str(hist_err)}")

        # 4. Fetch Registered Checks for Target and Level
        update_progress(30, "Dispatching checks from laboratory catalog...")
        applicable_checks = CheckRegistry.get_checks_for_target(target_type, max_level=level)

        if bugs_only:
            applicable_checks = [c for c in applicable_checks if getattr(c, "check_id", "").startswith("BUG-")]

        total_checks = len(applicable_checks)
        check_desc = "dedicated bug finder checks" if bugs_only else f"applicable security & bug checks for level '{level.value}'"
        log(f"Loaded {total_checks} {check_desc}.")

        # 5. Execute Checks
        findings: List[CheckFinding] = []
        for i, check in enumerate(applicable_checks, start=1):
            pct = 30 + int((i / max(1, total_checks)) * 60)
            update_progress(pct, f"[{i}/{total_checks}] Evaluating {check.check_id}: {check.name}...")

            try:
                finding = check.run(scan_target, context)
                findings.append(finding)
                log(f"-> {check.check_id} [{finding.status.value.upper()}] ({finding.severity.value.upper()}): {finding.title}")
            except Exception as e:
                log(f"! Error running {check.check_id}: {str(e)}")
                # Inconclusive fallback on unexpected exception
                err_finding = check.create_finding(
                    status=check.default_severity,
                    title=f"Check Execution Exception: {check.name}",
                    evidence=f"Internal error: {str(e)}",
                    impact="Check was unable to complete cleanly.",
                    remediation="Inspect application logs or target format.",
                )
                findings.append(err_finding)

        # 6. Calculate Security Posture and Score
        update_progress(95, "Computing security posture metrics and risk grade...")
        metrics = RiskCalculator.calculate_metrics(findings)
        log(f"Risk Evaluation Complete: Score={metrics.security_score}/100 | Grade={metrics.posture_grade}")
        log(f"Summary: Critical={metrics.critical_count} | High={metrics.high_count} | Medium={metrics.medium_count} | Low={metrics.low_count} | Passed={metrics.passed}")

        # 6.5 Theoretical Attack Resilience & Survival Simulator
        try:
            sim_report = AttackResilienceSimulator.simulate_target(
                target_name=scan_target.display_name,
                target_type=target_type,
                findings=findings,
                context=context,
                duration=round(time.time() - start_t0, 2),
            )
            scan_target.metadata["attack_simulation"] = sim_report.to_dict()
            log(f"Attack Resilience Simulation: Overall Survival Index={sim_report.overall_survival_chance}% ({sim_report.overall_verdict})")
        except Exception as sim_err:
            log(f"! Attack simulation note: {str(sim_err)}")

        # 6.6 Popular Tools Automation Testing (Playwright/Selenium, Appium/Espresso, WinAppDriver/Ranorex)
        try:
            auto_report = PopularToolsAutomationTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["automation_report"] = auto_report.to_dict()
            log(f"Automation QA Suite: {auto_report.primary_tool} & {auto_report.secondary_tool} | Score={auto_report.quality_score}% ({auto_report.overall_status})")
        except Exception as auto_err:
            log(f"! Automation testing note: {str(auto_err)}")

        # 6.7 REST & Backend API Contract Testing & Schema Fuzzer
        try:
            api_report = ApiTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["api_report"] = api_report.to_dict()
            log(f"API Testing Suite: {api_report.total_endpoints} Endpoints, {api_report.total_tests} Tests | Score={api_report.quality_score}% ({api_report.overall_status})")
        except Exception as api_err:
            log(f"! API testing note: {str(api_err)}")

        # 6.8 Performance & Concurrency Load Simulator (JMeter / k6)
        try:
            perf_report = PerformanceTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["performance_report"] = perf_report.to_dict()
            log(f"Performance & Concurrency Suite: {perf_report.virtual_users} VUs -> {perf_report.throughput_rps} RPS | p95={perf_report.percentiles.p95_ms}ms | SLA={perf_report.sla_status} (Grade {perf_report.performance_grade})")
        except Exception as perf_err:
            log(f"! Performance testing note: {str(perf_err)}")

        # 6.85 Database & Data Layer Integrity, SQL Defense & Schema Verification
        try:
            db_report = DatabaseTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["database_report"] = db_report.to_dict()
            log(f"Database Integrity Suite: {db_report.total_tables_checked} Tables, {db_report.total_checks} Checks | Score={db_report.data_integrity_score}% ({db_report.overall_status})")
        except Exception as db_err:
            log(f"! Database testing note: {str(db_err)}")

        # 6.88 Cross-Platform Compatibility, Viewport Matrix & WCAG A11y Suite
        try:
            compat_report = CompatibilityTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["compatibility_report"] = compat_report.to_dict()
            log(f"Compatibility & Viewport Suite: {compat_report.total_viewports_tested} Viewports, {compat_report.total_checks} Checks | Score={compat_report.compatibility_score}% ({compat_report.overall_status})")
        except Exception as compat_err:
            log(f"! Compatibility testing note: {str(compat_err)}")

        # 6.90 Network Protocol, TLS Cryptographic Cipher & Certificate Suite
        try:
            net_report = NetworkTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["network_report"] = net_report.to_dict()
            log(f"Network & TLS Protocol Suite: Grade {net_report.tls_grade} ({net_report.crypto_score}%) | Checks: {net_report.total_checks} | Status: {net_report.overall_status}")
        except Exception as net_err:
            log(f"! Network testing note: {str(net_err)}")

        # 6.92 Business Logic, State Machine & Workflow Integrity Suite
        try:
            logic_report = BusinessLogicTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["business_logic_report"] = logic_report.to_dict()
            log(f"Business Logic Suite: {logic_report.total_workflows_evaluated} Workflows, {logic_report.total_checks} Checks | Score={logic_report.logic_integrity_score}% ({logic_report.overall_status})")
        except Exception as logic_err:
            log(f"! Business logic testing note: {str(logic_err)}")

        # 6.94 Memory Leak, Handle Profiling & Resource Exhaustion Suite
        try:
            mem_report = MemoryLeakTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["memory_report"] = mem_report.to_dict()
            log(f"Memory & Resource Profiler: Score={mem_report.memory_stability_score}% ({mem_report.overall_status}) | Peak RAM={mem_report.metrics.peak_working_set_mb:.1f}MB | Handles={mem_report.metrics.peak_handle_count}")
        except Exception as mem_err:
            log(f"! Memory testing note: {str(mem_err)}")

        # 6.96 Automated Accessibility Audit & Assistive Technology Matrix (WCAG 2.2 / VPAT)
        try:
            a11y_report = AccessibilityTester.run_tests(
                target=scan_target,
                context=context,
                findings=findings,
            )
            scan_target.metadata["accessibility_report"] = a11y_report.to_dict()
            log(f"Accessibility Audit (WCAG 2.2): Score={a11y_report.metrics.wcag_score}% ({a11y_report.metrics.conformance_status}) | Criteria: {a11y_report.metrics.total_criteria_checked} (Passed: {a11y_report.metrics.passed_criteria}, Defects: {a11y_report.metrics.defects_count})")
        except Exception as a11y_err:
            log(f"! Accessibility testing note: {str(a11y_err)}")

        # 6.97 Specialized GraphQL & WebSocket Protocol Security Testing
        try:
            gql_report = GraphQLWebSocketTester.run_tests(
                target=scan_target,
                metadata=context,
                existing_findings=findings,
            )
            scan_target.metadata["graphql_report"] = gql_report.to_dict()
            log(f"GraphQL & WebSocket Suite: Score={gql_report.score:.1f}% ({gql_report.overall_status}) | Endpoints Checked: GraphQL + WebSocket | Defects: {gql_report.defects_count}")
        except Exception as gql_err:
            log(f"! GraphQL/WebSocket testing note: {str(gql_err)}")

        # 7. Finalize Result
        end_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        duration = round(time.time() - start_t0, 2)
        update_progress(100, f"Scan finished in {duration}s.")
        log(f"Security Assessment Finished successfully in {duration} seconds.")

        result = ScanResult(
            target=scan_target,
            level=level,
            start_time=start_time_iso,
            end_time=end_time_iso,
            duration_seconds=duration,
            findings=findings,
            metrics=metrics,
            logs=logs,
        )

        # 6.9 CI/CD Quality Gate & Pipeline Generation
        try:
            cicd_report = CiCdGenerator.run_pipeline_generation(scan_target, result)
            scan_target.metadata["cicd_report"] = cicd_report.to_dict()
            log(f"CI/CD Quality Gate: {cicd_report.gate_result.status} (Score={cicd_report.gate_result.overall_score:.1f}%, Violations={cicd_report.gate_result.total_violations})")
        except Exception as cicd_err:
            log(f"! CI/CD pipeline note: {str(cicd_err)}")

        return result

    @classmethod
    def run_bug_finder(
        cls,
        target_input: str,
        target_type: Optional[TargetType] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> ScanResult:
        """
        Executes a dedicated software defect and bug finder audit.
        Evaluates memory/handle leaks, broken links, form defects, crashes, and banned APIs.
        """
        return cls.run_scan(
            target_input=target_input,
            target_type=target_type,
            level=ScanLevel.BASIC,
            progress_callback=progress_callback,
            log_callback=log_callback,
            bugs_only=True,
        )

    @classmethod
    def run_attack_simulation(
        cls,
        target_input: str,
        target_type: Optional[TargetType] = None,
        level: ScanLevel = ScanLevel.INTERMEDIATE,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> AttackSimulationReport:
        """
        Executes a scan and extracts the dedicated Attack Simulation Report.
        """
        res = cls.run_scan(
            target_input=target_input,
            target_type=target_type,
            level=level,
            progress_callback=progress_callback,
            log_callback=log_callback,
        )
        sim_data = res.target.metadata.get("attack_simulation") if res.target else None
        if sim_data:
            # Reconstruct or return from simulator
            return AttackResilienceSimulator.simulate(res)
        return AttackResilienceSimulator.simulate(res)
