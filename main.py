"""
CHARLO Testing Agent - Entrypoint.
Launches the PySide6 desktop workstation or runs headless CLI security scans.
"""

import sys
import os
import argparse

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure clean UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from charlo.core.models import TargetType, ScanLevel, CheckStatus
from charlo.core.engine import ScanEngine
from charlo.reporting.html_reporter import HTMLReporter
from charlo.reporting.json_reporter import JSONReporter
from charlo.database.storage import ScanDatabase


def run_cli(args):
    target = args.target
    level = ScanLevel(args.level.lower())
    target_type = TargetType(args.type.lower()) if args.type else None
    bugs_only = getattr(args, "bugs", False)

    mode_title = "Dedicated Software Defect Audit" if bugs_only else "Security & Defect Audit"
    print(f"\n=======================================================")
    print(f" CHARLO Testing Agent - {mode_title}")
    print(f"=======================================================")
    print(f"Target: {target}")
    print(f"Level:  {level.value.upper()}")
    print(f"Mode:   {'Bug Finder Only' if bugs_only else 'Full Security + Bugs'}")
    print(f"-------------------------------------------------------")

    def progress(pct, msg):
        print(f"[{pct:3d}%] {msg}")

    def log_msg(line):
        # Only print high level logs
        if "->" in line or "!" in line:
            print(f"      {line}")

    result = ScanEngine.run_scan(
        target_input=target,
        target_type=target_type,
        level=level,
        progress_callback=progress,
        log_callback=log_msg,
        bugs_only=bugs_only,
    )

    # Persist
    db = ScanDatabase()
    db.save_scan(result)

    metrics = result.metrics
    print(f"\n-------------------------------------------------------")
    print(f"POSTURE GRADE:   {metrics.posture_grade}")
    print(f"SECURITY SCORE:  {metrics.security_score} / 100")
    print(f"DEFECTS FOUND:   {metrics.total_bugs} Software Bugs Flagged")
    print(f"SUMMARY COUNTS:  Critical: {metrics.critical_count} | High: {metrics.high_count} | Med: {metrics.medium_count} | Low: {metrics.low_count} | Passed: {metrics.passed}")
    print(f"-------------------------------------------------------")

    # Bug findings summary
    bug_findings = [f for f in result.findings if getattr(f, "is_bug", False) and f.status in (CheckStatus.FAILED, CheckStatus.WARNING)]
    if bug_findings:
        print(f"\n=======================================================")
        print(f" [*] SOFTWARE DEFECTS DETECTED ({len(bug_findings)} Bugs Flagged)")
        print(f"=======================================================")
        for b in bug_findings:
            print(f" [{b.severity.value.upper():8s}] {b.check_id}: {b.title}")
            print(f"            Component:  {b.affected_component}")
            print(f"            Root Cause: {str(b.evidence)[:110]}")
            print(f"            Action:     {b.remediation[:110]}")
            if b.code_example:
                first_code_line = b.code_example.strip().splitlines()[0]
                print(f"            Patch:      {first_code_line[:90]}")
            print(f"-------------------------------------------------------")
    elif bugs_only:
        print(f"\n[+] Zero software defects detected for target.")

    # Domain Chronology, History & Admin Intelligence
    hist_data = result.target.metadata.get("history") if result.target and result.target.metadata else None
    if hist_data and (getattr(args, "history", False) or (result.target and result.target.target_type == TargetType.WEB)):
        reg = hist_data.get("registration", {})
        adm = hist_data.get("admin_profile", {})
        foot = hist_data.get("footprint", {})
        timeline = hist_data.get("timeline", [])
        sec = hist_data.get("security_incidents", {})

        print(f"\n=======================================================")
        print(f" [*] DOMAIN CHRONOLOGY & ADMIN INTELLIGENCE")
        print(f"=======================================================")
        print(f" Domain:         {hist_data.get('domain')}")
        print(f" Site Type:      {hist_data.get('site_type')}")
        print(f" Registered:     {reg.get('registered_date') or 'N/A'}")
        print(f" Expiration:     {reg.get('expiration_date') or 'N/A'} ({reg.get('days_to_expiration', 'N/A')} days left)")
        print(f" Domain Age:     {reg.get('age_description', 'Active')}")
        print(f" Registrar:      {reg.get('registrar', 'Unknown')}")
        print(f" Estimated Size: {foot.get('estimated_total_site_size', 'N/A')}")
        print(f"-------------------------------------------------------")
        print(f" ADMIN PROFILE:  {adm.get('tier', 'Intermediate')} (Score: {adm.get('score', 50)}/100)")
        print(f" Maintenance:    {adm.get('maintenance_velocity', 'Moderate')}")
        print(f" Behavior:       {adm.get('behavior_summary', '')}")
        if adm.get("strengths"):
            print(f" Strengths:      " + ", ".join(adm.get("strengths")[:2]))
        if adm.get("blind_spots"):
            print(f" Blind Spots:    " + ", ".join(adm.get("blind_spots")[:2]))
        print(f"-------------------------------------------------------")
        print(f" PAST INCIDENTS: Defacement Risk: {sec.get('defacement_risk_level', 'Low')} | {sec.get('reputation_notes', 'Clean')}")
        if timeline:
            print(f"-------------------------------------------------------")
            print(f" HISTORICAL TIMELINE & UPGRADES:")
            for m in timeline[-4:]:
                print(f"  • {m.get('year')}: {m.get('inferred_theme')} ({m.get('snapshot_count', 0)} snapshots)")
                if m.get("major_features_added"):
                    print(f"      Features: {', '.join(m.get('major_features_added')[:2])}")
        print(f"-------------------------------------------------------")

    # Test a Hack: Theoretical Attack Resilience Simulator
    sim_data = result.target.metadata.get("attack_simulation") if result.target and result.target.metadata else None
    if sim_data and (getattr(args, "attacks", False) or True):  # Output summary or full table
        print(f"\n=======================================================")
        print(f" [*] TEST A HACK: ATTACK RESILIENCE & SURVIVAL SIMULATOR")
        print(f"=======================================================")
        overall_pct = sim_data.get("overall_survival_chance", 70.0)
        overall_verdict = sim_data.get("overall_verdict", "Moderate Resilience")
        total_atks = sim_data.get("total_attacks_tested", 0)
        hardened = sim_data.get("hardened_count", 0)
        moderate = sim_data.get("moderate_count", 0)
        critical = sim_data.get("critical_exposure_count", 0)

        print(f" Target Survival Index:   {overall_pct}% ({overall_verdict})")
        print(f" Scenarios Evaluated:     Total: {total_atks} | Resilient: {hardened} | Moderate: {moderate} | Critical: {critical}")
        print(f"-------------------------------------------------------")

        for atk in sim_data.get("attacks", []):
            pct = atk.get("survival_chance", 50.0)
            atk_id = atk.get("attack_id")
            atk_name = atk.get("name")
            verdict = atk.get("verdict")

            # Status tag based on survival %
            tag = "HIGH SURVIVAL" if pct >= 75.0 else "MODERATE" if pct >= 50.0 else "LOW SURVIVAL"
            print(f" [{pct:5.1f}% | {tag:13s}] {atk_id}: {atk_name}")
            print(f"                        Objective: {atk.get('threat_objective')[:95]}...")
            print(f"                        Verdict:   {verdict}")
            if atk.get("mitigating_controls_active"):
                print(f"                        Defenses:  " + ", ".join(atk.get("mitigating_controls_active")[:2]))
            if atk.get("contributing_vulnerabilities"):
                top_v = atk.get("contributing_vulnerabilities")[0]
                print(f"                        Penalties: [{top_v.get('impact_penalty', 0):+.0f}%] {top_v.get('title')}")
            if atk.get("hardening_steps"):
                print(f"                        Hardening: {atk.get('hardening_steps')[0][:95]}...")
            print(f"-------------------------------------------------------")

    # Popular Tools Automation Testing (Playwright / Selenium / Appium / WinAppDriver)
    auto_data = result.target.metadata.get("automation_report") if result.target and result.target.metadata else None
    if auto_data and (getattr(args, "qa", False) or True):
        print(f"\n=======================================================")
        print(f" [*] POPULAR TOOLS QA AUTOMATION TEST RESULTS")
        print(f"=======================================================")
        print(f" Primary Framework:   {auto_data.get('primary_tool')} (Secondary: {auto_data.get('secondary_tool')})")
        print(f" Target Platform:     {auto_data.get('platform')}")
        print(f" QA Quality Score:    {auto_data.get('quality_score')}% ({auto_data.get('overall_status')})")
        print(f" Test Case Summary:   Total: {auto_data.get('total_tests')} | Passed: {auto_data.get('passed_tests')} | Defects: {auto_data.get('failed_tests')} | Warnings: {auto_data.get('warning_tests')}")
        print(f" Accessibility a11y:  {auto_data.get('accessibility_score')}/100")
        print(f"-------------------------------------------------------")
        for s in auto_data.get("suites", []):
            for tc in s.get("test_cases", []):
                st = tc.get("status")
                tag = f"[{st:7s}]"
                print(f" {tag} {tc.get('test_id'):12s} ({tc.get('tool')} - {tc.get('duration_ms')}ms): {tc.get('name')}")
                if st in ("FAILED", "WARNING"):
                    print(f"             Defect:     {tc.get('actual')}")
                    print(f"             Assertion:  {tc.get('assertion')}")
                    print(f"             Fix:        {tc.get('developer_patch')[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_qa", None):
        if auto_data:
            client_md = auto_data.get("copiable_client_markdown", "")
            with open(args.export_qa, "w", encoding="utf-8") as f:
                f.write(client_md)
            print(f"[+] Client-Ready QA Automation Report exported: {args.export_qa}")

    # REST & Backend API Contract Testing & Schema Fuzzing
    api_data = result.target.metadata.get("api_report") if result.target and result.target.metadata else None
    if api_data and (getattr(args, "api", False) or True):
        print(f"\n=======================================================")
        print(f" [⚡] REST & BACKEND API CONTRACT TESTING RESULTS")
        print(f"=======================================================")
        print(f" Base Endpoint:       {api_data.get('base_url')}")
        print(f" Specification:       {api_data.get('specification_format')}")
        print(f" API Quality Score:   {api_data.get('quality_score')}% ({api_data.get('overall_status')})")
        print(f" Endpoints Audited:   {api_data.get('total_endpoints')} (Tests Run: {api_data.get('total_tests')} | Passed: {api_data.get('passed_tests')} | Defects: {api_data.get('failed_tests')})")
        print(f" Rate Limiting:       {'Enforced & Active' if api_data.get('rate_limiting_active') else 'Unthrottled / Missing'}")
        print(f"-------------------------------------------------------")
        for tc in api_data.get("test_cases", []):
            st = tc.get("status")
            tag = f"[{st:7s}]"
            print(f" {tag} {tc.get('test_id'):12s} ({tc.get('method'):6s} {tc.get('latency_ms')}ms): {tc.get('test_name')} -> {tc.get('endpoint')}")
            if st in ("FAILED", "WARNING"):
                print(f"             Defect:     {tc.get('actual_status')}")
                print(f"             Fix:        {tc.get('developer_patch')[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_api", None):
        if api_data:
            export_path = args.export_api
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_api_report(api_data)
            else:
                content = api_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready API Report exported: {export_path}")

    if getattr(args, "postman", None):
        if api_data:
            postman_json = api_data.get("postman_collection_json", "")
            with open(args.postman, "w", encoding="utf-8") as f:
                f.write(postman_json)
            print(f"[+] Exportable Postman Collection v2.1.0 generated: {args.postman}")

    # Performance, Stress & Concurrency Load Testing Results (JMeter / k6)
    perf_data = result.target.metadata.get("performance_report") if result.target and result.target.metadata else None
    if perf_data and (getattr(args, "performance", False) or True):
        pct = perf_data.get("percentiles", {})
        print(f"\n=======================================================")
        print(f" [📈] CONCURRENCY LOAD & STRESS TESTING RESULTS")
        print(f"=======================================================")
        print(f" Load Profile:        {perf_data.get('load_profile')}")
        print(f" Virtual Users (VUs): {perf_data.get('virtual_users')} Concurrent Workers")
        print(f" Throughput:          {perf_data.get('throughput_rps')} RPS (Requests / Sec)")
        print(f" Capacity SLA:        {perf_data.get('sla_status')} (Grade {perf_data.get('performance_grade')})")
        print(f" Total Requests:      {perf_data.get('total_requests')} (Failed: {perf_data.get('failed_requests')} | Error Rate: {perf_data.get('error_rate_pct')}%)")
        print(f" Data Transferred:    {perf_data.get('bytes_transferred_kb')} KB")
        print(f"-------------------------------------------------------")
        print(f" LATENCY PERCENTILES:")
        print(f"   • Min:             {pct.get('min_ms')} ms")
        print(f"   • Avg (Mean):      {pct.get('avg_ms')} ms")
        print(f"   • p50 (Median):    {pct.get('median_p50_ms')} ms")
        print(f"   • p90:             {pct.get('p90_ms')} ms")
        print(f"   • p95 (SLA Gate):  {pct.get('p95_ms')} ms (Target < 500ms)")
        print(f"   • p99 (Tail):      {pct.get('p99_ms')} ms")
        print(f"   • Max Peak:        {pct.get('max_ms')} ms")
        print(f"-------------------------------------------------------")
        print(f" HTTP CODES:          " + ", ".join(f"{c}: {n}" for c, n in perf_data.get("status_codes_distribution", {}).items()))
        print(f" Bottleneck:          {perf_data.get('bottleneck_diagnosis')[:100]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_perf", None):
        if perf_data:
            export_path = args.export_perf
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_performance_report(perf_data)
            else:
                content = perf_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready Performance Report exported: {export_path}")

    if getattr(args, "k6", None):
        if perf_data:
            k6_code = perf_data.get("k6_script_content", "")
            with open(args.k6, "w", encoding="utf-8") as f:
                f.write(k6_code)
            print(f"[+] Grafana k6 Load Test Script exported: {args.k6}")

    if getattr(args, "jmeter", None):
        if perf_data:
            jmx_code = perf_data.get("jmeter_jmx_content", "")
            with open(args.jmeter, "w", encoding="utf-8") as f:
                f.write(jmx_code)
            print(f"[+] Apache JMeter Test Plan XML (.jmx) exported: {args.jmeter}")

    # CI/CD Quality Gate & Automated Pipeline Deliverables
    cicd_data = result.target.metadata.get("cicd_report") if result.target and result.target.metadata else None
    if cicd_data and (getattr(args, "cicd", False) or True):
        gate = cicd_data.get("gate_result", {})
        passed = gate.get("passed", True)
        tag = "[✅ PASSED]" if passed else "[❌ BREACHED]"
        print(f"\n=======================================================")
        print(f" [🚀] CI/CD QUALITY GATE & PIPELINE GENERATOR")
        print(f"=======================================================")
        print(f" Quality Gate Status: {tag} {gate.get('status')} (Health Score: {gate.get('overall_score', 100):.1f}%)")
        print(f" Policy Violations:   {gate.get('total_violations')} issue(s) flagged")
        print(f"-------------------------------------------------------")
        for idx, item in enumerate(gate.get("violation_details", []), start=1):
            icon = "✔" if passed else "✖"
            print(f" {icon} {item}")
        if gate.get("remediation_advice"):
            print(f"-------------------------------------------------------")
            for idx, r in enumerate(gate.get("remediation_advice", []), start=1):
                print(f"   • Remediation: {r}")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_cicd", None):
        if cicd_data:
            export_path = args.export_cicd
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_cicd_report(cicd_data)
            else:
                content = cicd_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready CI/CD Deliverable exported: {export_path}")

    if getattr(args, "github", None):
        if cicd_data:
            with open(args.github, "w", encoding="utf-8") as f:
                f.write(cicd_data.get("github_actions_yaml", ""))
            print(f"[+] GitHub Actions Workflow exported: {args.github}")

    if getattr(args, "gitlab", None):
        if cicd_data:
            with open(args.gitlab, "w", encoding="utf-8") as f:
                f.write(cicd_data.get("gitlab_ci_yaml", ""))
            print(f"[+] GitLab CI/CD Pipeline exported: {args.gitlab}")

    if getattr(args, "jenkins", None):
        if cicd_data:
            with open(args.jenkins, "w", encoding="utf-8") as f:
                f.write(cicd_data.get("jenkinsfile_content", ""))
            print(f"[+] Jenkins Declarative Pipeline exported: {args.jenkins}")

    if getattr(args, "junit", None):
        if cicd_data:
            with open(args.junit, "w", encoding="utf-8") as f:
                f.write(cicd_data.get("junit_xml_content", ""))
            print(f"[+] Universal JUnit XML Deliverable exported: {args.junit}")

    # Database & Data Layer Integrity, SQL Defense & Schema Validation
    db_data = result.target.metadata.get("database_report") if result.target and result.target.metadata else None
    if db_data and (getattr(args, "database", False) or True):
        score = db_data.get("data_integrity_score", 100.0)
        status = db_data.get("overall_status", "PRODUCTION CERTIFIED")
        print(f"\n=======================================================")
        print(f" [🗄️] DATABASE SCHEMA & DATA LAYER INTEGRITY RESULTS")
        print(f"=======================================================")
        print(f" Database Engine:     {db_data.get('database_engine')}")
        print(f" Integrity Score:     {score:.1f}% ({status})")
        print(f" Tables Inspected:    {db_data.get('total_tables_checked')} (Total Checks: {db_data.get('total_checks')} | Defects: {db_data.get('defects_count')})")
        print(f"-------------------------------------------------------")
        for d in db_data.get("defects", []):
            st = d.get("status")
            sev = d.get("severity")
            print(f" [{st:7s}] {d.get('defect_id'):10s} ({sev:8s}): {d.get('title')} -> {d.get('target_entity')}")
            if st in ("DEFECT", "WARNING"):
                print(f"             Impact:     {d.get('impact')[:95]}...")
                first_patch = d.get("remediation_sql", "").strip().splitlines()[0] if d.get("remediation_sql") else ""
                if first_patch:
                    print(f"             SQL Patch:  {first_patch[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_db", None):
        if db_data:
            export_path = args.export_db
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_database_report(db_data)
            else:
                content = db_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready Database Report exported: {export_path}")

    if getattr(args, "export_sql", None):
        if db_data:
            with open(args.export_sql, "w", encoding="utf-8") as f:
                f.write(db_data.get("ready_to_run_sql_migration", ""))
            print(f"[+] Remediation SQL Migration Patch exported: {args.export_sql}")

    # Cross-Platform Compatibility, Multi-Device Viewport & WCAG Accessibility
    compat_data = result.target.metadata.get("compatibility_report") if result.target and result.target.metadata else None
    if compat_data and (getattr(args, "compatibility", False) or True):
        comp_score = compat_data.get("compatibility_score", 100.0)
        comp_status = compat_data.get("overall_status", "WCAG AA CERTIFIED")
        print(f"\n=======================================================")
        print(f" [📱] MULTI-DEVICE VIEWPORT & WCAG ACCESSIBILITY RESULTS")
        print(f"=======================================================")
        print(f" Compatibility Score: {comp_score:.1f}% ({comp_status})")
        print(f" Viewports Audited:   {compat_data.get('total_viewports_tested')} Devices (Total Checks: {compat_data.get('total_checks')} | Defects: {compat_data.get('defects_count')})")
        print(f"-------------------------------------------------------")
        for dev in compat_data.get("devices", []):
            st = dev.get("status", "PASSED")
            dims = f"{dev.get('viewport_width')}x{dev.get('viewport_height')}"
            over = "OVERFLOW" if dev.get("horizontal_overflow") else "Clean"
            print(f" [{st:7s}] {dev.get('name')[:20]:20s} ({dims:10s} | {dev.get('device_scale_factor')}x DPR) -> Lateral: {over} | Touch Hazards: {dev.get('touch_hazard_count')}")
        print(f"-------------------------------------------------------")
        for d in compat_data.get("defects", []):
            st = d.get("status")
            sev = d.get("severity")
            print(f" [{st:7s}] {d.get('defect_id'):12s} ({sev:8s}): {d.get('title')} -> {d.get('affected_viewport')}")
            if st in ("DEFECT", "WARNING"):
                print(f"             Impact:     {d.get('impact')[:95]}...")
                first_code = d.get("remediation_code", "").strip().splitlines()[0] if d.get("remediation_code") else ""
                if first_code:
                    print(f"             CSS Fix:    {first_code[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_compat", None):
        if compat_data:
            export_path = args.export_compat
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_compatibility_report(compat_data)
            else:
                content = compat_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready Compatibility Report exported: {export_path}")

    if getattr(args, "playwright_matrix", None):
        if compat_data:
            with open(args.playwright_matrix, "w", encoding="utf-8") as f:
                f.write(compat_data.get("playwright_matrix_script", ""))
            print(f"[+] Playwright Multi-Device Matrix Script exported: {args.playwright_matrix}")

    if getattr(args, "cypress_matrix", None):
        if compat_data:
            with open(args.cypress_matrix, "w", encoding="utf-8") as f:
                f.write(compat_data.get("cypress_matrix_script", ""))
            print(f"[+] Cypress Multi-Device Viewport Script exported: {args.cypress_matrix}")

    # Network Protocol, TLS Cryptographic Ciphers & Certificate Validation
    net_data = result.target.metadata.get("network_report") if result.target and result.target.metadata else None
    if net_data and (getattr(args, "network", False) or True):
        grade = net_data.get("tls_grade", "A")
        score = net_data.get("crypto_score", 100.0)
        status = net_data.get("overall_status", "ENTERPRISE HARDENED")
        cipher_info = net_data.get("cipher_info") or {}
        cert_info = net_data.get("cert_info") or {}
        print(f"\n=======================================================")
        print(f" [🔐] NETWORK PROTOCOL, TLS CIPHERS & CERTIFICATE RESULTS")
        print(f"=======================================================")
        print(f" TLS Health Grade:    GRADE {grade} (Score: {score:.1f}% / 100.0 - {status})")
        print(f" Negotiated Cipher:   {cipher_info.get('protocol_version')} -> {cipher_info.get('cipher_suite')}")
        print(f" Forward Secrecy:     {'ENABLED (PFS)' if cipher_info.get('perfect_forward_secrecy') else 'DISABLED (Vulnerable)'}")
        print(f" X.509 Certificate:   {cert_info.get('issuer_org')} ({cert_info.get('days_to_expiration')} days left | Key: {cert_info.get('key_type_and_bits')})")
        print(f" Total Checks:        {net_data.get('total_checks')} (Defects: {net_data.get('defects_count')} | Warnings: {net_data.get('warnings_count')})")
        print(f"-------------------------------------------------------")
        for d in net_data.get("defects", []):
            st = d.get("status")
            sev = d.get("severity")
            print(f" [{st:7s}] {d.get('defect_id'):12s} ({sev:8s}): {d.get('title')} -> {d.get('target_component')}")
            if st in ("DEFECT", "WARNING"):
                print(f"             Impact:     {d.get('impact')[:95]}...")
                first_cfg = d.get("remediation_config", "").strip().splitlines()[0] if d.get("remediation_config") else ""
                if first_cfg:
                    print(f"             Config Fix: {first_cfg[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_tls", None):
        if net_data:
            export_path = args.export_tls
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_network_report(net_data)
            else:
                content = net_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready Network & TLS Report exported: {export_path}")

    if getattr(args, "openssl", None):
        if net_data:
            with open(args.openssl, "w", encoding="utf-8") as f:
                f.write(net_data.get("openssl_diagnostic_script", ""))
            print(f"[+] OpenSSL Diagnostic Shell Script exported: {args.openssl}")

    # Business Logic, State Machine & Workflow Transaction Flaws
    logic_data = result.target.metadata.get("business_logic_report") if result.target and result.target.metadata else None
    if logic_data and (getattr(args, "logic", False) or True):
        score = logic_data.get("logic_integrity_score", 100.0)
        status = logic_data.get("overall_status", "LOGIC HARDENED")
        print(f"\n=======================================================")
        print(f" [💼] BUSINESS LOGIC & TRANSACTION INTEGRITY RESULTS")
        print(f"=======================================================")
        print(f" Logic Integrity Score: {score:.1f}% ({status})")
        print(f" Workflows Audited:     {logic_data.get('total_workflows_evaluated')} State Machines (Total Checks: {logic_data.get('total_checks')} | Defects: {logic_data.get('defects_count')})")
        print(f"-------------------------------------------------------")
        for f in logic_data.get("flaws", []):
            st = f.get("status")
            sev = f.get("severity")
            print(f" [{st:7s}] {f.get('flaw_id'):12s} ({sev:8s}): {f.get('title')} -> {f.get('target_workflow')}")
            if st in ("DEFECT", "WARNING"):
                print(f"             Impact:     {f.get('impact')[:95]}...")
                first_remedy = f.get("remediation_pattern", "").strip().splitlines()[0] if f.get("remediation_pattern") else ""
                if first_remedy:
                    print(f"             Remedy:     {first_remedy[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_logic", None):
        if logic_data:
            export_path = args.export_logic
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_business_logic_report(logic_data)
            else:
                content = logic_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready Business Logic Report exported: {export_path}")

    if getattr(args, "pytest_logic", None):
        if logic_data:
            with open(args.pytest_logic, "w", encoding="utf-8") as f:
                f.write(logic_data.get("pytest_logic_suite", ""))
            print(f"[+] Pytest Business Logic Test Suite exported: {args.pytest_logic}")

    # Memory Leak, OS Handle Exhaustion & Resource Leak Diagnostics
    mem_data = result.target.metadata.get("memory_report") if result.target and result.target.metadata else None
    if mem_data and (getattr(args, "memory", False) or True):
        score = mem_data.get("memory_stability_score", 100.0)
        status = mem_data.get("overall_status", "MEMORY STABLE & HARDENED")
        m = mem_data.get("metrics", {})
        print(f"\n=======================================================")
        print(f" [🧠] MEMORY LEAK, HANDLE PROFILING & RESOURCE LEAKS")
        print(f"=======================================================")
        print(f" Memory Stability:    {score:.1f}% ({status})")
        print(f" Initial Working Set: {m.get('initial_memory_mb', 0):.1f} MB -> Peak: {m.get('peak_working_set_mb', 0):.1f} MB (Delta: +{m.get('memory_growth_delta_mb', 0):.1f} MB)")
        print(f" OS Kernel Handles:   {m.get('active_handle_count', 0)} active -> Peak: {m.get('peak_handle_count', 0)} (Cap: 10,000)")
        print(f" Projected Leak Rate: +{m.get('projected_leak_rate_mb_hr', 0):.1f} MB/hr under continuous duty")
        print(f" Total Checks:        {mem_data.get('total_checks')} (Defects: {mem_data.get('defects_count')} | Warnings: {mem_data.get('warnings_count')})")
        print(f"-------------------------------------------------------")
        for d in mem_data.get("defects", []):
            st = d.get("status")
            sev = d.get("severity")
            print(f" [{st:7s}] {d.get('defect_id'):12s} ({sev:8s}): {d.get('title')} -> {d.get('target_component')}")
            if st in ("DEFECT", "WARNING"):
                print(f"             Leak Rate:  {d.get('leak_rate')}")
                print(f"             Impact:     {d.get('impact')[:95]}...")
                first_remedy = d.get("remediation_pattern", "").strip().splitlines()[0] if d.get("remediation_pattern") else ""
                if first_remedy:
                    print(f"             Remedy:     {first_remedy[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_memory", None):
        if mem_data:
            export_path = args.export_memory
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_memory_report(mem_data)
            else:
                content = mem_data.get("copiable_client_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready Memory & Resource Report exported: {export_path}")

    if getattr(args, "leak_script", None):
        if mem_data:
            with open(args.leak_script, "w", encoding="utf-8") as f:
                f.write(mem_data.get("diagnostic_script", ""))
            print(f"[+] Memory Leak Diagnostic Stress Script exported: {args.leak_script}")

    # Accessibility Audit & Assistive Technology Matrix (WCAG 2.2 / Section 508 / VPAT)
    a11y_data = result.target.metadata.get("accessibility_report") if result.target and result.target.metadata else None
    if a11y_data and (getattr(args, "accessibility", False) or True):
        m = a11y_data.get("metrics", {})
        score = m.get("wcag_score", 100.0)
        status = m.get("conformance_status", "CONFORMS (WCAG 2.2 AA)")
        print(f"\n=======================================================")
        print(f" [♿] ACCESSIBILITY & ASSISTIVE TECH (WCAG 2.2 / VPAT)")
        print(f"=======================================================")
        print(f" Accessibility Score: {score:.1f}% ({status})")
        print(f" Conformance Target:  W3C WCAG 2.2 Level A/AA & Revised Section 508")
        print(f" Evaluated Criteria:  {m.get('total_criteria_checked')} (Conforming: {m.get('passed_criteria')} | Defects: {m.get('defects_count')} | Warnings: {m.get('warnings_count')})")
        print(f" Specific Violations: Contrast: {m.get('contrast_violations')} | Missing Alt/Labels: {m.get('missing_labels')} | Keyboard Traps: {m.get('keyboard_traps')}")
        print(f"-------------------------------------------------------")
        for d in a11y_data.get("defects", []):
            st = d.get("status")
            sev = d.get("level")
            print(f" [{st:7s}] {d.get('defect_id'):14s} (Level {sev:3s}): {d.get('title')} -> {d.get('wcag_sc')}")
            if st in ("DEFECT", "WARNING"):
                print(f"             Target:     {d.get('target_element')}")
                print(f"             Impact:     {d.get('screen_reader_impact')[:95]}...")
                first_remedy = d.get("remediation_code", "").strip().splitlines()[0] if d.get("remediation_code") else ""
                if first_remedy:
                    print(f"             Fix:        {first_remedy[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_a11y", None):
        if a11y_data:
            export_path = args.export_a11y
            if export_path.endswith(".html"):
                content = HTMLReporter.generate_accessibility_report(a11y_data)
            else:
                content = a11y_data.get("copiable_vpat_markdown", "")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Client-Ready Accessibility Report exported: {export_path}")

    if getattr(args, "export_vpat", None):
        if a11y_data:
            with open(args.export_vpat, "w", encoding="utf-8") as f:
                f.write(a11y_data.get("copiable_vpat_markdown", ""))
            print(f"[+] Official VPAT 2.4 Markdown Deliverable exported: {args.export_vpat}")

    if getattr(args, "axe_script", None):
        if a11y_data:
            with open(args.axe_script, "w", encoding="utf-8") as f:
                f.write(a11y_data.get("axe_playwright_suite", ""))
            print(f"[+] Axe-Core & Playwright WCAG Test Suite exported: {args.axe_script}")

    # GraphQL & WebSocket Protocol Security Suite
    gql_data = result.target.metadata.get("graphql_report") if result.target and result.target.metadata else None
    if gql_data and (getattr(args, "graphql", False) or True):
        score = gql_data.get("score", 100.0)
        status = gql_data.get("overall_status", "SECURE")
        print(f"\n=======================================================")
        print(f" [🛰️] GRAPHQL & WEBSOCKET PROTOCOL SECURITY SUITE")
        print(f"=======================================================")
        print(f" Protocol Score:      {score:.1f}% ({status})")
        print(f" Target Endpoints:    GraphQL: {gql_data.get('graphql_endpoint')} | WS: {gql_data.get('websocket_endpoint')}")
        print(f" Introspection:       {'EXPOSED' if gql_data.get('introspection_enabled') else 'SECURED'}")
        print(f" Query Depth Limits:  {'ENFORCED' if gql_data.get('max_query_depth_enforced') else 'UNRESTRICTED (DoS RISK)'}")
        print(f" CSWSH Protection:    {'ENFORCED' if gql_data.get('cswsh_protected') else 'MISSING (HIJACKING RISK)'}")
        print(f" Defects Identified:  {gql_data.get('defects_count')}")
        print(f"-------------------------------------------------------")
        for d in gql_data.get("defects", []):
            st = d.get("status")
            sev = d.get("severity")
            print(f" [{st:7s}] {d.get('defect_id'):10s} [{d.get('protocol')} - {sev:6s}]: {d.get('title')}")
            print(f"             Category:   {d.get('category')}")
            print(f"             Impact:     {d.get('impact')[:95]}...")
        print(f"-------------------------------------------------------")

    if getattr(args, "export_graphql", None):
        if gql_data:
            from charlo.analyzers.graphql_websocket_tester import GraphQLWebSocketReport
            # Reconstruct report object for markdown generation
            with open(args.export_graphql, "w", encoding="utf-8") as f:
                f.write(f"# GraphQL & WebSocket Security Report\nScore: {gql_data.get('score')}%\nStatus: {gql_data.get('overall_status')}\n")
            print(f"[+] GraphQL & WebSocket Security Report exported: {args.export_graphql}")

    if getattr(args, "sarif", None):
        from charlo.reporting.sarif_reporter import SarifReporter
        sarif_file = SarifReporter.export_to_file(result, args.sarif)
        print(f"[+] OASIS SARIF 2.1.0 Report generated: {sarif_file}")

    if getattr(args, "webhook", None):
        from charlo.core.webhook_notifier import WebhookNotifier
        wh_res = WebhookNotifier.dispatch_alert(args.webhook, result)
        print(f"[+] Webhook Alert Dispatch: {wh_res.get('message')}")

    if args.html:
        html_out = HTMLReporter.generate_report(result)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"[+] HTML Report generated: {args.html}")

    if args.json:
        json_out = JSONReporter.export(result)
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(json_out)
        print(f"[+] JSON Data generated: {args.json}")

    print(f"[+] Scan completed successfully.\n")


def run_gui():
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QIcon
    from charlo.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("CHARLO Testing Agent")
    app.setOrganizationName("CHARLO Security")

    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "charlo_icon.png")
    if os.path.exists(icon_path):
        app_icon = QIcon(icon_path)
        app.setWindowIcon(app_icon)

    window = MainWindow()
    if os.path.exists(icon_path):
        window.setWindowIcon(QIcon(icon_path))
    window.show()
    sys.exit(app.exec())


def main():
    parser = argparse.ArgumentParser(description="CHARLO Testing Agent - AI-Powered Security Testing Laboratory")
    parser.add_argument("--cli", action="store_true", help="Run in headless CLI mode instead of GUI")
    parser.add_argument("--target", type=str, help="Target APK file, EXE file, or Website URL")
    parser.add_argument("--type", type=str, choices=["apk", "exe", "web"], help="Target type override")
    parser.add_argument("--level", type=str, choices=["basic", "intermediate", "advanced"], default="intermediate", help="Scan rigor level")
    parser.add_argument("--html", type=str, help="Path to export HTML security report")
    parser.add_argument("--json", type=str, help="Path to export JSON audit findings")
    parser.add_argument("--bugs", action="store_true", help="Run dedicated Bug Finder audit for software defects")
    parser.add_argument("--history", action="store_true", help="Display domain chronology, RDAP history, admin intelligence, and footprint")
    parser.add_argument("--attacks", "--test-a-hack", dest="attacks", action="store_true", help="Display theoretical attack resilience simulator and survival probability matrix")
    parser.add_argument("--qa", "--automation", dest="qa", action="store_true", help="Display popular automation tools QA testing results (Playwright, Selenium, Appium, WinAppDriver)")
    parser.add_argument("--export-qa", type=str, help="Export copiable client-ready QA deliverable report (Markdown)")
    parser.add_argument("--api", action="store_true", help="Display REST & backend API contract testing and schema fuzzing results")
    parser.add_argument("--export-api", type=str, help="Export copiable client-ready API deliverable report (.md or .html)")
    parser.add_argument("--postman", type=str, help="Export runnable Postman Collection v2.1.0 JSON")
    parser.add_argument("--performance", "--load", dest="performance", action="store_true", help="Display performance, stress, and concurrency load testing metrics (JMeter / k6)")
    parser.add_argument("--vus", type=int, default=50, help="Virtual users concurrency count for load simulation")
    parser.add_argument("--export-perf", type=str, help="Export copiable client-ready performance deliverable report (.md or .html)")
    parser.add_argument("--k6", type=str, help="Export runnable Grafana k6 JavaScript load test script")
    parser.add_argument("--jmeter", type=str, help="Export runnable Apache JMeter Test Plan XML (.jmx)")
    parser.add_argument("--cicd", "--quality-gate", dest="cicd", action="store_true", help="Display CI/CD quality gate enforcement and automated pipeline configurations")
    parser.add_argument("--export-cicd", type=str, help="Export copiable client-ready CI/CD deliverable report (.md or .html)")
    parser.add_argument("--github", type=str, help="Export production-grade GitHub Actions workflow YAML (.github/workflows/quality_gate.yml)")
    parser.add_argument("--gitlab", type=str, help="Export production-grade GitLab CI/CD pipeline YAML (.gitlab-ci.yml)")
    parser.add_argument("--jenkins", type=str, help="Export production-grade Jenkins Declarative Pipeline (Jenkinsfile)")
    parser.add_argument("--junit", type=str, help="Export universal JUnit XML test report (junit_results.xml)")
    parser.add_argument("--database", "--db", dest="database", action="store_true", help="Display database schema integrity, indexing traps, and SQL defense verification")
    parser.add_argument("--export-db", type=str, help="Export copiable client-ready database report (.md or .html)")
    parser.add_argument("--export-sql", type=str, help="Export idempotent DDL remediation SQL patch (.sql)")
    parser.add_argument("--viewport", "--compatibility", "--compat", dest="compatibility", action="store_true", help="Display multi-device responsive viewport matrix and WCAG accessibility audit")
    parser.add_argument("--export-compat", type=str, help="Export copiable client-ready compatibility deliverable report (.md or .html)")
    parser.add_argument("--playwright-matrix", type=str, help="Export runnable Playwright multi-device matrix Python test script")
    parser.add_argument("--cypress-matrix", type=str, help="Export runnable Cypress multi-device viewport JavaScript test script")
    parser.add_argument("--network", "--tls", dest="network", action="store_true", help="Display network protocol, TLS cryptographic cipher suites, and certificate validation")
    parser.add_argument("--export-tls", type=str, help="Export copiable client-ready network & TLS deliverable report (.md or .html)")
    parser.add_argument("--openssl", type=str, help="Export runnable OpenSSL cryptographic diagnostic shell script (.sh)")
    parser.add_argument("--logic", "--business-logic", dest="logic", action="store_true", help="Display business logic, state machine, and transaction flaw audit results")
    parser.add_argument("--export-logic", type=str, help="Export copiable client-ready business logic deliverable report (.md or .html)")
    parser.add_argument("--pytest-logic", type=str, help="Export runnable Pytest business logic test suite (.py)")
    parser.add_argument("--memory", "--heap", "--leak-audit", dest="memory", action="store_true", help="Display memory leak, OS handle exhaustion, and resource profiling results")
    parser.add_argument("--export-memory", type=str, help="Export copiable client-ready memory deliverable report (.md or .html)")
    parser.add_argument("--leak-script", type=str, help="Export runnable memory leak diagnostic stress test script")
    parser.add_argument("--wcag", "--a11y", "--accessibility", dest="accessibility", action="store_true", help="Display WCAG 2.2, Section 508, and screen reader accessibility audit results")
    parser.add_argument("--export-a11y", type=str, help="Export copiable client-ready accessibility deliverable report (.md or .html)")
    parser.add_argument("--export-vpat", type=str, help="Export official VPAT 2.4 accessibility conformance deliverable (.md)")
    parser.add_argument("--axe-script", type=str, help="Export runnable Axe-Core & Playwright WCAG AA test suite (.py)")
    parser.add_argument("--graphql", dest="graphql", action="store_true", help="Display GraphQL and WebSocket security flaw analysis")
    parser.add_argument("--export-graphql", type=str, help="Export GraphQL & WebSocket vulnerability deliverable (.md)")
    parser.add_argument("--sarif", type=str, help="Export official OASIS SARIF 2.1.0 JSON report (for GitHub/GitLab Security)")
    parser.add_argument("--webhook", type=str, help="Webhook URL to dispatch scan completion alert (Slack, Discord, Teams, Generic)")

    args = parser.parse_args()

    if args.cli or args.target:
        if not args.target:
            parser.error("--target is required when running in CLI mode")
        run_cli(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
