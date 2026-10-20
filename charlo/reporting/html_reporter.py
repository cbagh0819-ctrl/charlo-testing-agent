"""
HTML Security Assessment Report Generator for CHARLO Testing Agent.
Generates self-contained, publication-grade responsive HTML reports
including AI-Powered Executive Threat Modeling and Attack Surface Analysis.
"""

import html
import datetime
from typing import Dict, Any, Optional, Union
from ..core.models import ScanResult, Severity, CheckStatus, TargetType
from ..core.scoring import RiskCalculator
from ..core.threat_model import ThreatModelGenerator
from ..analyzers.web_history import WebHistoryAnalyzer
from ..analyzers.attack_simulator import AttackResilienceSimulator
from ..analyzers.automation_tools import PopularToolsAutomationTester
from ..analyzers.api_tester import ApiTester


class HTMLReporter:
    """
    Renders standalone interactive HTML security assessment reports.
    """

    @classmethod
    def generate_report(cls, result: ScanResult) -> str:
        target = result.target
        target_name = target.display_name if target else "Unknown Target"
        target_type = target.target_type.value.upper() if target else "UNKNOWN"
        target_sha = target.sha256 if target else "N/A"
        metrics = result.metrics

        risk_label, risk_color = RiskCalculator.get_risk_label(
            metrics.security_score, metrics.critical_count
        )

        threat_model = ThreatModelGenerator.generate_threat_model(result)

        # 1. Plausible Attacks HTML
        attacks_html = []
        if threat_model["plausible_attacks"]:
            for i, atk in enumerate(threat_model["plausible_attacks"], start=1):
                p_color = "#ff3366" if "critical" in atk["priority"].lower() else "#ff6b22" if "high" in atk["priority"].lower() else "#ffb800"
                attacks_html.append(f"""
                <div class="attack-card">
                    <div class="attack-header">
                        <div class="attack-title">{i}. {html.escape(atk['name'])}</div>
                        <span class="attack-priority" style="background:{p_color};">{html.escape(atk['priority'])}</span>
                    </div>
                    <div class="attack-ref"><strong>Triggered by:</strong> <code>{html.escape(atk['finding_ref'])}</code></div>
                    <p class="attack-scenario">{html.escape(atk['scenario'])}</p>
                    <div class="attack-caveat">
                        <strong>Important:</strong> {html.escape(atk['caveat'])}
                    </div>
                </div>
                """)
        else:
            attacks_html.append("""
            <div class="clean-box">
                No immediate high-probability exploitation attack paths identified for current target configuration.
            </div>
            """)
        attacks_str = "\n".join(attacks_html)

        # 2. Investigation Risks Table HTML
        investigation_rows = []
        for row in threat_model["investigation_risks"]:
            investigation_rows.append(f"""
            <tr>
                <td style="font-weight:600; color:#00d4ff;">{html.escape(row['threat'])}</td>
                <td>{html.escape(row['finding'])}</td>
            </tr>
            """)
        investigation_table_str = "\n".join(investigation_rows)

        # 3. Roadmap HTML
        roadmap_items = []
        for i, step in enumerate(threat_model["roadmap"], start=1):
            roadmap_items.append(f"""
            <li class="roadmap-item">
                <span class="roadmap-num">{i}</span>
                <span class="roadmap-text">{html.escape(step)}</span>
            </li>
            """)
        roadmap_str = "\n".join(roadmap_items) if roadmap_items else "<p>Target meets current defense-in-depth baseline.</p>"

        # 3.5 Bug Finder Section HTML
        bug_findings = [f for f in result.findings if getattr(f, "is_bug", False) and f.status in (CheckStatus.FAILED, CheckStatus.WARNING)]
        bug_section_html = ""
        if bug_findings:
            bug_cards = []
            for b in bug_findings:
                b_color = b.severity.badge_color
                code_snippet = f"<div class='code-box'><div class='code-header'>Recommended Bug Fix:</div><pre><code>{html.escape(b.code_example)}</code></pre></div>" if b.code_example else ""
                bug_cards.append(f"""
                <div class="attack-card" style="border-left: 5px solid {b_color};">
                    <div class="attack-header">
                        <div class="attack-title">&#128030; {html.escape(b.check_id)}: {html.escape(b.title)}</div>
                        <span class="attack-priority" style="background:{b_color};">{html.escape(b.severity.value.upper())}</span>
                    </div>
                    <div class="attack-ref"><strong>Affected Component:</strong> <code>{html.escape(b.affected_component)}</code> | <strong>Category:</strong> {html.escape(b.category)}</div>
                    <p class="attack-scenario"><strong>Root Cause & Evidence:</strong> {html.escape(b.evidence)}</p>
                    <p class="attack-scenario" style="color:#d7e0f0;"><strong>Impact:</strong> {html.escape(b.impact)}</p>
                    <div class="attack-caveat">
                        <strong>Actionable Fix:</strong> {html.escape(b.remediation)}
                    </div>
                    {code_snippet}
                </div>
                """)
            bug_cards_str = "\n".join(bug_cards)
            bug_section_html = f"""
            <div class="threat-section" style="border-left: 4px solid #00d4ff; margin-top:30px;">
                <h2 class="section-title" style="color:#00d4ff;">&#128030; Dedicated Bug Finder & Software Defects ({len(bug_findings)} Defects Flagged)</h2>
                <p style="color:var(--text-muted); font-size:13.5px; margin-bottom:20px;">
                    CHARLO's dedicated software quality engine audited memory/handle lifecycles, form input boundaries, broken routes, stack traces, and runtime API calls.
                </p>
                {bug_cards_str}
            </div>
            """

        # 3.8 Domain History & Admin Intelligence Section HTML
        history_section_html = ""
        hist_data = target.metadata.get("history") if target and target.metadata else None
        if not hist_data and target and getattr(target, "target_type", None) == TargetType.WEB:
            try:
                hist_data = WebHistoryAnalyzer.analyze(target.target_path).to_dict()
            except Exception:
                pass

        if hist_data:
            reg = hist_data.get("registration", {})
            adm = hist_data.get("admin_profile", {})
            timeline = hist_data.get("timeline", [])
            sec = hist_data.get("security_incidents", {})
            foot = hist_data.get("footprint", {})

            # Timeline cards
            t_cards = []
            for m in timeline:
                feats = "".join([f"<li>{html.escape(f)}</li>" for f in m.get("major_features_added", [])])
                t_cards.append(f"""
                <div class="attack-card" style="margin-bottom:12px;">
                    <div class="attack-header">
                        <div class="attack-title"><span style="color:#00d4ff; font-weight:800;">{m.get('year')}</span> &bull; {html.escape(m.get('inferred_theme', ''))}</div>
                        <span class="attack-priority" style="background:#1f2d4d; color:#00ff9d;">{m.get('snapshot_count', 0)} Snapshots</span>
                    </div>
                    <div style="font-size:12px; color:#8b9bb4; margin:4px 0 8px 0;"><strong>Architecture:</strong> {html.escape(m.get('architecture_status', ''))}</div>
                    <ul style="font-size:12px; color:#cfdaf0; padding-left:18px; margin:0;">{feats}</ul>
                </div>
                """)
            t_cards_str = "\n".join(t_cards)

            str_items = "".join([f"<li style='color:#00ff9d;'>&#10004; {html.escape(s)}</li>" for s in adm.get("strengths", [])]) or "<li>Standard functional posture</li>"
            bsp_items = "".join([f"<li style='color:#ffb800;'>&#9888; {html.escape(b)}</li>" for b in adm.get("blind_spots", [])]) or "<li>No glaring administrative oversights noted</li>"

            history_section_html = f"""
            <div class="threat-section" style="border-left: 4px solid #00ff9d; margin-top:30px;">
                <h2 class="section-title" style="color:#00ff9d;">&#127760; Domain Chronology, Historical Evolution & Admin Intelligence</h2>
                <p style="color:var(--text-muted); font-size:13.5px; margin-bottom:20px;">
                    Forensic domain registration records (RDAP), historical Wayback snapshot chronology, administrative technical maturity assessment, and storage footprint analysis.
                </p>

                <!-- Domain Vital Stats -->
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:20px;">
                    <div class="stat-card" style="text-align:left; padding:15px;">
                        <div class="stat-label">Domain Lifespan / Age</div>
                        <div style="font-size:15px; font-weight:800; color:#00d4ff; margin-top:5px;">{html.escape(reg.get('age_description', 'Active'))}</div>
                        <div style="font-size:11px; color:#8b9bb4; margin-top:3px;">Registered: {html.escape(reg.get('registered_date') or 'N/A')}</div>
                    </div>
                    <div class="stat-card" style="text-align:left; padding:15px;">
                        <div class="stat-label">Domain Expiration</div>
                        <div style="font-size:15px; font-weight:800; color:{'#ff3366' if reg.get('is_expired') else '#00ff9d'}; margin-top:5px;">
                            {html.escape(reg.get('expiration_date') or 'N/A')}
                        </div>
                        <div style="font-size:11px; color:#8b9bb4; margin-top:3px;">Days Remaining: {reg.get('days_to_expiration', 'N/A')}</div>
                    </div>
                    <div class="stat-card" style="text-align:left; padding:15px;">
                        <div class="stat-label">Registrar & DNSSEC</div>
                        <div style="font-size:14px; font-weight:700; color:#f0f4fc; margin-top:5px;">{html.escape(reg.get('registrar', 'Unknown'))}</div>
                        <div style="font-size:11px; color:#8b9bb4; margin-top:3px;">DNSSEC: {'Enabled (Signed)' if reg.get('dnssec_enabled') else 'Disabled / Inactive'}</div>
                    </div>
                    <div class="stat-card" style="text-align:left; padding:15px;">
                        <div class="stat-label">Website Type & Classification</div>
                        <div style="font-size:14px; font-weight:700; color:#ffb800; margin-top:5px;">{html.escape(hist_data.get('site_type', 'General Web Application'))}</div>
                        <div style="font-size:11px; color:#8b9bb4; margin-top:3px;">Content: {html.escape(foot.get('content_richness', 'Standard'))}</div>
                    </div>
                    <div class="stat-card" style="text-align:left; padding:15px;">
                        <div class="stat-label">Estimated Storage Footprint</div>
                        <div style="font-size:14px; font-weight:700; color:#00d4ff; margin-top:5px;">{html.escape(foot.get('estimated_total_site_size', 'N/A'))}</div>
                        <div style="font-size:11px; color:#8b9bb4; margin-top:3px;">Homepage Transfer: ~{foot.get('sampled_asset_weight_mb', 0)} MB</div>
                    </div>
                </div>

                <!-- Admin Profile Card -->
                <div class="attack-card" style="background:#0f172a; border: 1px solid #1e293b; margin-bottom:20px;">
                    <div class="attack-header">
                        <div class="attack-title">&#128104;&#8205;&#128188; Administrator Technical Maturity & Behavior Profile</div>
                        <span class="attack-priority" style="background:#00d4ff; color:#0b0f19;">Knowledge Score: {adm.get('score', 50)}/100</span>
                    </div>
                    <div style="font-size:14px; font-weight:700; color:#00ff9d; margin:6px 0;">Tier: {html.escape(adm.get('tier', 'Intermediate'))} (Update Velocity: {html.escape(adm.get('maintenance_velocity', 'Moderate'))})</div>
                    <p style="font-size:13px; color:#cbd5e1; margin-bottom:12px;">{html.escape(adm.get('behavior_summary', ''))}</p>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px;">
                        <div>
                            <strong style="font-size:11.5px; text-transform:uppercase; color:#00ff9d; letter-spacing:0.5px;">Observed Technical Strengths:</strong>
                            <ul style="font-size:12px; margin:6px 0 0 16px; padding:0;">{str_items}</ul>
                        </div>
                        <div>
                            <strong style="font-size:11.5px; text-transform:uppercase; color:#ffb800; letter-spacing:0.5px;">Administrator Blind Spots:</strong>
                            <ul style="font-size:12px; margin:6px 0 0 16px; padding:0;">{bsp_items}</ul>
                        </div>
                    </div>
                </div>

                <!-- Past Hacking & Security Incident History -->
                <div class="attack-card" style="background:#0f172a; border-left: 5px solid {'#ff3366' if sec.get('has_past_incident_indicators') else '#00ff9d'}; margin-bottom:20px;">
                    <div class="attack-header">
                        <div class="attack-title">&#128737;&#65039; Historical Security & Past Incident Forensic Audit</div>
                        <span class="attack-priority" style="background:{'#ff3366' if sec.get('has_past_incident_indicators') else '#00ff9d'}; color:#0b0f19;">
                            Defacement Risk: {sec.get('defacement_risk_level', 'Low')}
                        </span>
                    </div>
                    <p style="font-size:13px; color:#cbd5e1; margin:6px 0;">{html.escape(sec.get('reputation_notes', ''))}</p>
                    <div style="font-size:12px; color:#8b9bb4;"><strong>Historical Outage Pattern:</strong> {html.escape(sec.get('historical_downtime_patterns', 'Stable'))}</div>
                </div>

                <!-- Year-by-Year Evolution Timeline -->
                <h3 class="subhead" style="margin-top:20px;">&#128197; Year-by-Year Evolutionary Upgrades & Feature Timeline</h3>
                {t_cards_str}
            </div>
            """

        # 3.9 Attack Resilience & Theoretical Threat Survival Section HTML
        sim_data = target.metadata.get("attack_simulation") if target and target.metadata else None
        if not sim_data:
            try:
                sim_data = AttackResilienceSimulator.simulate(result).to_dict()
            except Exception:
                sim_data = None

        attack_resilience_section_html = ""
        if sim_data:
            sim_attacks = sim_data.get("attacks", [])
            overall_pct = sim_data.get("overall_survival_chance", 70.0)
            overall_verdict = sim_data.get("overall_verdict", "Moderate Resilience")
            overall_color = sim_data.get("overall_badge_color", "#ffb800")

            sim_cards = []
            for atk in sim_attacks:
                atk_pct = atk.get("survival_chance", 50.0)
                atk_color = atk.get("verdict_badge_color", "#ffb800")
                atk_verdict = atk.get("verdict", "")

                vuln_items = []
                for v in atk.get("contributing_vulnerabilities", []):
                    vuln_items.append(
                        f"<li><span style='color:#ff3366; font-weight:700;'>[{v.get('impact_penalty', 0):+.0f}%]</span> "
                        f"<strong>{html.escape(v.get('title', ''))}:</strong> {html.escape(v.get('description', ''))}</li>"
                    )
                vulns_html = "".join(vuln_items) if vuln_items else "<li style='color:#00ff9d;'>&#10004; Zero contributing vulnerability penalties flagged</li>"

                active_items = "".join([f"<li style='color:#00ff9d;'>&#10004; {html.escape(d)}</li>" for d in atk.get("mitigating_controls_active", [])]) or "<li>Basic platform baseline</li>"
                hard_items = "".join([f"<li>{html.escape(h)}</li>" for h in atk.get("hardening_steps", [])])

                sim_cards.append(f"""
                <div class="attack-card" style="border-left: 5px solid {atk_color}; margin-bottom: 20px;">
                    <div class="attack-header">
                        <div>
                            <span class="attack-title">&#9876;&#65039; {html.escape(atk.get('name', ''))}</span>
                            <span style="font-size:11px; color:#8b9bb4; margin-left:8px;">({html.escape(atk.get('category', ''))})</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span style="font-size:18px; font-weight:900; color:{atk_color};">{atk_pct}% Survival</span>
                            <span class="attack-priority" style="background:{atk_color};">{html.escape(atk_verdict)}</span>
                        </div>
                    </div>

                    <div style="background:#131b2e; border-radius:10px; height:8px; width:100%; margin:8px 0 14px 0; overflow:hidden;">
                        <div style="background:{atk_color}; height:100%; width:{atk_pct}%; border-radius:10px;"></div>
                    </div>

                    <div style="font-size:12.5px; color:#cfdaf0; margin-bottom:8px;">
                        <strong>Threat Actor Objective:</strong> {html.escape(atk.get('threat_objective', ''))}
                    </div>
                    <p class="attack-scenario" style="font-size:12.5px; margin-bottom:12px;">
                        <strong>Theoretical Vector Mechanics:</strong> {html.escape(atk.get('vector_description', ''))}
                    </p>

                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px; background:#080d1a; padding:12px; border-radius:6px; margin-bottom:12px;">
                        <div>
                            <strong style="font-size:11px; text-transform:uppercase; color:#00ff9d; letter-spacing:0.5px;">Confirmed Mitigating Controls:</strong>
                            <ul style="font-size:11.5px; margin:6px 0 0 16px; padding:0;">{active_items}</ul>
                        </div>
                        <div>
                            <strong style="font-size:11px; text-transform:uppercase; color:#ff3366; letter-spacing:0.5px;">Vulnerabilities Reducing Survival:</strong>
                            <ul style="font-size:11.5px; margin:6px 0 0 16px; padding:0;">{vulns_html}</ul>
                        </div>
                    </div>

                    <div class="attack-caveat" style="background:#0f172a; border-left:3px solid #00d4ff; color:#d7e8ff;">
                        <strong style="color:#00d4ff;">Required Defensive Hardening to Reach 95%+ Survival:</strong>
                        <ol style="font-size:11.5px; margin:6px 0 0 18px; padding:0;">{hard_items}</ol>
                    </div>
                </div>
                """)
            sim_cards_str = "\n".join(sim_cards)

            attack_resilience_section_html = f"""
            <div class="threat-section" style="border-left: 4px solid #ff3366; margin-top:30px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px; margin-bottom:15px;">
                    <div>
                        <h2 class="section-title" style="color:#ff3366; margin-bottom:4px;">&#9876;&#65039; Test a Hack: Theoretical Attack Resilience & Survival Simulator</h2>
                        <p style="color:var(--text-muted); font-size:13.5px; margin:0;">
                            Mathematical survival probability modeling against real-world theoretical attack scenarios (SQLi, DDoS, BOLA/IDOR, XSS, Buffer Overflow, DLL Side-Loading, Pass-the-Hash/Kerberoasting, Ransomware, SSRF).
                        </p>
                    </div>
                    <div style="background:#0c1322; border:1px solid #1f2d4d; border-radius:10px; padding:12px 20px; text-align:center;">
                        <div style="font-size:11px; text-transform:uppercase; color:#8b9bb4; letter-spacing:1px;">Target Survival Index</div>
                        <div style="font-size:28px; font-weight:900; color:{overall_color};">{overall_pct}%</div>
                        <div style="font-size:11px; font-weight:700; color:{overall_color};">{overall_verdict}</div>
                    </div>
                </div>

                <div class="disclaimer-box" style="margin-bottom:20px;">
                    <strong>Defensive Modeling Notice:</strong> These scenarios simulate theoretical exploit mechanics against observed target defenses and configuration weaknesses. They are completely safe and non-destructive. Survival probabilities reflect mathematical defense-in-depth maturity rather than physical penetration execution.
                </div>

                {sim_cards_str}
            </div>
            """

        # 3.9 Popular Tools QA Automation Testing HTML
        automation_section_html = ""
        auto_data = target.metadata.get("automation_report") if target and target.metadata else None
        if not auto_data and target:
            try:
                auto_data = PopularToolsAutomationTester.run_tests(target, findings=result.findings).to_dict()
                target.metadata["automation_report"] = auto_data
            except Exception:
                pass

        if auto_data:
            auto_status_color = "#00ff9d" if "PROD" in auto_data.get("overall_status", "") else "#ffb800" if "ATTENTION" in auto_data.get("overall_status", "") else "#ff3366"
            test_rows = []
            for suite in auto_data.get("suites", []):
                for tc in suite.get("test_cases", []):
                    tc_color = "#00ff9d" if tc.get("status") == "PASSED" else "#ff3366" if tc.get("status") == "FAILED" else "#ffb800"
                    test_rows.append(f"""
                    <tr>
                        <td><code>{html.escape(tc.get('test_id', ''))}</code></td>
                        <td><span style="background:{tc_color}; color:#0b0f19; font-weight:800; font-size:10px; padding:2px 7px; border-radius:4px;">{html.escape(tc.get('status', ''))}</span></td>
                        <td><strong>{html.escape(tc.get('name', ''))}</strong><div style="font-size:11px; color:#8b9bb4;">{html.escape(tc.get('suite', ''))}</div></td>
                        <td style="color:#00d4ff; font-weight:600;">{html.escape(tc.get('tool', ''))}</td>
                        <td style="color:#cbd5e1;">{tc.get('duration_ms', 0)}ms</td>
                        <td style="font-size:12px; color:#d7daf0;">{html.escape(tc.get('details', ''))}</td>
                    </tr>
                    """)
            test_rows_html = "\n".join(test_rows)

            automation_section_html = f"""
            <div class="threat-section" style="border-left: 4px solid #00ff9d; margin-top:30px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px; margin-bottom:15px;">
                    <div>
                        <h2 class="section-headline" style="color:#00ff9d; margin-bottom:4px;">🧪 Popular Tools QA Automation Testing ({html.escape(auto_data.get('primary_tool', ''))} & {html.escape(auto_data.get('secondary_tool', ''))})</h2>
                        <p style="color:var(--text-muted); font-size:13.5px; margin:0;">
                            Automated functional, UI hierarchy, responsive cross-browser, and lifecycle testing conforming to industry QA standards.
                        </p>
                    </div>
                    <div style="background:#0c1322; border:1px solid #1f2d4d; border-radius:10px; padding:12px 20px; text-align:center;">
                        <div style="font-size:11px; text-transform:uppercase; color:#8b9bb4; letter-spacing:1px;">Automation Score</div>
                        <div style="font-size:28px; font-weight:900; color:{auto_status_color};">{auto_data.get('quality_score', 0)}%</div>
                        <div style="font-size:11px; font-weight:700; color:{auto_status_color};">{html.escape(auto_data.get('overall_status', ''))}</div>
                    </div>
                </div>

                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin-bottom:20px;">
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Total Tests</div>
                        <div style="font-size:22px; font-weight:800; color:#f0f4fc; margin-top:4px;">{auto_data.get('total_tests', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Passed Tests</div>
                        <div style="font-size:22px; font-weight:800; color:#00ff9d; margin-top:4px;">{auto_data.get('passed_tests', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Defects Flagged</div>
                        <div style="font-size:22px; font-weight:800; color:#ff3366; margin-top:4px;">{auto_data.get('failed_tests', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Warnings / Flaky</div>
                        <div style="font-size:22px; font-weight:800; color:#ffb800; margin-top:4px;">{auto_data.get('warning_tests', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Accessibility Score</div>
                        <div style="font-size:22px; font-weight:800; color:#00d4ff; margin-top:4px;">{auto_data.get('accessibility_score', 95.0)}/100</div>
                    </div>
                </div>

                <h3 class="subhead">Automated Test Cases Execution Grid</h3>
                <div style="overflow-x:auto;">
                    <table class="risk-table" style="font-size:12.5px;">
                        <thead>
                            <tr>
                                <th>Test ID</th>
                                <th>Status</th>
                                <th>Test Case & Suite</th>
                                <th>Automation Tool</th>
                                <th>Duration</th>
                                <th>Evidence & Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {test_rows_html}
                        </tbody>
                    </table>
                </div>

                <div class="code-box" style="margin-top:20px;">
                    <div class="code-header">Ready-to-Run Primary Automation Test Script ({html.escape(auto_data.get('primary_tool', ''))}):</div>
                    <pre><code>{html.escape(auto_data.get('ready_to_run_script_primary', ''))}</code></pre>
                </div>
            </div>
            """

        # 3.10 REST & Backend API Contract Testing HTML
        api_section_html = ""
        api_data = target.metadata.get("api_report") if target and target.metadata else None
        if not api_data and target:
            try:
                api_data = ApiTester.run_tests(target, findings=result.findings).to_dict()
                target.metadata["api_report"] = api_data
            except Exception:
                pass

        if api_data:
            api_status_color = "#00ff9d" if "PROD" in api_data.get("overall_status", "") else "#ffb800" if "ATTENTION" in api_data.get("overall_status", "") else "#ff3366"
            api_test_rows = []
            for tc in api_data.get("test_cases", []):
                tc_color = "#00ff9d" if tc.get("status") == "PASSED" else "#ff3366" if tc.get("status") == "FAILED" else "#ffb800"
                api_test_rows.append(f"""
                <tr>
                    <td><code>{html.escape(tc.get('test_id', ''))}</code></td>
                    <td><span style="background:{tc_color}; color:#0b0f19; font-weight:800; font-size:10px; padding:2px 7px; border-radius:4px;">{html.escape(tc.get('status', ''))}</span></td>
                    <td style="color:#00d4ff; font-weight:700;">{html.escape(tc.get('method', ''))}</td>
                    <td><strong>{html.escape(tc.get('endpoint', ''))}</strong></td>
                    <td style="color:#a855f7; font-weight:600;">{html.escape(tc.get('category', ''))}</td>
                    <td style="color:#cbd5e1;">{tc.get('latency_ms', 0)}ms</td>
                    <td style="font-size:12px; color:#d7daf0;">{html.escape(tc.get('details', ''))}</td>
                </tr>
                """)
            api_test_rows_html = "\n".join(api_test_rows)

            api_section_html = f"""
            <div class="threat-section" style="border-left: 4px solid #00d4ff; margin-top:30px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:15px; margin-bottom:15px;">
                    <div>
                        <h2 class="section-headline" style="color:#00d4ff; margin-bottom:4px;">⚡ REST & Backend API Contract Testing ({html.escape(api_data.get('specification_format', 'REST'))})</h2>
                        <p style="color:var(--text-muted); font-size:13.5px; margin:0;">
                            Automated schema validation, negative boundary fuzzing, BOLA/IDOR authorization guards, and rate limiting diagnostics.
                        </p>
                    </div>
                    <div style="background:#0c1322; border:1px solid #1f2d4d; border-radius:10px; padding:12px 20px; text-align:center;">
                        <div style="font-size:11px; text-transform:uppercase; color:#8b9bb4; letter-spacing:1px;">API Quality Score</div>
                        <div style="font-size:28px; font-weight:900; color:{api_status_color};">{api_data.get('quality_score', 0)}%</div>
                        <div style="font-size:11px; font-weight:700; color:{api_status_color};">{html.escape(api_data.get('overall_status', ''))}</div>
                    </div>
                </div>

                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin-bottom:20px;">
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Total Endpoints</div>
                        <div style="font-size:22px; font-weight:800; color:#f0f4fc; margin-top:4px;">{api_data.get('total_endpoints', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Tests Dispatched</div>
                        <div style="font-size:22px; font-weight:800; color:#00d4ff; margin-top:4px;">{api_data.get('total_tests', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Passed Tests</div>
                        <div style="font-size:22px; font-weight:800; color:#00ff9d; margin-top:4px;">{api_data.get('passed_tests', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Contract Defects</div>
                        <div style="font-size:22px; font-weight:800; color:#ff3366; margin-top:4px;">{api_data.get('failed_tests', 0)}</div>
                    </div>
                    <div class="stat-card" style="padding:15px; text-align:left;">
                        <div class="stat-label">Rate Limiting</div>
                        <div style="font-size:18px; font-weight:800; color:{'#00ff9d' if api_data.get('rate_limiting_active') else '#ffb800'}; margin-top:6px;">{'Enforced' if api_data.get('rate_limiting_active') else 'Unthrottled'}</div>
                    </div>
                </div>

                <h3 class="subhead">API Endpoint Verification & Boundary Fuzzing Matrix</h3>
                <div style="overflow-x:auto;">
                    <table class="risk-table" style="font-size:12.5px;">
                        <thead>
                            <tr>
                                <th>Test ID</th>
                                <th>Status</th>
                                <th>Method</th>
                                <th>Endpoint Path</th>
                                <th>Category</th>
                                <th>Latency</th>
                                <th>Observed Telemetry & Criteria</th>
                            </tr>
                        </thead>
                        <tbody>
                            {api_test_rows_html}
                        </tbody>
                    </table>
                </div>

                <div class="code-box" style="margin-top:20px;">
                    <div class="code-header">Ready-to-Run Python Test Script (Pytest / Requests):</div>
                    <pre><code>{html.escape(api_data.get('ready_to_run_python_script', ''))}</code></pre>
                </div>
            </div>
            """

        # 4. Individual Findings Cards HTML
        findings_html = []
        for i, f in enumerate(result.findings, start=1):
            badge_color = f.severity.badge_color
            status_badge = (
                f'<span class="badge" style="background:{badge_color};">{f.severity.value.upper()}</span>'
                if f.status in (CheckStatus.FAILED, CheckStatus.WARNING)
                else f'<span class="badge" style="background:#00FF9D; color:#0b0f19;">PASSED</span>'
            )

            code_block = ""
            if f.code_example:
                code_block = f"""
                <div class="code-box">
                    <div class="code-header">Secure Implementation Example:</div>
                    <pre><code>{html.escape(f.code_example)}</code></pre>
                </div>
                """

            verif_block = ""
            if f.verification_step:
                verif_block = f"""
                <div class="verif-box">
                    <strong>Verification Test:</strong> {html.escape(f.verification_step)}
                </div>
                """

            standards_tags = "".join(
                [f'<span class="std-tag">{html.escape(s)}</span>' for s in f.standards]
            )

            findings_html.append(f"""
            <div class="finding-card {f.severity.value} status-{f.status.value}">
                <div class="finding-header">
                    <div class="finding-title-group">
                        <span class="finding-id">{html.escape(f.check_id)}</span>
                        <h3 class="finding-title">{html.escape(f.title)}</h3>
                    </div>
                    <div>{status_badge}</div>
                </div>

                <div class="finding-meta">
                    <div><strong>Component:</strong> <code>{html.escape(f.affected_component)}</code></div>
                    <div><strong>Category:</strong> {html.escape(f.category)}</div>
                    <div><strong>Standards:</strong> {standards_tags or 'General Security'}</div>
                </div>

                <div class="finding-body">
                    <div class="section-label">Evidence & Discovery:</div>
                    <pre class="evidence-box"><code>{html.escape(str(f.evidence))}</code></pre>

                    <div class="section-label">Potential Impact:</div>
                    <p class="impact-text">{html.escape(f.impact)}</p>

                    <div class="section-label">Actionable Remediation Guidance:</div>
                    <p class="remediation-text">{html.escape(f.remediation)}</p>

                    {code_block}
                    {verif_block}
                </div>
            </div>
            """)

        all_findings_str = "\n".join(findings_html)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHARLO Security Audit - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #131b2e;
            --surface-hover: #19233c;
            --border: #1f2d4d;
            --text-main: #f0f4fc;
            --text-muted: #8b9bb4;
            --cyan: #00d4ff;
            --green: #00ff9d;
            --yellow: #ffb800;
            --orange: #ff6b22;
            --red: #ff3366;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: var(--bg); color: var(--text-main); line-height: 1.5; padding: 40px 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}

        /* Header */
        .report-header {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 30px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px; }}
        .brand-title {{ font-size: 26px; font-weight: 800; letter-spacing: 1px; color: var(--cyan); }}
        .brand-subtitle {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1.5px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }}
        .meta-item {{ font-size: 13px; }}
        .meta-label {{ color: var(--text-muted); font-size: 11px; text-transform: uppercase; }}

        /* Executive Scorecard */
        .scorecard {{ display: grid; grid-template-columns: 280px 1fr; gap: 20px; margin-bottom: 25px; }}
        .grade-box {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 25px; text-align: center; display: flex; flex-direction: column; justify-content: center; align-items: center; }}
        .grade-badge {{ font-size: 58px; font-weight: 900; line-height: 1; margin: 10px 0; color: {risk_color}; }}
        .score-val {{ font-size: 20px; font-weight: 700; color: var(--text-main); }}
        .risk-pill {{ display: inline-block; padding: 4px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; background: {risk_color}; color: #0b0f19; margin-top: 8px; }}

        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 15px; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }}
        .stat-num {{ font-size: 32px; font-weight: 800; margin-top: 5px; }}
        .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }}

        /* Threat Model Section */
        .threat-section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 30px; margin-bottom: 30px; }}
        .section-headline {{ font-size: 22px; font-weight: 800; color: var(--cyan); margin-bottom: 12px; display: flex; align-items: center; gap: 10px; }}
        .exec-narrative {{ font-size: 14.5px; line-height: 1.6; color: #dce6f8; margin-bottom: 25px; background: #0c1322; padding: 16px 20px; border-left: 4px solid var(--cyan); border-radius: 6px; }}

        .subhead {{ font-size: 16px; font-weight: 700; color: #f0f4fc; margin: 25px 0 12px 0; text-transform: uppercase; letter-spacing: 0.5px; }}

        .attack-card {{ background: #0c1322; border: 1px solid var(--border); border-radius: 8px; padding: 18px 20px; margin-bottom: 15px; }}
        .attack-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 8px; }}
        .attack-title {{ font-size: 16px; font-weight: 700; color: #fff; }}
        .attack-priority {{ padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: #0b0f19; }}
        .attack-ref {{ font-size: 12px; color: var(--text-muted); margin-bottom: 10px; }}
        .attack-scenario {{ font-size: 13.5px; color: #cfdaf0; line-height: 1.5; margin-bottom: 10px; }}
        .attack-caveat {{ background: #131b2e; border-left: 3px solid var(--yellow); padding: 8px 12px; border-radius: 4px; font-size: 12px; color: #ffdb80; }}

        /* Risk Table */
        .risk-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 25px; }}
        .risk-table th {{ background: #0c1322; color: var(--text-muted); text-align: left; padding: 10px 14px; font-size: 11px; text-transform: uppercase; border: 1px solid var(--border); }}
        .risk-table td {{ padding: 12px 14px; border: 1px solid var(--border); font-size: 13px; color: #d0dcf5; }}

        /* Disclaimer */
        .disclaimer-box {{ background: #181926; border-left: 4px solid #ff9900; padding: 14px 18px; border-radius: 6px; font-size: 13px; color: #f5d59e; line-height: 1.5; margin-bottom: 25px; }}

        /* Roadmap */
        .roadmap-list {{ list-style: none; margin-top: 10px; }}
        .roadmap-item {{ display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px; background: #0c1322; padding: 12px 16px; border-radius: 6px; border: 1px solid var(--border); }}
        .roadmap-num {{ background: var(--cyan); color: #0b0f19; font-weight: 800; font-size: 12px; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 2px; }}
        .roadmap-text {{ font-size: 13.5px; color: #e4edf8; font-weight: 500; }}

        /* Findings */
        .findings-section {{ margin-top: 35px; }}
        .section-title {{ font-size: 20px; font-weight: 700; margin-bottom: 15px; color: var(--cyan); }}

        .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 20px; padding: 25px; transition: border-color 0.2s; }}
        .finding-card.critical {{ border-left: 5px solid var(--red); }}
        .finding-card.high {{ border-left: 5px solid var(--orange); }}
        .finding-card.medium {{ border-left: 5px solid var(--yellow); }}
        .finding-card.low {{ border-left: 5px solid var(--cyan); }}
        .finding-card.status-passed {{ border-left: 5px solid var(--green); }}

        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px; gap: 10px; }}
        .finding-id {{ font-size: 11px; font-weight: 700; background: #1c2844; padding: 2px 8px; border-radius: 4px; color: var(--cyan); margin-bottom: 5px; display: inline-block; }}
        .finding-title {{ font-size: 17px; font-weight: 700; }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: #fff; }}

        .finding-meta {{ display: flex; flex-wrap: wrap; gap: 20px; font-size: 12px; color: var(--text-muted); border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 15px; }}
        .std-tag {{ background: #1f2b48; color: #b1c4e9; padding: 2px 6px; border-radius: 4px; margin-right: 5px; font-size: 10px; }}

        .section-label {{ font-size: 12px; text-transform: uppercase; font-weight: 700; color: var(--text-muted); margin: 12px 0 6px 0; letter-spacing: 0.5px; }}
        .evidence-box {{ background: #070a12; border: 1px solid var(--border); padding: 12px; border-radius: 6px; font-size: 12px; font-family: Consolas, monospace; color: #9bc5ff; overflow-x: auto; margin-bottom: 12px; white-space: pre-wrap; }}
        .impact-text, .remediation-text {{ font-size: 13.5px; color: #d7e0f0; margin-bottom: 10px; }}

        .code-box {{ background: #070a12; border: 1px solid #27375e; border-radius: 6px; padding: 12px; margin-top: 10px; }}
        .code-header {{ font-size: 11px; font-weight: 700; color: var(--green); margin-bottom: 6px; }}
        pre code {{ font-family: Consolas, Monaco, monospace; font-size: 12px; color: #e1ebff; }}

        .verif-box {{ background: #12213a; border-left: 3px solid var(--cyan); padding: 10px; font-size: 12px; margin-top: 10px; border-radius: 4px; }}

        footer {{ text-align: center; margin-top: 50px; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 25px; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="report-header">
            <div>
                <div class="brand-title">CHARLO Testing Agent</div>
                <div class="brand-subtitle">Automated Security Assessment & Remediation Laboratory</div>
                <div class="meta-grid">
                    <div class="meta-item"><span class="meta-label">Target Name:</span><br><strong>{html.escape(target_name)}</strong></div>
                    <div class="meta-item"><span class="meta-label">Target Type:</span><br><strong>{target_type}</strong></div>
                    <div class="meta-item"><span class="meta-label">Scan Level:</span><br><strong>{result.level.value.upper()}</strong></div>
                    <div class="meta-item"><span class="meta-label">Scan Timestamp:</span><br>{result.start_time[:19].replace('T', ' ')} UTC</div>
                    <div class="meta-item"><span class="meta-label">Duration:</span><br>{result.duration_seconds}s</div>
                    <div class="meta-item"><span class="meta-label">SHA-256 Digest:</span><br><code style="font-size:10px;">{target_sha[:20]}...</code></div>
                </div>
            </div>
        </div>

        <!-- Executive Scorecard -->
        <div class="scorecard">
            <div class="grade-box">
                <div class="stat-label">Security Posture Grade</div>
                <div class="grade-badge">{metrics.posture_grade}</div>
                <div class="score-val">{metrics.security_score} <span style="font-size:13px; color:var(--text-muted);">/ 100</span></div>
                <div class="risk-pill">{risk_label}</div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Critical</div>
                    <div class="stat-num" style="color:var(--red);">{metrics.critical_count}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">High</div>
                    <div class="stat-num" style="color:var(--orange);">{metrics.high_count}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Medium</div>
                    <div class="stat-num" style="color:var(--yellow);">{metrics.medium_count}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Low</div>
                    <div class="stat-num" style="color:var(--cyan);">{metrics.low_count}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Passed</div>
                    <div class="stat-num" style="color:var(--green);">{metrics.passed}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Software Defects</div>
                    <div class="stat-num" style="color:var(--cyan);">{metrics.total_bugs}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Checks</div>
                    <div class="stat-num" style="color:var(--text-main);">{metrics.total_checks}</div>
                </div>
            </div>
        </div>

        <!-- Section 1: Executive Threat Surface & Attack Scenarios Analysis -->
        <div class="threat-section">
            <h2 class="section-headline">🛡️ Executive Threat Analysis & Attack Surface Assessment</h2>
            <div class="exec-narrative">{html.escape(threat_model['executive_summary'])}</div>

            <h3 class="subhead">1. Potential Attack Vectors That Might Harm the Target</h3>
            {attacks_str}

            <h3 class="subhead">2. Additional Risks Worth Investigating</h3>
            <table class="risk-table">
                <thead>
                    <tr>
                        <th style="width:35%;">Attack / Risk Type</th>
                        <th>What This Assessment Confirms vs Scope Boundaries</th>
                    </tr>
                </thead>
                <tbody>
                    {investigation_table_str}
                </tbody>
            </table>

            <h3 class="subhead">3. Why You Should Not Treat This as a Confirmed Penetration Test</h3>
            <div class="disclaimer-box">
                {html.escape(threat_model['methodology_disclaimer'])}
            </div>

            <h3 class="subhead">4. Prioritized Defensive Roadmap (What Should Be Fixed First?)</h3>
            <ul class="roadmap-list">
                {roadmap_str}
            </ul>
        </div>

        <!-- Section 1.3: Domain History, RDAP & Admin Intelligence -->
        {history_section_html}

        <!-- Section 1.5: Dedicated Software Defects & Bug Finder -->
        {bug_section_html}

        <!-- Section 1.8: Test a Hack - Theoretical Attack Resilience & Survival Simulator -->
        {attack_resilience_section_html}

        <!-- Section 1.9: Popular Tools QA Automation Testing -->
        {automation_section_html}

        <!-- Section 1.10: REST & Backend API Contract Testing -->
        {api_section_html}

        <!-- Section 2: Detailed Evidence-Backed Check Findings -->
        <div class="findings-section">
            <h2 class="section-title">Technical Check Findings & Evidence Log ({len(result.findings)} Evaluated)</h2>
            {all_findings_str}
        </div>

        <!-- Footer -->
        <footer>
            CHARLO Testing Agent &bull; Defensive Application Security Verification Laboratory &bull; Generated for authorized assessment purposes only.
        </footer>
    </div>
</body>
</html>
"""
        return html_template

    @classmethod
    def generate_qa_report(cls, auto_data: Any) -> str:
        """
        Generates a dedicated standalone HTML QA deliverable for clients and employers.
        """
        if hasattr(auto_data, "to_dict"):
            auto_data = auto_data.to_dict()

        target_name = auto_data.get("target_name", "Target Application")
        platform = auto_data.get("platform", "Cross-Platform")
        p_tool = auto_data.get("primary_tool", "Primary Tool")
        s_tool = auto_data.get("secondary_tool", "Secondary Tool")
        score = auto_data.get("quality_score", 100.0)
        status = auto_data.get("overall_status", "PRODUCTION READY")
        total_tests = auto_data.get("total_tests", 0)
        passed_tests = auto_data.get("passed_tests", 0)
        failed_tests = auto_data.get("failed_tests", 0)
        warning_tests = auto_data.get("warning_tests", 0)
        flaky_count = auto_data.get("flaky_count", 0)
        a11y_score = auto_data.get("accessibility_score", 95.0)
        exec_time = auto_data.get("duration_seconds", 0.0)
        timestamp = auto_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        status_color = "#00ff9d" if "PROD" in status else "#ffb800" if "ATTENTION" in status else "#ff3366"

        test_rows = []
        defect_cards = []
        for suite in auto_data.get("suites", []):
            s_name = suite.get("name", "")
            for tc in suite.get("test_cases", []):
                tc_st = tc.get("status", "PASSED")
                tc_col = "#00ff9d" if tc_st == "PASSED" else "#ff3366" if tc_st == "FAILED" else "#ffb800"
                test_rows.append(f"""
                <tr>
                    <td><code>{html.escape(tc.get('test_id', ''))}</code></td>
                    <td><span class="badge" style="background:{tc_col}; color:#0b0f19; font-weight:800; font-size:10px; padding:3px 8px; border-radius:4px;">{html.escape(tc_st)}</span></td>
                    <td><strong>{html.escape(tc.get('name', ''))}</strong><div style="font-size:11px; color:#8b9bb4;">{html.escape(s_name)}</div></td>
                    <td style="color:#00d4ff; font-weight:600;">{html.escape(tc.get('tool', ''))}</td>
                    <td style="color:#cbd5e1;">{tc.get('duration_ms', 0)}ms</td>
                    <td style="font-size:12px; color:#d7daf0;">{html.escape(tc.get('assertion', ''))}</td>
                    <td style="font-size:11.5px; color:#94a3b8;">{html.escape(tc.get('actual', ''))}</td>
                </tr>
                """)

                if tc_st in ("FAILED", "WARNING"):
                    repro_str = "".join([f"<li>{html.escape(step)}</li>" for step in tc.get("reproduction_steps", [])])
                    defect_cards.append(f"""
                    <div class="card" style="border-left: 4px solid {tc_col}; margin-bottom: 16px; background:#121826; border-radius:8px; padding:16px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <h3 style="margin:0; font-size:15px; color:#ffffff;">{html.escape(tc.get('name', ''))} ({html.escape(tc.get('test_id', ''))})</h3>
                            <span class="badge" style="background:{tc_col}; color:#0b0f19; font-weight:800; font-size:10.5px; padding:3px 8px; border-radius:4px;">{html.escape(tc_st)}</span>
                        </div>
                        <p style="color:#cbd5e1; font-size:13px; margin:8px 0 4px 0;"><strong>Observed Failure:</strong> {html.escape(tc.get('details', tc.get('actual', '')))}</p>
                        {f'<div style="margin-top:8px;"><strong style="font-size:12px; color:#94a3b8;">Reproduction Steps:</strong><ol style="margin:4px 0 0 18px; color:#cbd5e1; font-size:12px;">{repro_str}</ol></div>' if repro_str else ''}
                        {f'<div style="margin-top:10px;"><strong style="font-size:12px; color:#00d4ff;">Developer Remediation / Patch:</strong><pre style="background:#0b0e14; padding:10px; border-radius:6px; color:#38bdf8; font-size:12px; overflow-x:auto;"><code>{html.escape(tc.get("developer_patch", ""))}</code></pre></div>' if tc.get("developer_patch") else ''}
                    </div>
                    """)

        test_table_html = "\n".join(test_rows)
        defects_html = "\n".join(defect_cards) if defect_cards else """
        <div style="background:#0d1814; border:1px solid #143828; border-radius:8px; padding:16px; color:#00ff9d; font-size:13.5px;">
            ✔ <strong>Zero Blocking Defects Detected:</strong> All functional, UI boundary, and accessibility assertions passed verification.
        </div>
        """

        p_script = auto_data.get("ready_to_run_script_primary", "")
        s_script = auto_data.get("ready_to_run_script_secondary", "")
        cicd_yaml = auto_data.get("ci_cd_pipeline_yaml", "")
        copiable_md = auto_data.get("copiable_client_markdown", "")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QA Automation Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f1420;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        .btn {{
            background: var(--accent);
            color: #0b0f19;
            padding: 9px 18px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 800;
            font-size: 12px;
            border: none;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19; font-size:11px; font-weight:800;">QA AUTOMATION DELIVERABLE</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Platform: <strong>{html.escape(platform)}</strong> &bull;
                    Primary Tool: <strong style="color:var(--accent);">{html.escape(p_tool)}</strong> &bull;
                    Secondary: <strong style="color:var(--accent);">{html.escape(s_tool)}</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted);">Automated QA Quality Score</div>
                <div style="font-size:38px; font-weight:900; color:{status_color};">{score:.1f}%</div>
                <div style="font-size:12px; font-weight:700; color:{status_color};">{html.escape(status)}</div>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Total Tests</div>
                <div class="kpi-val" style="color:#ffffff;">{total_tests}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Passed Assertions</div>
                <div class="kpi-val" style="color:var(--green);">{passed_tests}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Defects Flagged</div>
                <div class="kpi-val" style="color:var(--primary);">{failed_tests}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Flaky / Warning</div>
                <div class="kpi-val" style="color:var(--amber);">{warning_tests}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Accessibility Score</div>
                <div class="kpi-val" style="color:var(--accent);">{a11y_score}/100</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Execution Duration</div>
                <div class="kpi-val" style="color:#a855f7;">{exec_time}s</div>
            </div>
        </div>

        <div class="section">
            <h2>1. Automated Test Cases Execution Grid</h2>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Test ID</th>
                            <th>Status</th>
                            <th>Test Case & Suite</th>
                            <th>Tool</th>
                            <th>Latency</th>
                            <th>Assertion Criteria</th>
                            <th>Actual Telemetry</th>
                        </tr>
                    </thead>
                    <tbody>
                        {test_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>2. Flagged Defects & Remediation Fixes</h2>
            {defects_html}
        </div>

        <div class="section">
            <h2>3. Ready-to-Run Primary Automation Test Script ({html.escape(p_tool)})</h2>
            <pre><code>{html.escape(p_script)}</code></pre>
        </div>

        {f'''<div class="section">
            <h2>4. Ready-to-Run Secondary Automation Test Script ({html.escape(s_tool)})</h2>
            <pre><code>{html.escape(s_script)}</code></pre>
        </div>''' if s_script else ''}

        {f'''<div class="section">
            <h2>5. CI/CD Pipeline Automation (GitHub Actions / Azure DevOps)</h2>
            <pre><code>{html.escape(cicd_yaml)}</code></pre>
        </div>''' if cicd_yaml else ''}

        <div class="section">
            <h2>6. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Industrial Automated QA & Quality Engineering Deliverable System
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_api_report(cls, api_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for REST and backend API testing.
        """
        if hasattr(api_data, "to_dict"):
            api_data = api_data.to_dict()

        target_name = api_data.get("target_api", "Backend API Service")
        base_url = api_data.get("base_url", "https://api.example.com")
        spec_format = api_data.get("specification_format", "REST Service")
        score = api_data.get("quality_score", 100.0)
        status = api_data.get("overall_status", "PRODUCTION READY")
        total_endpoints = api_data.get("total_endpoints", 0)
        total_tests = api_data.get("total_tests", 0)
        passed_tests = api_data.get("passed_tests", 0)
        failed_tests = api_data.get("failed_tests", 0)
        warning_tests = api_data.get("warning_tests", 0)
        rl_active = api_data.get("rate_limiting_active", False)
        exec_time = api_data.get("duration_seconds", 0.0)
        timestamp = api_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        status_color = "#00ff9d" if "PROD" in status else "#ffb800" if "ATTENTION" in status else "#ff3366"

        endpoint_rows = []
        for e in api_data.get("endpoints", []):
            m_col = "#00d4ff" if e.get("method") == "GET" else "#00ff9d" if e.get("method") == "POST" else "#ffb800" if e.get("method") == "PUT" else "#ff3366"
            auth_badge = '<span class="badge" style="background:#24192b; color:#d946ef; border:1px solid #701a75;">Required</span>' if e.get("auth_required") else '<span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Public</span>'
            endpoint_rows.append(f"""
            <tr>
                <td><span class="badge" style="background:{m_col}; color:#0b0f19; font-weight:800;">{html.escape(e.get('method', ''))}</span></td>
                <td><code>{html.escape(e.get('path', ''))}</code></td>
                <td>{auth_badge}</td>
                <td style="color:#a855f7; font-weight:600;">{html.escape(e.get('category', ''))}</td>
                <td>{html.escape(e.get('summary', ''))}</td>
            </tr>
            """)
        endpoints_table_html = "\n".join(endpoint_rows)

        test_rows = []
        defect_cards = []
        for tc in api_data.get("test_cases", []):
            tc_st = tc.get("status", "PASSED")
            tc_col = "#00ff9d" if tc_st == "PASSED" else "#ff3366" if tc_st == "FAILED" else "#ffb800"
            test_rows.append(f"""
            <tr>
                <td><code>{html.escape(tc.get('test_id', ''))}</code></td>
                <td><span class="badge" style="background:{tc_col}; color:#0b0f19; font-weight:800; font-size:10px; padding:3px 8px; border-radius:4px;">{html.escape(tc_st)}</span></td>
                <td style="color:#00d4ff; font-weight:700;">{html.escape(tc.get('method', ''))}</td>
                <td><code>{html.escape(tc.get('endpoint', ''))}</code></td>
                <td style="color:#a855f7; font-weight:600;">{html.escape(tc.get('category', ''))}</td>
                <td style="color:#cbd5e1;">{tc.get('latency_ms', 0)}ms</td>
                <td><strong>{html.escape(tc.get('test_name', ''))}</strong><div style="font-size:11.5px; color:#8b9bb4;">{html.escape(tc.get('details', ''))}</div></td>
            </tr>
            """)

            if tc_st in ("FAILED", "WARNING"):
                curl_block = f'<div style="margin-top:8px;"><strong style="font-size:12px; color:#cbd5e1;">Reproduction cURL:</strong><pre style="background:#0b0e14; padding:8px; border-radius:6px; color:#a5f3fc; font-size:11.5px;"><code>{html.escape(tc.get("reproduction_curl", ""))}</code></pre></div>' if tc.get("reproduction_curl") else ""
                patch_block = f'<div style="margin-top:8px;"><strong style="font-size:12px; color:#00ff9d;">Developer Fix:</strong><pre style="background:#0b0e14; padding:8px; border-radius:6px; color:#38bdf8; font-size:11.5px;"><code>{html.escape(tc.get("developer_patch", ""))}</code></pre></div>' if tc.get("developer_patch") else ""
                defect_cards.append(f"""
                <div class="card" style="border-left: 4px solid {tc_col}; margin-bottom: 16px; background:#121826; border-radius:8px; padding:16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h3 style="margin:0; font-size:15px; color:#ffffff;">{html.escape(tc.get('test_name', ''))} ({html.escape(tc.get('test_id', ''))})</h3>
                        <span class="badge" style="background:{tc_col}; color:#0b0f19; font-weight:800; font-size:10.5px; padding:3px 8px; border-radius:4px;">{html.escape(tc_st)}</span>
                    </div>
                    <p style="color:#cbd5e1; font-size:13px; margin:8px 0 4px 0;"><strong>Endpoint:</strong> <code>{html.escape(tc.get('method', ''))} {html.escape(tc.get('endpoint', ''))}</code> | <strong>Category:</strong> {html.escape(tc.get('category', ''))}</p>
                    <p style="color:#94a3b8; font-size:12.5px; margin:4px 0;"><strong>Observed:</strong> {html.escape(tc.get('actual_status', tc.get('details', '')))}</p>
                    {curl_block}
                    {patch_block}
                </div>
                """)

        test_table_html = "\n".join(test_rows)
        defects_html = "\n".join(defect_cards) if defect_cards else """
        <div style="background:#0d1814; border:1px solid #143828; border-radius:8px; padding:16px; color:#00ff9d; font-size:13.5px;">
            ✔ <strong>Zero Blocking API Defects Detected:</strong> Endpoints comply with all schema contracts, authentication gates, and boundary criteria.
        </div>
        """

        py_script = api_data.get("ready_to_run_python_script", "")
        postman_json = api_data.get("postman_collection_json", "")
        copiable_md = api_data.get("copiable_client_markdown", "")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REST & API Quality Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f1420;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19; font-size:11px; font-weight:800;">REST & BACKEND API AUDIT</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Base URL: <strong>{html.escape(base_url)}</strong> &bull;
                    Specification: <strong style="color:var(--accent);">{html.escape(spec_format)}</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted);">API Quality Score</div>
                <div style="font-size:38px; font-weight:900; color:{status_color};">{score:.1f}%</div>
                <div style="font-size:12px; font-weight:700; color:{status_color};">{html.escape(status)}</div>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Total Endpoints</div>
                <div class="kpi-val" style="color:#ffffff;">{total_endpoints}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Tests Dispatched</div>
                <div class="kpi-val" style="color:var(--accent);">{total_tests}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Passed Tests</div>
                <div class="kpi-val" style="color:var(--green);">{passed_tests}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Contract Defects</div>
                <div class="kpi-val" style="color:var(--primary);">{failed_tests}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Rate Limiting</div>
                <div class="kpi-val" style="color:{'var(--green)' if rl_active else 'var(--amber)'}; font-size:20px; margin-top:8px;">{'Enforced' if rl_active else 'Unthrottled'}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Execution Duration</div>
                <div class="kpi-val" style="color:#a855f7;">{exec_time}s</div>
            </div>
        </div>

        <div class="section">
            <h2>1. API Endpoint Inventory & Route Map</h2>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Method</th>
                            <th>Endpoint Path</th>
                            <th>Access Control</th>
                            <th>Category</th>
                            <th>Operation Summary</th>
                        </tr>
                    </thead>
                    <tbody>
                        {endpoints_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>2. Automated Contract Verification & Boundary Fuzzing Matrix</h2>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Test ID</th>
                            <th>Status</th>
                            <th>Method</th>
                            <th>Endpoint</th>
                            <th>Category</th>
                            <th>Latency</th>
                            <th>Verification Objective</th>
                        </tr>
                    </thead>
                    <tbody>
                        {test_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>3. Flagged Defects & Remediation Guidance</h2>
            {defects_html}
        </div>

        <div class="section">
            <h2>4. Ready-to-Run Python Test Script (Pytest / Requests)</h2>
            <pre><code>{html.escape(py_script)}</code></pre>
        </div>

        {f'''<div class="section">
            <h2>5. Exportable Postman Collection v2.1.0 JSON</h2>
            <pre><code>{html.escape(postman_json)}</code></pre>
        </div>''' if postman_json else ''}

        <div class="section">
            <h2>6. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise REST API Verification & Quality Engineering Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_performance_report(cls, perf_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for Performance, Stress,
        and Concurrency Load Testing with JMeter and k6 artifacts.
        """
        if hasattr(perf_data, "to_dict"):
            perf_data = perf_data.to_dict()

        target_name = perf_data.get("target_name", "Evaluated Target")
        target_url = perf_data.get("target_url", "https://example.com")
        profile = perf_data.get("load_profile", "Standard Load")
        vus = perf_data.get("virtual_users", 50)
        duration = perf_data.get("duration_seconds", 30.0)
        total_reqs = perf_data.get("total_requests", 0)
        success_reqs = perf_data.get("successful_requests", 0)
        failed_reqs = perf_data.get("failed_requests", 0)
        error_rate = perf_data.get("error_rate_pct", 0.0)
        rps = perf_data.get("throughput_rps", 0.0)
        bytes_kb = perf_data.get("bytes_transferred_kb", 0.0)
        sla_st = perf_data.get("sla_status", "COMPLIANT")
        grade = perf_data.get("performance_grade", "A")
        bottleneck = perf_data.get("bottleneck_diagnosis", "No critical bottleneck observed.")
        timestamp = perf_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        pct = perf_data.get("percentiles", {})
        k6_script = perf_data.get("k6_script_content", "")
        jmeter_jmx = perf_data.get("jmeter_jmx_content", "")
        copiable_md = perf_data.get("copiable_client_markdown", "")

        sla_col = "#00ff9d" if "COMPLIANT" in sla_st else "#ffb800" if "DEGRADED" in sla_st else "#ff3366"
        grade_col = "#00ff9d" if grade in ("A", "B") else "#ffb800" if grade == "C" else "#ff3366"

        codes_rows = []
        for code, count in perf_data.get("status_codes_distribution", {}).items():
            pct_val = (count / max(1, total_reqs)) * 100.0
            col = "#00ff9d" if "200" in code else "#ffb800" if "429" in code else "#ff3366"
            codes_rows.append(f"""
            <tr>
                <td><span class="badge" style="background:{col}; color:#0b0f19; font-weight:800;">{html.escape(code)}</span></td>
                <td style="font-weight:700; color:#cbd5e1;">{count}</td>
                <td style="color:#a855f7;">{pct_val:.1f}%</td>
            </tr>
            """)
        codes_table_html = "\n".join(codes_rows)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance & Concurrency Load Audit - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f1420;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19; font-size:11px; font-weight:800;">PERFORMANCE & CONCURRENCY AUDIT</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Endpoint: <strong>{html.escape(target_url)}</strong> &bull;
                    Profile: <strong style="color:var(--accent);">{html.escape(profile)}</strong> &bull;
                    Workers: <strong>{vus} VUs</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted);">Capacity SLA Status</div>
                <div style="font-size:38px; font-weight:900; color:{grade_col};">Grade {html.escape(grade)}</div>
                <div style="font-size:12px; font-weight:700; color:{sla_col};">{html.escape(sla_st)}</div>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Throughput (RPS)</div>
                <div class="kpi-val" style="color:#00ff9d;">{rps:.1f}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">p95 Latency</div>
                <div class="kpi-val" style="color:var(--accent);">{pct.get('p95_ms', 0):.1f}ms</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Mean Latency</div>
                <div class="kpi-val" style="color:#cbd5e1;">{pct.get('avg_ms', 0):.1f}ms</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Error Rate</div>
                <div class="kpi-val" style="color:{'var(--green)' if error_rate <= 1.0 else 'var(--primary)'};">{error_rate:.2f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Total Requests</div>
                <div class="kpi-val" style="color:#f0f4fc;">{total_reqs}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Concurrency Load</div>
                <div class="kpi-val" style="color:#a855f7;">{vus} VUs</div>
            </div>
        </div>

        <div class="section">
            <h2>1. Latency Percentile Profiling (Response Times Under Load)</h2>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Percentile Level</th>
                            <th>Measured Latency</th>
                            <th>Industry Benchmark SLA</th>
                            <th>Evaluation</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Minimum (Fastest)</strong></td>
                            <td style="color:#00ff9d; font-weight:700;">{pct.get('min_ms', 0):.1f} ms</td>
                            <td>Baseline socket connect time</td>
                            <td><span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Optimal</span></td>
                        </tr>
                        <tr>
                            <td><strong>Average (Mean)</strong></td>
                            <td style="color:#38bdf8; font-weight:700;">{pct.get('avg_ms', 0):.1f} ms</td>
                            <td>Working transaction average</td>
                            <td><span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Conformant</span></td>
                        </tr>
                        <tr>
                            <td><strong>50th Percentile (p50 Median)</strong></td>
                            <td style="color:#38bdf8; font-weight:700;">{pct.get('median_p50_ms', 0):.1f} ms</td>
                            <td>Median user experience</td>
                            <td><span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Conformant</span></td>
                        </tr>
                        <tr>
                            <td><strong>90th Percentile (p90)</strong></td>
                            <td style="color:#facc15; font-weight:700;">{pct.get('p90_ms', 0):.1f} ms</td>
                            <td>Upper load boundary</td>
                            <td><span class="badge" style="background:#241d13; color:#facc15; border:1px solid #713f12;">Stable</span></td>
                        </tr>
                        <tr>
                            <td><strong>95th Percentile (p95 SLA Gate)</strong></td>
                            <td style="color:#f97316; font-weight:700;">{pct.get('p95_ms', 0):.1f} ms</td>
                            <td>Primary Enterprise SLA Gate (&lt; 500ms)</td>
                            <td><span class="badge" style="background:{'#0d1e17' if pct.get('p95_ms', 0) <= 500 else '#2a1318'}; color:{'#00ff9d' if pct.get('p95_ms', 0) <= 500 else '#ff3366'}; border:1px solid {'#064e3b' if pct.get('p95_ms', 0) <= 500 else '#881337'};">{'PASS' if pct.get('p95_ms', 0) <= 500 else 'SLA BREACH'}</span></td>
                        </tr>
                        <tr>
                            <td><strong>99th Percentile (p99 Tail)</strong></td>
                            <td style="color:#ff3366; font-weight:700;">{pct.get('p99_ms', 0):.1f} ms</td>
                            <td>Worst 1% tail latency (&lt; 1200ms)</td>
                            <td><span class="badge" style="background:{'#0d1e17' if pct.get('p99_ms', 0) <= 1200 else '#2a1318'}; color:{'#00ff9d' if pct.get('p99_ms', 0) <= 1200 else '#ff3366'}; border:1px solid {'#064e3b' if pct.get('p99_ms', 0) <= 1200 else '#881337'};">{'PASS' if pct.get('p99_ms', 0) <= 1200 else 'TAIL DELAY'}</span></td>
                        </tr>
                        <tr>
                            <td><strong>Maximum Peak</strong></td>
                            <td style="color:#ff3366; font-weight:700;">{pct.get('max_ms', 0):.1f} ms</td>
                            <td>Worst single transaction recorded</td>
                            <td><span class="badge" style="background:#24192b; color:#d946ef; border:1px solid #701a75;">Outlier</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>2. HTTP Status Code Distribution</h2>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>HTTP Response Code</th>
                            <th>Total Responses</th>
                            <th>Share (%)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {codes_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>3. Capacity Bottleneck Diagnosis & Architectural Remediation</h2>
            <div style="background:#151b2a; border-left:4px solid var(--accent); padding:16px; border-radius:6px; margin-bottom:15px;">
                <strong style="color:var(--accent);">Observed Bottleneck:</strong>
                <p style="margin:6px 0 0 0; color:#e2e8f0;">{html.escape(bottleneck)}</p>
            </div>
            <div style="font-size:13px; color:#cbd5e1; line-height:1.7;">
                <strong>Recommended Performance Optimization Steps:</strong>
                <ol style="margin-top:6px; padding-left:20px;">
                    <li><strong>Reverse Proxy Connection Pooling:</strong> Tune upstream keepalive parameters in Nginx / HAProxy (`keepalive 64;` in upstream blocks) to reuse established TCP handshakes.</li>
                    <li><strong>Content Compression:</strong> Ensure Brotli or Gzip is enabled for JSON and HTML payloads exceeding 1KB to reduce data transfer overhead.</li>
                    <li><strong>Database Query Optimization:</strong> Review queries exceeding 50ms under concurrency, add missing B-Tree composite indices, and verify pool max connections >= VU ceiling.</li>
                </ol>
            </div>
        </div>

        <div class="section">
            <h2>4. Grafana k6 Production Load Test Script</h2>
            <pre><code>{html.escape(k6_script)}</code></pre>
        </div>

        <div class="section">
            <h2>5. Apache JMeter 5.x Test Plan XML (.jmx)</h2>
            <pre><code>{html.escape(jmeter_jmx)}</code></pre>
        </div>

        <div class="section">
            <h2>6. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise Performance & Reliability Engineering Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_cicd_report(cls, cicd_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for CI/CD Pipeline Automation,
        Quality Gate Enforcement, and DevOps Test Artifacts.
        """
        if hasattr(cicd_data, "to_dict"):
            cicd_data = cicd_data.to_dict()

        target_name = cicd_data.get("target_name", "Evaluated Target")
        target_path = cicd_data.get("target_path", "https://example.com")
        target_type = cicd_data.get("target_type", "web").upper()
        timestamp = cicd_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        rule = cicd_data.get("gate_rule", {})
        gate = cicd_data.get("gate_result", {})
        passed = gate.get("passed", True)
        status = gate.get("status", "GATE PASSED")
        score = gate.get("overall_score", 100.0)
        violations_cnt = gate.get("total_violations", 0)

        gh_actions = cicd_data.get("github_actions_yaml", "")
        gitlab_ci = cicd_data.get("gitlab_ci_yaml", "")
        jenkinsfile = cicd_data.get("jenkinsfile_content", "")
        junit_xml = cicd_data.get("junit_xml_content", "")
        copiable_md = cicd_data.get("copiable_client_markdown", "")

        status_col = "#00ff9d" if passed else "#ff3366"
        status_bg = "#0d1e17" if passed else "#2a1318"
        status_border = "#064e3b" if passed else "#881337"

        violations_html = []
        for v in gate.get("violation_details", []):
            icon = "✔" if passed else "✖"
            col = "#00ff9d" if passed else "#ff3366"
            violations_html.append(f"""
            <div style="background:#151b2a; border-left:4px solid {col}; padding:10px 14px; border-radius:6px; margin-bottom:8px; font-size:13px; color:#f1f5f9;">
                <strong style="color:{col}; margin-right:8px;">{icon}</strong> {html.escape(v)}
            </div>
            """)
        viols_rendered = "\n".join(violations_html)

        remed_html = []
        for r in gate.get("remediation_advice", []):
            remed_html.append(f"""
            <li style="margin-bottom:6px; color:#cbd5e1;"><strong>ACTION:</strong> {html.escape(r)}</li>
            """)
        remed_rendered = f"<ol style='padding-left:20px; font-size:13px;'>{''.join(remed_html)}</ol>" if remed_html else "<p style='color:#00ff9d; font-size:13px;'>No remediation actions required. Build clean.</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CI/CD Quality Gate & DevOps Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 0.5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19;">CI/CD DEVOPS QUALITY GATE</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Target: <strong>{html.escape(target_path)}</strong> &bull;
                    Platform: <strong style="color:var(--accent);">{target_type}</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Automated Gate Verdict</div>
                <span class="badge" style="background:{status_bg}; color:{status_col}; border:1px solid {status_border}; font-size:15px; padding:6px 16px;">{html.escape(status)}</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Quality Gate Status</div>
                <div class="kpi-val" style="color:{status_col};">{html.escape(status)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Overall Health Score</div>
                <div class="kpi-val" style="color:var(--accent);">{score:.1f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Gate Policy Violations</div>
                <div class="kpi-val" style="color:{'var(--green)' if violations_cnt == 0 else 'var(--primary)'};">{violations_cnt}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Max Critical Allowed</div>
                <div class="kpi-val" style="color:#ffffff;">{rule.get('max_critical_findings', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Max High Allowed</div>
                <div class="kpi-val" style="color:#ffffff;">{rule.get('max_high_findings', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">p95 Latency SLA Limit</div>
                <div class="kpi-val" style="color:#a855f7;">{rule.get('max_p95_latency_ms', 600)}ms</div>
            </div>
        </div>

        <div class="section">
            <h2>1. Policy Compliance & Criteria Evaluation</h2>
            {viols_rendered}
        </div>

        <div class="section">
            <h2>2. Gate Remediation & Blocking Defect Actions</h2>
            {remed_rendered}
        </div>

        <div class="section">
            <h2>3. GitHub Actions Workflow (.github/workflows/quality_gate.yml)</h2>
            <pre><code>{html.escape(gh_actions)}</code></pre>
        </div>

        <div class="section">
            <h2>4. GitLab CI/CD Pipeline (.gitlab-ci.yml)</h2>
            <pre><code>{html.escape(gitlab_ci)}</code></pre>
        </div>

        <div class="section">
            <h2>5. Jenkins Declarative Pipeline (Jenkinsfile)</h2>
            <pre><code>{html.escape(jenkinsfile)}</code></pre>
        </div>

        <div class="section">
            <h2>6. Universal JUnit XML Test Deliverable (junit_results.xml)</h2>
            <pre><code>{html.escape(junit_xml)}</code></pre>
        </div>

        <div class="section">
            <h2>7. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise DevOps Quality Gate & Continuous Testing Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_database_report(cls, db_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for Database Schema Validation,
        Referential Integrity, Index Optimization, and SQL Defense.
        """
        if hasattr(db_data, "to_dict"):
            db_data = db_data.to_dict()

        target_name = db_data.get("target_name", "Evaluated Target")
        db_engine = db_data.get("database_engine", "Enterprise RDBMS")
        score = db_data.get("data_integrity_score", 100.0)
        status = db_data.get("overall_status", "PRODUCTION CERTIFIED")
        total_tables = db_data.get("total_tables_checked", 0)
        total_checks = db_data.get("total_checks", 0)
        passed_checks = db_data.get("passed_checks", 0)
        defects_cnt = db_data.get("defects_count", 0)
        warnings_cnt = db_data.get("warnings_count", 0)
        sql_patch = db_data.get("ready_to_run_sql_migration", "")
        copiable_md = db_data.get("copiable_client_markdown", "")
        timestamp = db_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        status_col = "#00ff9d" if "CERTIFIED" in status else "#ffb800" if "ATTENTION" in status else "#ff3366"
        status_bg = "#0d1e17" if "CERTIFIED" in status else "#241d13" if "ATTENTION" in status else "#2a1318"
        status_border = "#064e3b" if "CERTIFIED" in status else "#713f12" if "ATTENTION" in status else "#881337"

        # Tables rows
        table_rows = []
        for t in db_data.get("tables", []):
            unidx = ", ".join(t.get("unindexed_foreign_keys", [])) if t.get("unindexed_foreign_keys") else "None (Indexed)"
            unidx_badge = f'<span class="badge" style="background:#241d13; color:#ffb800; border:1px solid #713f12;">{html.escape(unidx)}</span>' if t.get("unindexed_foreign_keys") else '<span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Clean</span>'
            table_rows.append(f"""
            <tr>
                <td style="font-weight:700; color:#38bdf8;"><code>{html.escape(t.get('table_name', ''))}</code></td>
                <td>{t.get('column_count', 0)}</td>
                <td>{t.get('estimated_row_count', 0):,}</td>
                <td><code>{html.escape(t.get('primary_key', ''))}</code></td>
                <td>{unidx_badge}</td>
            </tr>
            """)
        tables_table_html = "\n".join(table_rows)

        # Defect cards
        defect_cards = []
        for d in db_data.get("defects", []):
            st = d.get("status", "PASSED")
            sev = d.get("severity", "INFO")
            st_col = "#00ff9d" if st == "PASSED" else "#ff3366" if st == "DEFECT" else "#ffb800"
            patch_section = f'<pre style="margin-top:8px; font-size:11.5px;"><code>{html.escape(d.get("remediation_sql", "").strip())}</code></pre>' if d.get("remediation_sql") and st in ("DEFECT", "WARNING") else ""
            defect_cards.append(f"""
            <div style="background:#151b2a; border-left:4px solid {st_col}; border-radius:8px; padding:16px; margin-bottom:14px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <div style="font-size:14px; font-weight:800; color:#ffffff;">{html.escape(d.get('title', ''))}</div>
                    <div>
                        <span class="badge" style="background:{st_col}; color:#0b0f19;">{html.escape(st)}</span>
                        <span class="badge" style="background:#1e2434; color:#cbd5e1; margin-left:4px;">{html.escape(sev)}</span>
                    </div>
                </div>
                <div style="font-size:12px; color:var(--accent); margin-bottom:6px;">Entity: <code>{html.escape(d.get('target_entity', ''))}</code> &bull; Category: {html.escape(d.get('category', ''))}</div>
                <div style="font-size:13px; color:#cbd5e1; margin-bottom:6px;">{html.escape(d.get('description', ''))}</div>
                <div style="font-size:12px; color:#ffb800;"><strong>Impact:</strong> {html.escape(d.get('impact', ''))}</div>
                {patch_section}
            </div>
            """)
        defects_html = "\n".join(defect_cards)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Database Integrity & Schema Validation Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f1420;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19;">DATABASE & DATA LAYER INTEGRITY</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Engine: <strong style="color:var(--accent);">{html.escape(db_engine)}</strong> &bull;
                    Tables Checked: <strong>{total_tables} Entities</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Integrity Certification</div>
                <span class="badge" style="background:{status_bg}; color:{status_col}; border:1px solid {status_border}; font-size:15px; padding:6px 16px;">{html.escape(status)}</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Integrity Score</div>
                <div class="kpi-val" style="color:{status_col};">{score:.1f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Tables Inspected</div>
                <div class="kpi-val" style="color:var(--accent);">{total_tables}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Total Checks</div>
                <div class="kpi-val" style="color:#ffffff;">{total_checks}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Passed Checks</div>
                <div class="kpi-val" style="color:var(--green);">{passed_checks}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Schema Defects</div>
                <div class="kpi-val" style="color:{'var(--green)' if defects_cnt == 0 else 'var(--primary)'};">{defects_cnt}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Integrity Warnings</div>
                <div class="kpi-val" style="color:{'var(--green)' if warnings_cnt == 0 else 'var(--amber)'};">{warnings_cnt}</div>
            </div>
        </div>

        <div class="section">
            <h2>1. Table Schema & Referential Constraint Directory</h2>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Table Name</th>
                            <th>Columns</th>
                            <th>Est. Records</th>
                            <th>Primary Key</th>
                            <th>Unindexed Foreign Keys (Table-Lock Traps)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tables_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>2. Database Quality Defects & Remediation Patches</h2>
            {defects_html}
        </div>

        <div class="section">
            <h2>3. Idempotent DDL Remediation SQL Migration Script</h2>
            <pre><code>{html.escape(sql_patch)}</code></pre>
        </div>

        <div class="section">
            <h2>4. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise Database Reliability & Data Layer Quality Engineering Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_compatibility_report(cls, compat_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for Cross-Platform Compatibility,
        Multi-Device Viewport Matrix Simulation, and WCAG Accessibility Testing.
        """
        if hasattr(compat_data, "to_dict"):
            compat_data = compat_data.to_dict()

        target_name = compat_data.get("target_name", "Evaluated Target")
        target_type = compat_data.get("target_type", "web").upper()
        score = compat_data.get("compatibility_score", 100.0)
        status = compat_data.get("overall_status", "WCAG AA CERTIFIED")
        total_viewports = compat_data.get("total_viewports_tested", 0)
        total_checks = compat_data.get("total_checks", 0)
        passed_checks = compat_data.get("passed_checks", 0)
        defects_cnt = compat_data.get("defects_count", 0)
        warnings_cnt = compat_data.get("warnings_count", 0)
        playwright_script = compat_data.get("playwright_matrix_script", "")
        cypress_script = compat_data.get("cypress_matrix_script", "")
        copiable_md = compat_data.get("copiable_client_markdown", "")
        timestamp = compat_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        status_col = "#00ff9d" if "CERTIFIED" in status else "#ffb800" if "ATTENTION" in status or "WARNINGS" in status else "#ff3366"
        status_bg = "#0d1e17" if "CERTIFIED" in status else "#241d13" if "ATTENTION" in status or "WARNINGS" in status else "#2a1318"
        status_border = "#064e3b" if "CERTIFIED" in status else "#713f12" if "ATTENTION" in status or "WARNINGS" in status else "#881337"

        # Devices table rows
        device_rows = []
        for dev in compat_data.get("devices", []):
            dims = f"{dev.get('viewport_width', 0)} x {dev.get('viewport_height', 0)}"
            overflow = dev.get("horizontal_overflow", False)
            over_badge = '<span class="badge" style="background:#2a1318; color:#ff3366; border:1px solid #881337;">OVERFLOW (DEFECT)</span>' if overflow else '<span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Clean (No Scroll)</span>'
            dev_status = dev.get("status", "PASSED")
            dev_stat_col = "#00ff9d" if dev_status == "PASSED" else "#ffb800" if dev_status == "WARNING" else "#ff3366"
            device_rows.append(f"""
            <tr>
                <td style="font-weight:700; color:#38bdf8;">{html.escape(dev.get('name', ''))}</td>
                <td style="color:var(--text-muted);">{html.escape(dev.get('category', ''))}</td>
                <td><code>{dims}</code></td>
                <td>{dev.get('device_scale_factor', 1.0)}x</td>
                <td><span style="font-weight:700; color:{dev_stat_col};">[{dev_status}]</span></td>
                <td>{over_badge}</td>
                <td><strong style="color:{'var(--green)' if dev.get('touch_hazard_count', 0) == 0 else 'var(--primary)'};">{dev.get('touch_hazard_count', 0)}</strong></td>
                <td style="font-size:12.5px; color:#cbd5e1;">{html.escape(dev.get('render_notes', ''))}</td>
            </tr>
            """)
        devices_table_html = "\n".join(device_rows)

        # Defect cards
        defect_cards = []
        for df in compat_data.get("defects", []):
            sev = df.get("severity", "MEDIUM")
            df_status = df.get("status", "PASSED")
            sev_col = "#ff3366" if sev == "CRITICAL" else "#ff5252" if sev == "HIGH" else "#ffb800" if sev == "MEDIUM" else "#00d4ff" if sev == "LOW" else "#38bdf8"
            stat_col = "#00ff9d" if df_status == "PASSED" else "#ffb800" if df_status == "WARNING" else "#ff3366"
            remed_html = ""
            if df.get("remediation_code"):
                remed_html = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px; font-weight:700;">Remediation Code & Fix</div>
                    <pre style="margin:0; background:#080b12; padding:10px; border-radius:6px; border:1px solid #1e2638;"><code style="color:#00ff9d;">{html.escape(df.get('remediation_code', ''))}</code></pre>
                </div>
                """
            defect_cards.append(f"""
            <div class="card" style="border-left: 4px solid {sev_col}; margin-bottom:14px; padding:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                    <span style="font-weight:700; font-size:15px; color:#ffffff;">{html.escape(df.get('title', ''))}</span>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span class="badge" style="background:#171f32; color:{stat_col}; border:1px solid {stat_col};">[{df_status}]</span>
                        <span class="badge" style="background:#171f32; color:{sev_col}; border:1px solid {sev_col};">{sev}</span>
                        <code style="color:var(--text-muted); font-size:11px;">{html.escape(df.get('defect_id', ''))}</code>
                    </div>
                </div>
                <div style="font-size:12px; color:var(--accent); margin: 6px 0;">
                    Category: <strong>{html.escape(df.get('category', ''))}</strong> &bull;
                    Viewports: <strong style="color:#cbd5e1;">{html.escape(df.get('affected_viewport', ''))}</strong> &bull;
                    Criterion: <strong style="color:#a78bfa;">{html.escape(df.get('wcag_criterion', ''))}</strong>
                </div>
                <div style="font-size:13px; color:#cbd5e1; margin-top:6px;">{html.escape(df.get('description', ''))}</div>
                <div style="font-size:12.5px; color:#fca5a5; margin-top:6px;"><strong>Impact:</strong> {html.escape(df.get('impact', ''))}</div>
                {remed_html}
            </div>
            """)
        defects_html = "\n".join(defect_cards)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Responsive Viewport & WCAG Accessibility Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: #0d121c;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 700;
        }}
        .card {{
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}
        .btn {{
            background: linear-gradient(135deg, #00d4ff 0%, #0077b6 100%);
            color: #0b0f19;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19;">RESPONSIVE VIEWPORT & WCAG ACCESSIBILITY</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Platform: <strong style="color:var(--accent);">{html.escape(target_type)}</strong> &bull;
                    Viewports Audited: <strong>{total_viewports} Form Factors</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Responsive Certification</div>
                <span class="badge" style="background:{status_bg}; color:{status_col}; border:1px solid {status_border}; font-size:15px; padding:6px 16px;">{html.escape(status)}</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Compatibility Score</div>
                <div class="kpi-val" style="color:{status_col};">{score:.1f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Viewports Audited</div>
                <div class="kpi-val" style="color:var(--accent);">{total_viewports}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Total Checks</div>
                <div class="kpi-val" style="color:#ffffff;">{total_checks}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Passed Checks</div>
                <div class="kpi-val" style="color:var(--green);">{passed_checks}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Layout & A11y Defects</div>
                <div class="kpi-val" style="color:{'var(--green)' if defects_cnt == 0 else 'var(--primary)'};">{defects_cnt}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Advisory Warnings</div>
                <div class="kpi-val" style="color:{'var(--green)' if warnings_cnt == 0 else 'var(--amber)'};">{warnings_cnt}</div>
            </div>
        </div>

        <div class="section">
            <h2>1. Multi-Device Viewport Simulation Matrix</h2>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Device Name</th>
                            <th>Category</th>
                            <th>Dimensions</th>
                            <th>DPR Scale</th>
                            <th>Status</th>
                            <th>Horizontal Overflow</th>
                            <th>Touch Hazards</th>
                            <th>Render Notes</th>
                        </tr>
                    </thead>
                    <tbody>
                        {devices_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>2. Viewport & Accessibility Defect Matrix</h2>
            {defects_html}
        </div>

        <div class="section">
            <h2>3. Playwright Multi-Device Matrix Test Script (matrix_viewport_test.py)</h2>
            <pre><code>{html.escape(playwright_script)}</code></pre>
        </div>

        <div class="section">
            <h2>4. Cypress Multi-Device Viewport Test Script (viewport-test.spec.js)</h2>
            <pre><code>{html.escape(cypress_script)}</code></pre>
        </div>

        <div class="section">
            <h2>5. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre id="copiable-md" style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise Cross-Platform Compatibility & WCAG Accessibility Testing Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_network_report(cls, net_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for Network Protocol,
        TLS Cryptographic Cipher Suites, X.509 Certificates, and DNS Security.
        """
        if hasattr(net_data, "to_dict"):
            net_data = net_data.to_dict()

        target_name = net_data.get("target_name", "Evaluated Target")
        target_host = net_data.get("target_host", "localhost")
        port = net_data.get("port", 443)
        tls_grade = net_data.get("tls_grade", "A")
        crypto_score = net_data.get("crypto_score", 100.0)
        overall_status = net_data.get("overall_status", "ENTERPRISE HARDENED")
        total_checks = net_data.get("total_checks", 0)
        passed_checks = net_data.get("passed_checks", 0)
        defects_cnt = net_data.get("defects_count", 0)
        warnings_cnt = net_data.get("warnings_count", 0)
        openssl_script = net_data.get("openssl_diagnostic_script", "")
        copiable_md = net_data.get("copiable_client_markdown", "")
        timestamp = net_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        cipher_info = net_data.get("cipher_info") or {}
        cert_info = net_data.get("cert_info") or {}
        dns_mail = net_data.get("dns_mail_info") or {}

        status_col = "#00ff9d" if "HARDENED" in overall_status else "#ffb800" if "ATTENTION" in overall_status else "#ff3366"
        status_bg = "#0d1e17" if "HARDENED" in overall_status else "#241d13" if "ATTENTION" in overall_status else "#2a1318"
        status_border = "#064e3b" if "HARDENED" in overall_status else "#713f12" if "ATTENTION" in overall_status else "#881337"

        # Defect cards
        defect_cards = []
        for df in net_data.get("defects", []):
            sev = df.get("severity", "MEDIUM")
            df_status = df.get("status", "PASSED")
            sev_col = "#ff3366" if sev == "CRITICAL" else "#ff5252" if sev == "HIGH" else "#ffb800" if sev == "MEDIUM" else "#00d4ff" if sev == "LOW" else "#38bdf8"
            stat_col = "#00ff9d" if df_status == "PASSED" else "#ffb800" if df_status == "WARNING" else "#ff3366"
            remed_html = ""
            if df.get("remediation_config"):
                remed_html = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px; font-weight:700;">Remediation & Server Configuration</div>
                    <pre style="margin:0; background:#080b12; padding:10px; border-radius:6px; border:1px solid #1e2638;"><code style="color:#00ff9d;">{html.escape(df.get('remediation_config', ''))}</code></pre>
                </div>
                """
            defect_cards.append(f"""
            <div class="card" style="border-left: 4px solid {sev_col}; margin-bottom:14px; padding:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                    <span style="font-weight:700; font-size:15px; color:#ffffff;">{html.escape(df.get('title', ''))}</span>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span class="badge" style="background:#171f32; color:{stat_col}; border:1px solid {stat_col};">[{df_status}]</span>
                        <span class="badge" style="background:#171f32; color:{sev_col}; border:1px solid {sev_col};">{sev}</span>
                        <code style="color:var(--text-muted); font-size:11px;">{html.escape(df.get('defect_id', ''))}</code>
                    </div>
                </div>
                <div style="font-size:12px; color:var(--accent); margin: 6px 0;">
                    Category: <strong>{html.escape(df.get('category', ''))}</strong> &bull;
                    Component: <strong style="color:#cbd5e1;">{html.escape(df.get('target_component', ''))}</strong>
                </div>
                <div style="font-size:13px; color:#cbd5e1; margin-top:6px;">{html.escape(df.get('description', ''))}</div>
                <div style="font-size:12.5px; color:#fca5a5; margin-top:6px;"><strong>Impact:</strong> {html.escape(df.get('impact', ''))}</div>
                {remed_html}
            </div>
            """)
        defects_html = "\n".join(defect_cards)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Protocol & Cryptographic TLS Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: #0d121c;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 700;
        }}
        .card {{
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}
        .btn {{
            background: linear-gradient(135deg, #00d4ff 0%, #0077b6 100%);
            color: #0b0f19;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19;">NETWORK PROTOCOL & TLS CRYPTOGRAPHY</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Endpoint: <strong style="color:var(--accent);">{html.escape(target_host)}:{port}</strong> &bull;
                    Protocol: <strong>{html.escape(cipher_info.get('protocol_version', 'TLSv1.3'))}</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Cryptographic Grade</div>
                <span class="badge" style="background:{status_bg}; color:{status_col}; border:1px solid {status_border}; font-size:20px; font-weight:800; padding:6px 20px;">GRADE {html.escape(tls_grade)}</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Crypto Score</div>
                <div class="kpi-val" style="color:{status_col};">{crypto_score:.1f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">TLS Grade</div>
                <div class="kpi-val" style="color:var(--accent);">{tls_grade}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Cert Expiration</div>
                <div class="kpi-val" style="color:{'var(--green)' if cert_info.get('days_to_expiration', 0) > 30 else 'var(--primary)'};">{cert_info.get('days_to_expiration', 0)}d Left</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Total Checks</div>
                <div class="kpi-val" style="color:#ffffff;">{total_checks}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Crypto Defects</div>
                <div class="kpi-val" style="color:{'var(--green)' if defects_cnt == 0 else 'var(--primary)'};">{defects_cnt}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Advisory Warnings</div>
                <div class="kpi-val" style="color:{'var(--green)' if warnings_cnt == 0 else 'var(--amber)'};">{warnings_cnt}</div>
            </div>
        </div>

        <div class="section">
            <h2>1. TLS Handshake & Cipher Suite Negotiation</h2>
            <div style="overflow-x:auto;">
                <table>
                    <tbody>
                        <tr>
                            <td style="font-weight:700; width:30%;">Active TLS Protocol</td>
                            <td><code>{html.escape(cipher_info.get('protocol_version', 'TLSv1.3'))}</code></td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Negotiated Cipher Suite</td>
                            <td><code>{html.escape(cipher_info.get('cipher_suite', 'TLS_AES_256_GCM_SHA384'))}</code></td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Key Exchange Mechanism</td>
                            <td>{html.escape(cipher_info.get('key_exchange', 'ECDHE (Curve X25519)'))}</td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Encryption & MAC Mode</td>
                            <td>{html.escape(cipher_info.get('encryption_algorithm', 'AES-256-GCM (AEAD)'))}</td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Perfect Forward Secrecy (PFS)</td>
                            <td><span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">{'YES (Ephemeral Exchange)' if cipher_info.get('perfect_forward_secrecy') else 'NO'}</span></td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">TLS Compression (CRIME/BREACH Defense)</td>
                            <td><span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">{'Disabled (Immune)' if cipher_info.get('tls_compression_disabled') else 'Enabled (Vulnerable)'}</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>2. X.509 Certificate Chain of Trust & Expiration</h2>
            <div style="overflow-x:auto;">
                <table>
                    <tbody>
                        <tr>
                            <td style="font-weight:700; width:30%;">Common Name (CN)</td>
                            <td><code>{html.escape(cert_info.get('common_name', ''))}</code></td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Issuer Organization</td>
                            <td>{html.escape(cert_info.get('issuer_org', ''))}</td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Validity Period</td>
                            <td>{html.escape(cert_info.get('valid_from', ''))} &rarr; <strong>{html.escape(cert_info.get('valid_until', ''))}</strong> ({cert_info.get('days_to_expiration', 0)} days remaining)</td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Public Key Algorithm & Size</td>
                            <td><code>{html.escape(cert_info.get('key_type_and_bits', 'RSA 2048-bit'))}</code> ({html.escape(cert_info.get('signature_algorithm', 'SHA256withRSA'))})</td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">OCSP Stapling Proof</td>
                            <td>{'<span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Enabled (Fast Handshake)</span>' if cert_info.get('ocsp_stapling') else '<span class="badge" style="background:#241d13; color:#ffb800; border:1px solid #713f12;">Omitted (Synchronous Latency)</span>'}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>3. DNSSEC, CAA & Anti-Spoofing Perimeter</h2>
            <div style="overflow-x:auto;">
                <table>
                    <tbody>
                        <tr>
                            <td style="font-weight:700; width:30%;">ALPN HTTP/2 Protocol Multiplexing</td>
                            <td>{'<span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">YES (h2 Negotiated)</span>' if dns_mail.get('alpn_http2_supported') else 'NO'}</td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Certification Authority Authorization (CAA)</td>
                            <td>{'<span class="badge" style="background:#0d1e17; color:#00ff9d; border:1px solid #064e3b;">Configured</span>' if dns_mail.get('caa_records_present') else '<span class="badge" style="background:#2a1318; color:#ff3366; border:1px solid #881337;">Missing (Defect)</span>'}</td>
                        </tr>
                        <tr>
                            <td style="font-weight:700;">Domain Anti-Spoofing DMARC Policy</td>
                            <td><code>{html.escape(dns_mail.get('dmarc_policy', 'MISSING'))}</code></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>4. Network & Cryptographic Defect Matrix</h2>
            {defects_html}
        </div>

        <div class="section">
            <h2>5. Automated OpenSSL Diagnostic Script (network_tls_diagnostic.sh)</h2>
            <pre><code>{html.escape(openssl_script)}</code></pre>
        </div>

        <div class="section">
            <h2>6. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre id="copiable-md" style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise Network Protocol & TLS Cryptographic Engineering Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_business_logic_report(cls, logic_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for Business Logic,
        State Machine Transitions, Price Manipulation, and Concurrency Flaws.
        """
        if hasattr(logic_data, "to_dict"):
            logic_data = logic_data.to_dict()

        target_name = logic_data.get("target_name", "Evaluated Target")
        target_type = logic_data.get("target_type", "web").upper()
        score = logic_data.get("logic_integrity_score", 100.0)
        status = logic_data.get("overall_status", "LOGIC HARDENED")
        total_workflows = logic_data.get("total_workflows_evaluated", 0)
        total_checks = logic_data.get("total_checks", 0)
        passed_checks = logic_data.get("passed_checks", 0)
        defects_cnt = logic_data.get("defects_count", 0)
        warnings_cnt = logic_data.get("warnings_count", 0)
        pytest_suite = logic_data.get("pytest_logic_suite", "")
        copiable_md = logic_data.get("copiable_client_markdown", "")
        timestamp = logic_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        status_col = "#00ff9d" if "HARDENED" in status else "#ffb800" if "ATTENTION" in status or "WARNINGS" in status else "#ff3366"
        status_bg = "#0d1e17" if "HARDENED" in status else "#241d13" if "ATTENTION" in status or "WARNINGS" in status else "#2a1318"
        status_border = "#064e3b" if "HARDENED" in status else "#713f12" if "ATTENTION" in status or "WARNINGS" in status else "#881337"

        # Workflow rows
        wf_items = []
        for wf in logic_data.get("workflows", []):
            wf_items.append(f"""
            <li style="padding: 8px 12px; background: #0d121c; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px; font-weight: 600; color: #38bdf8;">
                {html.escape(wf)}
            </li>
            """)
        workflows_html = "\n".join(wf_items)

        # Flaw cards
        flaw_cards = []
        for fl in logic_data.get("flaws", []):
            sev = fl.get("severity", "MEDIUM")
            fl_status = fl.get("status", "PASSED")
            sev_col = "#ff3366" if sev == "CRITICAL" else "#ff5252" if sev == "HIGH" else "#ffb800" if sev == "MEDIUM" else "#00d4ff" if sev == "LOW" else "#38bdf8"
            stat_col = "#00ff9d" if fl_status == "PASSED" else "#ffb800" if fl_status == "WARNING" else "#ff3366"

            poc_html = ""
            if fl.get("flawed_sequence_poc") and fl_status in ("DEFECT", "WARNING"):
                poc_html = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; text-transform:uppercase; color:#ff3366; margin-bottom:4px; font-weight:700;">Proof-of-Concept Flawed Sequence</div>
                    <pre style="margin:0; background:#080b12; padding:10px; border-radius:6px; border:1px solid #33151c;"><code style="color:#fca5a5;">{html.escape(fl.get('flawed_sequence_poc', ''))}</code></pre>
                </div>
                """

            remed_html = ""
            if fl.get("remediation_pattern"):
                remed_html = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px; font-weight:700;">Remediation Domain Logic Pattern</div>
                    <pre style="margin:0; background:#080b12; padding:10px; border-radius:6px; border:1px solid #1e2638;"><code style="color:#00ff9d;">{html.escape(fl.get('remediation_pattern', ''))}</code></pre>
                </div>
                """

            flaw_cards.append(f"""
            <div class="card" style="border-left: 4px solid {sev_col}; margin-bottom:14px; padding:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                    <span style="font-weight:700; font-size:15px; color:#ffffff;">{html.escape(fl.get('title', ''))}</span>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span class="badge" style="background:#171f32; color:{stat_col}; border:1px solid {stat_col};">[{fl_status}]</span>
                        <span class="badge" style="background:#171f32; color:{sev_col}; border:1px solid {sev_col};">{sev}</span>
                        <code style="color:var(--text-muted); font-size:11px;">{html.escape(fl.get('flaw_id', ''))}</code>
                    </div>
                </div>
                <div style="font-size:12px; color:var(--accent); margin: 6px 0;">
                    Category: <strong>{html.escape(fl.get('category', ''))}</strong> &bull;
                    Workflow: <strong style="color:#cbd5e1;">{html.escape(fl.get('target_workflow', ''))}</strong>
                </div>
                <div style="font-size:13px; color:#cbd5e1; margin-top:6px;">{html.escape(fl.get('description', ''))}</div>
                <div style="font-size:12.5px; color:#fca5a5; margin-top:6px;"><strong>Impact:</strong> {html.escape(fl.get('impact', ''))}</div>
                {poc_html}
                {remed_html}
            </div>
            """)
        flaws_html = "\n".join(flaw_cards)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Business Logic & Transaction Integrity Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #00d4ff;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 700;
        }}
        .card {{
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}
        ul {{
            list-style: none;
            padding-left: 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#00d4ff; color:#0b0f19;">BUSINESS LOGIC & TRANSACTION INTEGRITY</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Platform: <strong style="color:var(--accent);">{html.escape(target_type)}</strong> &bull;
                    Workflows Audited: <strong>{total_workflows} State Machines</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Logic Integrity State</div>
                <span class="badge" style="background:{status_bg}; color:{status_col}; border:1px solid {status_border}; font-size:16px; font-weight:800; padding:6px 20px;">{html.escape(status)}</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Logic Score</div>
                <div class="kpi-val" style="color:{status_col};">{score:.1f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Workflows Audited</div>
                <div class="kpi-val" style="color:var(--accent);">{total_workflows}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Total Checks</div>
                <div class="kpi-val" style="color:#ffffff;">{total_checks}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Passed Checks</div>
                <div class="kpi-val" style="color:var(--green);">{passed_checks}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Logic Defects</div>
                <div class="kpi-val" style="color:{'var(--green)' if defects_cnt == 0 else 'var(--primary)'};">{defects_cnt}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Advisory Warnings</div>
                <div class="kpi-val" style="color:{'var(--green)' if warnings_cnt == 0 else 'var(--amber)'};">{warnings_cnt}</div>
            </div>
        </div>

        <div class="section">
            <h2>1. Audited Business Workflows & State Machine Boundaries</h2>
            <ul>
                {workflows_html}
            </ul>
        </div>

        <div class="section">
            <h2>2. Business Logic Flaws & State Machine Defect Matrix</h2>
            {flaws_html}
        </div>

        <div class="section">
            <h2>3. Automated Pytest Business Logic Test Suite (test_business_logic.py)</h2>
            <pre><code>{html.escape(pytest_suite)}</code></pre>
        </div>

        <div class="section">
            <h2>4. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre id="copiable-md" style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise Business Logic & Financial Transaction Quality Engineering Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_memory_report(cls, mem_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for Memory Leaks,
        OS Handle Exhaustion, GDI Object Profiling, and Detached Objects.
        """
        if hasattr(mem_data, "to_dict"):
            mem_data = mem_data.to_dict()

        target_name = mem_data.get("target_name", "Evaluated Target")
        target_type = mem_data.get("target_type", "web").upper()
        score = mem_data.get("memory_stability_score", 100.0)
        status = mem_data.get("overall_status", "MEMORY STABLE & HARDENED")
        metrics = mem_data.get("metrics", {})
        total_checks = mem_data.get("total_checks", 0)
        passed_checks = mem_data.get("passed_checks", 0)
        defects_cnt = mem_data.get("defects_count", 0)
        warnings_cnt = mem_data.get("warnings_count", 0)
        diag_script = mem_data.get("diagnostic_script", "")
        copiable_md = mem_data.get("copiable_client_markdown", "")
        timestamp = mem_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        status_col = "#00ff9d" if "STABLE" in status else "#ffb800" if "WARNING" in status or "DRIFT" in status else "#ff2a44"
        status_bg = "#0d1e17" if "STABLE" in status else "#241d13" if "WARNING" in status or "DRIFT" in status else "#2a1318"
        status_border = "#064e3b" if "STABLE" in status else "#713f12" if "WARNING" in status or "DRIFT" in status else "#881337"

        # Defect cards
        defect_cards = []
        for df in mem_data.get("defects", []):
            sev = df.get("severity", "MEDIUM")
            df_status = df.get("status", "PASSED")
            sev_col = "#ff3366" if sev == "CRITICAL" else "#ff5252" if sev == "HIGH" else "#ffb800" if sev == "MEDIUM" else "#00d4ff" if sev == "LOW" else "#38bdf8"
            stat_col = "#00ff9d" if df_status == "PASSED" else "#ffb800" if df_status == "WARNING" else "#ff3366"

            poc_html = ""
            if df.get("diagnostic_poc") and df_status in ("DEFECT", "WARNING"):
                poc_html = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; text-transform:uppercase; color:#ff3366; margin-bottom:4px; font-weight:700;">Diagnostic Test Scenario / Leak Trace</div>
                    <pre style="background:#1a0f14; border:1px solid #4a121e; color:#fca5a5; font-size:11px; padding:10px; border-radius:6px; overflow-x:auto;"><code>{html.escape(df.get('diagnostic_poc'))}</code></pre>
                </div>
                """

            remed_html = ""
            if df.get("remediation_pattern"):
                remed_html = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; text-transform:uppercase; color:#00ff9d; margin-bottom:4px; font-weight:700;">RAII / Lifecycle Remediation Pattern</div>
                    <pre style="background:#091410; border:1px solid #143826; color:#a7f3d0; font-size:11px; padding:10px; border-radius:6px; overflow-x:auto;"><code>{html.escape(df.get('remediation_pattern'))}</code></pre>
                </div>
                """

            defect_cards.append(f"""
            <div class="card" style="margin-bottom:16px; padding:16px; border-left: 4px solid {stat_col};">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <span class="badge" style="background:#121826; color:{stat_col}; border:1px solid {stat_col};">[{df_status}]</span>
                        <strong style="color:#ffffff; font-size:15px; margin-left:6px;">{html.escape(df.get('title', ''))}</strong>
                    </div>
                    <div>
                        <span class="badge" style="background:#171f32; color:{sev_col}; border:1px solid {sev_col};">{sev}</span>
                        <code style="color:var(--text-muted); font-size:11px;">{html.escape(df.get('defect_id', ''))}</code>
                    </div>
                </div>
                <div style="font-size:12px; color:var(--accent); margin: 6px 0;">
                    Category: <strong>{html.escape(df.get('category', ''))}</strong> &bull;
                    Component: <strong style="color:#cbd5e1;">{html.escape(df.get('target_component', ''))}</strong> &bull;
                    Leak Rate: <strong style="color:#ffb800;">{html.escape(df.get('leak_rate', 'None'))}</strong>
                </div>
                <div style="font-size:13px; color:#cbd5e1; margin-top:6px;">{html.escape(df.get('description', ''))}</div>
                <div style="font-size:12.5px; color:#fca5a5; margin-top:6px;"><strong>Impact:</strong> {html.escape(df.get('impact', ''))}</div>
                {poc_html}
                {remed_html}
            </div>
            """)
        defects_html = "\n".join(defect_cards)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Memory Profiling & Resource Leak Deliverable - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #38bdf8;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 24px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 700;
        }}
        .card {{
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0e1320;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#a855f7; color:#ffffff;">MEMORY & RESOURCE LEAK AUDIT</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Platform: <strong style="color:var(--accent);">{html.escape(target_type)}</strong> &bull;
                    Checks Evaluated: <strong>{total_checks} Resource Vectors</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Memory Health State</div>
                <span class="badge" style="background:{status_bg}; color:{status_col}; border:1px solid {status_border}; font-size:16px; font-weight:800; padding:6px 20px;">{html.escape(status)}</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">Stability Score</div>
                <div class="kpi-val" style="color:{status_col};">{score:.1f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Initial Working Set</div>
                <div class="kpi-val" style="color:#38bdf8;">{metrics.get('initial_memory_mb', 0):.1f} MB</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Peak Working Set</div>
                <div class="kpi-val" style="color:#ffb800;">{metrics.get('peak_working_set_mb', 0):.1f} MB</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Net Memory Drift</div>
                <div class="kpi-val" style="color:#ff2a44;">+{metrics.get('memory_growth_delta_mb', 0):.1f} MB</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Peak Handles</div>
                <div class="kpi-val" style="color:#a855f7;">{metrics.get('peak_handle_count', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Memory Defects</div>
                <div class="kpi-val" style="color:{'#ff2a44' if defects_cnt > 0 else '#00ff9d'};">{defects_cnt}</div>
            </div>
        </div>

        <div class="section">
            <h2>1. Resource Telemetry & Runaway Heap Profile</h2>
            <table>
                <thead>
                    <tr>
                        <th>Resource Attribute</th>
                        <th>Measured Metric</th>
                        <th>System Safety Threshold</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Initial Process Working Set (RAM)</td>
                        <td style="color:#38bdf8; font-weight:700;">{metrics.get('initial_memory_mb', 0):.2f} MB</td>
                        <td>Baseline allocation upon launch</td>
                    </tr>
                    <tr>
                        <td>Peak Working Set During Loop Stress</td>
                        <td style="color:#ffb800; font-weight:700;">{metrics.get('peak_working_set_mb', 0):.2f} MB</td>
                        <td>Must not scale unboundedly</td>
                    </tr>
                    <tr>
                        <td>Post-GC Retained Memory</td>
                        <td style="color:#cbd5e1; font-weight:700;">{metrics.get('post_gc_retained_mb', 0):.2f} MB</td>
                        <td>Should converge back to baseline</td>
                    </tr>
                    <tr>
                        <td>Active / Peak OS Kernel Handles</td>
                        <td style="color:#a855f7; font-weight:700;">{metrics.get('active_handle_count', 0)} / {metrics.get('peak_handle_count', 0)}</td>
                        <td>Hard Windows Cap: 10,000 handles</td>
                    </tr>
                    <tr>
                        <td>GDI Objects / Detached DOM Elements</td>
                        <td style="color:#ff3366; font-weight:700;">{metrics.get('gdi_objects_count', 0) if target_type == 'EXE' else metrics.get('detached_nodes_or_contexts', 0)}</td>
                        <td>Zero detached nodes after route exit</td>
                    </tr>
                    <tr>
                        <td>Projected Leak Rate Under Continuous Duty</td>
                        <td style="color:#ff2a44; font-weight:700;">+{metrics.get('projected_leak_rate_mb_hr', 0):.2f} MB/hr</td>
                        <td>&lt; 5.0 MB/hr for long-running services</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>2. Resource Exhaustion & Memory Leak Defect Matrix</h2>
            {defects_html}
        </div>

        <div class="section">
            <h2>3. Automated Diagnostic & Stress Profiling Script</h2>
            <pre><code>{html.escape(diag_script)}</code></pre>
        </div>

        <div class="section">
            <h2>4. Copiable Plaintext / Markdown Client Deliverable</h2>
            <pre id="copiable-md" style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise Memory Profiling & Resource Reliability Laboratory
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def generate_accessibility_report(cls, a11y_data: Any) -> str:
        """
        Generates a dedicated standalone HTML deliverable for WCAG 2.2,
        Section 508, Screen Reader ARIA Tree, and VPAT Conformance.
        """
        if hasattr(a11y_data, "to_dict"):
            a11y_data = a11y_data.to_dict()

        target_name = a11y_data.get("target_name", "Evaluated Target")
        target_type = a11y_data.get("target_type", "web").upper()
        metrics = a11y_data.get("metrics", {})
        score = metrics.get("wcag_score", 100.0)
        status = metrics.get("conformance_status", "CONFORMS (WCAG 2.2 AA)")
        axe_suite = a11y_data.get("axe_playwright_suite", "")
        copiable_md = a11y_data.get("copiable_vpat_markdown", "")
        timestamp = a11y_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        status_col = "#00ff9d" if "CONFORMS" in status else "#ffb800" if "PARTIAL" in status else "#ff2a44"
        status_bg = "#0d1e17" if "CONFORMS" in status else "#241d13" if "PARTIAL" in status else "#2a1318"
        status_border = "#064e3b" if "CONFORMS" in status else "#713f12" if "PARTIAL" in status else "#881337"

        # Landmarks rows
        lm_rows = []
        for lm in a11y_data.get("landmarks", []):
            st_col = "#00ff9d" if lm.get("status") == "VALID" else "#ffb800"
            lm_rows.append(f"""
            <tr>
                <td><span class="badge" style="background:#171f32; color:#38bdf8; border:1px solid #232c42;">{html.escape(lm.get('role', ''))}</span></td>
                <td><code style="color:#a7f3d0;">{html.escape(lm.get('element', ''))}</code></td>
                <td style="color:#f0f4fc; font-weight:600;">{html.escape(lm.get('accessible_name', ''))}</td>
                <td><span style="color:{st_col}; font-weight:700;">{html.escape(lm.get('status', ''))}</span></td>
            </tr>
            """)
        landmarks_html = "\n".join(lm_rows) if lm_rows else "<tr><td colspan='4'>No landmarks detected</td></tr>"

        # Defect cards
        defect_cards = []
        for df in a11y_data.get("defects", []):
            sev = df.get("level", "AA")
            df_status = df.get("status", "PASSED")
            stat_col = "#00ff9d" if df_status == "PASSED" else "#ffb800" if df_status == "WARNING" else "#ff3366"
            vpat_col = "#00ff9d" if df.get("vpat_conformance") == "Supports" else "#ffb800" if df.get("vpat_conformance") == "Partially Supports" else "#ff3366"

            remed_html = ""
            if df.get("remediation_code"):
                remed_html = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; text-transform:uppercase; color:#00ff9d; margin-bottom:4px; font-weight:700;">Accessible Code Remediation Pattern</div>
                    <pre style="background:#091410; border:1px solid #143826; color:#a7f3d0; font-size:11px; padding:10px; border-radius:6px; overflow-x:auto;"><code>{html.escape(df.get('remediation_code'))}</code></pre>
                </div>
                """

            defect_cards.append(f"""
            <div class="card" style="margin-bottom:16px; padding:16px; border-left: 4px solid {stat_col};">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <span class="badge" style="background:#121826; color:{stat_col}; border:1px solid {stat_col};">[{df_status}]</span>
                        <strong style="color:#ffffff; font-size:15px; margin-left:6px;">{html.escape(df.get('title', ''))}</strong>
                    </div>
                    <div>
                        <span class="badge" style="background:#171f32; color:#38bdf8; border:1px solid #38bdf8;">Level {sev}</span>
                        <span class="badge" style="background:#171f32; color:{vpat_col}; border:1px solid {vpat_col}; margin-left:4px;">{html.escape(df.get('vpat_conformance', ''))}</span>
                        <code style="color:var(--text-muted); font-size:11px; margin-left:6px;">{html.escape(df.get('defect_id', ''))}</code>
                    </div>
                </div>
                <div style="font-size:12px; color:var(--accent); margin: 6px 0;">
                    Principle: <strong>{html.escape(df.get('principle', ''))}</strong> &bull;
                    WCAG SC: <strong style="color:#f0f4fc;">{html.escape(df.get('wcag_sc', ''))}</strong> &bull;
                    Target Element: <code style="color:#ffb800;">{html.escape(df.get('target_element', ''))}</code>
                </div>
                <div style="font-size:13px; color:#cbd5e1; margin-top:6px;">{html.escape(df.get('description', ''))}</div>
                <div style="font-size:12.5px; color:#fca5a5; margin-top:6px;"><strong>Screen Reader Impact:</strong> {html.escape(df.get('screen_reader_impact', ''))}</div>
                {remed_html}
            </div>
            """)
        defects_html = "\n".join(defect_cards)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Accessibility & Assistive Tech Deliverable (WCAG 2.2) - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #121826;
            --surface-card: #171f32;
            --border: #232c42;
            --text: #f0f4fc;
            --text-muted: #8b9bb4;
            --primary: #ff2a44;
            --accent: #38bdf8;
            --green: #00ff9d;
            --amber: #ffb800;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #151a28 0%, #0d121c 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 24px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .kpi-lbl {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 1px;
        }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        code, pre {{
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
        }}
        pre {{
            background: #0b0e14;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            color: #38bdf8;
            font-size: 12px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 700;
        }}
        .card {{
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0e1320;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <span class="badge" style="background:#0284c7; color:#ffffff;">WCAG 2.2 & SECTION 508 AUDIT</span>
                <h1 style="margin:8px 0 4px 0; font-size:24px;">{html.escape(target_name)}</h1>
                <div style="font-size:13px; color:var(--text-muted);">
                    Platform: <strong style="color:var(--accent);">{html.escape(target_type)}</strong> &bull;
                    Standard: <strong>W3C WCAG 2.2 Level A/AA & VPAT 2.4</strong> &bull;
                    Timestamp: {html.escape(timestamp[:19].replace('T', ' '))}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">A11y Conformance</div>
                <span class="badge" style="background:{status_bg}; color:{status_col}; border:1px solid {status_border}; font-size:15px; font-weight:800; padding:6px 18px;">{html.escape(status)}</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-lbl">WCAG Score</div>
                <div class="kpi-val" style="color:{status_col};">{score:.1f}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Criteria Checked</div>
                <div class="kpi-val" style="color:#38bdf8;">{metrics.get('total_criteria_checked', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Conforming Criteria</div>
                <div class="kpi-val" style="color:#00ff9d;">{metrics.get('passed_criteria', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">A11y Defects</div>
                <div class="kpi-val" style="color:{'#ff2a44' if metrics.get('defects_count', 0) > 0 else '#00ff9d'};">{metrics.get('defects_count', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">Contrast Violations</div>
                <div class="kpi-val" style="color:{'#ffb800' if metrics.get('contrast_violations', 0) > 0 else '#00ff9d'};">{metrics.get('contrast_violations', 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-lbl">A11y Warnings</div>
                <div class="kpi-val" style="color:#ffb800;">{metrics.get('warnings_count', 0)}</div>
            </div>
        </div>

        <div class="section">
            <h2>1. WAI-ARIA Accessibility Tree & Landmark Telemetry</h2>
            <table>
                <thead>
                    <tr>
                        <th>ARIA Role</th>
                        <th>Semantic Element</th>
                        <th>Accessible Name</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {landmarks_html}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>2. WCAG 2.2 Level A & AA Criteria Defect Matrix</h2>
            {defects_html}
        </div>

        <div class="section">
            <h2>3. Automated Axe-Core & Playwright Test Suite (test_accessibility_wcag.py)</h2>
            <pre><code>{html.escape(axe_suite)}</code></pre>
        </div>

        <div class="section">
            <h2>4. Official VPAT 2.4 Executive Conformance Deliverable (Markdown)</h2>
            <pre id="copiable-md" style="color:#e2e8f0; font-size:11.5px;"><code>{html.escape(copiable_md)}</code></pre>
        </div>

        <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
            Generated by CHARLO Testing Agent &bull; Enterprise Accessibility & Assistive Technology Laboratory (WCAG 2.2 / Section 508)
        </footer>
    </div>
</body>
</html>"""




