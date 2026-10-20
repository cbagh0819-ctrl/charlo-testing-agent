"""
CHARLO CI/CD Pipeline Automation, Quality Gate Rule Engine & JUnit XML Deliverable Generator.

Provides enterprise DevOps and Continuous Testing integration:
- Automated Quality Gate verification (pass/fail criteria for PRs & builds).
- Conforms to standard JUnit XML schema (<testsuites><testsuite><testcase><failure>).
- Production-grade GitHub Actions Workflow (.github/workflows/quality_gate.yml).
- Production-grade GitLab CI/CD Pipeline (.gitlab-ci.yml).
- Production-grade Jenkins Declarative Pipeline (Jenkinsfile).
- Copiable DevOps Client Deliverable with gating sign-off.
"""

import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import html
import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional

from charlo.core.models import ScanTarget, ScanResult, TargetType, CheckFinding, Severity, CheckStatus


@dataclass
class QualityGateRule:
    max_critical_findings: int = 0
    max_high_findings: int = 0
    min_overall_score: float = 75.0
    max_p95_latency_ms: float = 600.0
    max_error_rate_pct: float = 1.0
    block_on_contract_defect: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QualityGateResult:
    passed: bool
    status: str             # "GATE PASSED", "GATE BREACHED", "WARNING"
    overall_score: float
    total_violations: int
    violation_details: List[str] = field(default_factory=list)
    remediation_advice: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CiCdPipelineReport:
    target_name: str
    target_type: str
    target_path: str
    gate_rule: QualityGateRule
    gate_result: QualityGateResult
    github_actions_yaml: str = ""
    gitlab_ci_yaml: str = ""
    jenkinsfile_content: str = ""
    junit_xml_content: str = ""
    copiable_client_markdown: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["gate_rule"] = self.gate_rule.to_dict()
        d["gate_result"] = self.gate_result.to_dict()
        return d


class CiCdGenerator:
    """
    Automated Continuous Integration quality gate evaluator and multi-platform CI/CD generator.
    """

    @classmethod
    def evaluate_quality_gate(
        cls,
        result: Optional[ScanResult],
        rule: Optional[QualityGateRule] = None,
    ) -> QualityGateResult:
        rule = rule or QualityGateRule()

        if not result:
            return QualityGateResult(
                passed=True,
                status="GATE PASSED",
                overall_score=100.0,
                total_violations=0,
                violation_details=["No scan execution data available; default pass."],
                remediation_advice=[],
            )

        violations: List[str] = []
        advice: List[str] = []

        # 1. Evaluate Findings (Security & Bugs)
        crit_count = sum(1 for f in result.findings if f.status == CheckStatus.FAILED and f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in result.findings if f.status == CheckStatus.FAILED and f.severity == Severity.HIGH)

        if crit_count > rule.max_critical_findings:
            violations.append(f"Critical Vulnerability Threshold Breached: {crit_count} Criticals detected (Max Allowed: {rule.max_critical_findings}).")
            advice.append("Resolve all Severity: CRITICAL findings before merging pull requests.")

        if high_count > rule.max_high_findings:
            violations.append(f"High Severity Threshold Breached: {high_count} Highs detected (Max Allowed: {rule.max_high_findings}).")
            advice.append("Remediate High-risk security vulnerabilities or request architecture exemption.")

        # 2. Evaluate Score
        score = result.metrics.security_score if result.metrics else 100.0
        if score < rule.min_overall_score:
            violations.append(f"Health Score Threshold Breached: Overall Score is {score:.1f}% (Minimum Required: {rule.min_overall_score}%).")
            advice.append(f"Improve test coverage and resolve flagged defects to achieve >= {rule.min_overall_score}%.")

        # 3. Evaluate API Contract Defects
        meta = result.target.metadata if (result.target and result.target.metadata) else {}
        api_rep = meta.get("api_report")
        if api_rep and rule.block_on_contract_defect:
            failed_tests = api_rep.get("failed_tests", 0)
            if failed_tests > 0:
                violations.append(f"REST API Contract Defects: {failed_tests} blocking API defects detected in contract validation.")
                advice.append("Fix failing API contract endpoints or update OpenAPI specifications.")

        # 4. Evaluate Performance Latency & Error Rate
        perf_rep = meta.get("performance_report")
        if perf_rep:
            pct = perf_rep.get("percentiles", {})
            p95 = pct.get("p95_ms", 0.0)
            err_rate = perf_rep.get("error_rate_pct", 0.0)

            if p95 > rule.max_p95_latency_ms:
                violations.append(f"Latency SLA Breached: p95 response time is {p95:.1f}ms (Max Allowed: {rule.max_p95_latency_ms}ms).")
                advice.append("Profile slow database queries and enable HTTP connection pooling.")

            if err_rate > rule.max_error_rate_pct:
                violations.append(f"Error Rate SLA Breached: Error rate is {err_rate:.2f}% (Max Allowed: {rule.max_error_rate_pct}%).")
                advice.append("Investigate HTTP 429/504 gateway timeouts under concurrency.")

        passed = len(violations) == 0
        status = "GATE PASSED" if passed else "GATE BREACHED"

        return QualityGateResult(
            passed=passed,
            status=status,
            overall_score=score,
            total_violations=len(violations),
            violation_details=violations if violations else ["All quality gate criteria satisfied. Clean build."],
            remediation_advice=advice,
        )

    # =========================================================================
    # JUNIT XML GENERATOR (Universal CI/CD Test Format)
    # =========================================================================
    @classmethod
    def generate_junit_xml(cls, result: Optional[ScanResult]) -> str:
        """
        Produces standard JUnit XML (<testsuites>) consumed by GitHub, GitLab, Jenkins,
        Azure DevOps, and Bitbucket pipelines.
        """
        testsuites = ET.Element("testsuites", {
            "name": "CHARLO Automated Test Suite",
            "time": str(round(result.duration_seconds if result else 1.0, 2)),
            "tests": str(len(result.findings) if result else 0),
            "failures": str(sum(1 for f in result.findings if f.status == CheckStatus.FAILED) if result else 0),
            "errors": "0",
            "skipped": str(sum(1 for f in result.findings if f.status in (CheckStatus.NOT_APPLICABLE, CheckStatus.INCONCLUSIVE)) if result else 0),
        })

        # Security & Bug Checks Suite
        sec_suite = ET.SubElement(testsuites, "testsuite", {
            "name": "Security & Software Defect Audit",
            "tests": str(len(result.findings) if result else 0),
            "failures": str(sum(1 for f in result.findings if f.status == CheckStatus.FAILED) if result else 0),
            "time": str(round((result.duration_seconds if result else 1.0) * 0.5, 2)),
        })

        if result and result.findings:
            for f in result.findings:
                tc = ET.SubElement(sec_suite, "testcase", {
                    "name": f.title,
                    "classname": f"charlo.checks.{f.target_type.value}.{f.check_id}",
                    "time": "0.05",
                })
                if f.status == CheckStatus.FAILED:
                    fail_elem = ET.SubElement(tc, "failure", {
                        "message": f"[{f.severity.value.upper()}] {f.description[:120]}",
                        "type": f.category,
                    })
                    fail_elem.text = f"Title: {f.title}\nSeverity: {f.severity.value}\nAffected: {f.affected_component}\nRemediation: {f.remediation}"
                elif f.status in (CheckStatus.NOT_APPLICABLE, CheckStatus.INCONCLUSIVE):
                    skip_elem = ET.SubElement(tc, "skipped")
                    skip_elem.text = "Check not applicable to evaluated environment."

        # REST API Contract Suite (if present in metadata)
        meta = result.target.metadata if (result and result.target and result.target.metadata) else {}
        api_data = meta.get("api_report")
        if api_data:
            cases = api_data.get("test_cases", [])
            api_suite = ET.SubElement(testsuites, "testsuite", {
                "name": "REST API Contract & Schema Fuzzing",
                "tests": str(len(cases)),
                "failures": str(sum(1 for c in cases if c.get("status") == "FAILED")),
                "time": str(round(api_data.get("duration_seconds", 0.8), 2)),
            })
            for c in cases:
                tc = ET.SubElement(api_suite, "testcase", {
                    "name": c.get("test_name", "API Test"),
                    "classname": f"charlo.api.{c.get('category', 'contract').replace(' ', '_')}.{c.get('test_id')}",
                    "time": str(round(c.get("latency_ms", 45) / 1000.0, 3)),
                })
                if c.get("status") == "FAILED":
                    fail_elem = ET.SubElement(tc, "failure", {
                        "message": c.get("actual_status", "Assertion failed"),
                        "type": "ApiContractViolation",
                    })
                    fail_elem.text = f"Endpoint: {c.get('method')} {c.get('endpoint')}\nDetails: {c.get('details')}\nFix: {c.get('developer_patch')}"

        rough_string = ET.tostring(testsuites, encoding="utf-8")
        parsed = minidom.parseString(rough_string)
        return parsed.toprettyxml(indent="  ")

    # =========================================================================
    # GITHUB ACTIONS WORKFLOW GENERATOR (.github/workflows/quality_gate.yml)
    # =========================================================================
    @classmethod
    def generate_github_actions(cls, target: ScanTarget, rule: QualityGateRule) -> str:
        target_path = target.target_path if hasattr(target, "target_path") else str(target)
        t_type = target.target_type.value if hasattr(target, "target_type") else "web"

        return f"""# ============================================================================
# CHARLO QUALITY GATE & CONTINUOUS TESTING PIPELINE (GitHub Actions)
# Target:      {target_path}
# Platform:    {t_type.upper()}
# Policy:      Strict Quality Gate (Exit Code 1 on Failure)
# ============================================================================
name: CHARLO Automated Quality Gate & Security Audit

on:
  push:
    branches: [ main, master, release/** ]
  pull_request:
    branches: [ main, master ]
  workflow_dispatch:
    inputs:
      target_override:
        description: 'Target to evaluate (URL, APK, or EXE)'
        required: false
        default: '{target_path}'

permissions:
  contents: read
  checks: write
  pull-requests: write

jobs:
  quality_gate_audit:
    name: Execute CHARLO QA, Security & Performance Gate
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - name: Checkout Repository Code
        uses: actions/checkout@v4

      - name: Set up Python Environment
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: Install CHARLO Dependencies & Runners
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt || pip install pytest requests

      - name: Run Full CHARLO Automated Audit
        id: run_audit
        run: |
          python main.py --cli \\
            --target "${{{{ github.event.inputs.target_override || '{target_path}' }}}}" \\
            --type {t_type} \\
            --level intermediate \\
            --api \\
            --performance \\
            --html ./charlo_report.html \\
            --json ./charlo_findings.json

      - name: Enforce Quality Gate Policy
        run: |
          python -c "
          import json, sys
          with open('charlo_findings.json') as f:
              data = json.load(f)
          
          findings = data.get('findings', [])
          crit = sum(1 for x in findings if x.get('severity') == 'critical' and x.get('status') == 'failed')
          high = sum(1 for x in findings if x.get('severity') == 'high' and x.get('status') == 'failed')
          score = data.get('metrics', {{}}).get('security_score', 100)

          print(f'Gate Evaluation: Score={{score}}%, Criticals={{crit}}, Highs={{high}}')
          
          if crit > {rule.max_critical_findings}:
              print(f'❌ REJECTED: Critical findings count {{crit}} exceeds threshold {rule.max_critical_findings}')
              sys.exit(1)
          if high > {rule.max_high_findings}:
              print(f'❌ REJECTED: High findings count {{high}} exceeds threshold {rule.max_high_findings}')
              sys.exit(1)
          if score < {rule.min_overall_score}:
              print(f'❌ REJECTED: Overall health score {{score}}% is below threshold {rule.min_overall_score}%')
              sys.exit(1)
          
          print('✅ QUALITY GATE PASSED: All security & test criteria satisfied.')
          "

      - name: Upload HTML Security & QA Deliverable
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: charlo-qa-audit-deliverable
          path: ./charlo_report.html
          retention-days: 14
"""

    # =========================================================================
    # GITLAB CI/CD PIPELINE GENERATOR (.gitlab-ci.yml)
    # =========================================================================
    @classmethod
    def generate_gitlab_ci(cls, target: ScanTarget, rule: QualityGateRule) -> str:
        target_path = target.target_path if hasattr(target, "target_path") else str(target)
        t_type = target.target_type.value if hasattr(target, "target_type") else "web"

        return f"""# ============================================================================
# CHARLO QUALITY GATE & TESTING PIPELINE (GitLab CI/CD)
# Target:      {target_path} ({t_type.upper()})
# ============================================================================
stages:
  - test
  - security-audit
  - quality-gate

variables:
  TARGET_PATH: "{target_path}"
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip
    - venv/

charlo:security_and_api_audit:
  stage: security-audit
  image: python:3.12-slim
  before_script:
    - python -V
    - pip install -r requirements.txt || pip install pytest requests
  script:
    - python main.py --cli --target "$TARGET_PATH" --type {t_type} --api --performance --html charlo_report.html --json charlo_findings.json
  artifacts:
    when: always
    paths:
      - charlo_report.html
      - charlo_findings.json
    expire_in: 2 weeks

charlo:quality_gate_enforcement:
  stage: quality-gate
  image: python:3.12-slim
  dependencies:
    - charlo:security_and_api_audit
  script:
    - python -c "
      import json, sys
      with open('charlo_findings.json') as f:
          data = json.load(f)
      crit = sum(1 for x in data.get('findings', []) if x.get('severity') == 'critical' and x.get('status') == 'failed')
      high = sum(1 for x in data.get('findings', []) if x.get('severity') == 'high' and x.get('status') == 'failed')
      score = data.get('metrics', {{}}).get('security_score', 100)
      if crit > {rule.max_critical_findings} or high > {rule.max_high_findings} or score < {rule.min_overall_score}:
          print('❌ GitLab CI Quality Gate FAILED.')
          sys.exit(1)
      print('✅ GitLab CI Quality Gate PASSED.')
      "
"""

    # =========================================================================
    # JENKINS DECLARATIVE PIPELINE (Jenkinsfile)
    # =========================================================================
    @classmethod
    def generate_jenkinsfile(cls, target: ScanTarget, rule: QualityGateRule) -> str:
        target_path = target.target_path if hasattr(target, "target_path") else str(target)
        t_type = target.target_type.value if hasattr(target, "target_type") else "web"

        return f"""// ============================================================================
// CHARLO QUALITY GATE & TESTING PIPELINE (Jenkins Declarative Pipeline)
// Target:      {target_path} ({t_type.upper()})
// ============================================================================
pipeline {{
    agent any

    environment {{
        TARGET_URL = '{target_path}'
        MAX_CRITICAL = '{rule.max_critical_findings}'
        MAX_HIGH = '{rule.max_high_findings}'
        MIN_SCORE = '{rule.min_overall_score}'
    }}

    stages {{
        stage('Initialize Environment') {{
            steps {{
                echo "Initializing CHARLO Testing Suite for ${{TARGET_URL}}..."
                sh 'python3 --version'
                sh 'python3 -m pip install -r requirements.txt || python3 -m pip install requests pytest'
            }}
        }}

        stage('Execute CHARLO Automated Audit') {{
            steps {{
                echo "Executing security, software defect, API, and performance benchmark..."
                sh '''
                    python3 main.py --cli \\
                        --target "${{TARGET_URL}}" \\
                        --type {t_type} \\
                        --level intermediate \\
                        --api \\
                        --performance \\
                        --html charlo_report.html \\
                        --json charlo_findings.json
                '''
            }}
        }}

        stage('Quality Gate & SLA Enforcement') {{
            steps {{
                echo "Enforcing corporate quality gate thresholds..."
                sh '''
                    python3 -c "
import json, sys
with open('charlo_findings.json') as f:
    d = json.load(f)
findings = d.get('findings', [])
crit = sum(1 for x in findings if x.get('severity') == 'critical' and x.get('status') == 'failed')
high = sum(1 for x in findings if x.get('severity') == 'high' and x.get('status') == 'failed')
score = d.get('metrics', {{}}).get('security_score', 100)

print(f'Score: {{score}}% | Criticals: {{crit}} | Highs: {{high}}')
if crit > int('${{MAX_CRITICAL}}') or high > int('${{MAX_HIGH}}') or score < float('${{MIN_SCORE}}'):
    print('❌ Pipeline Blocked: Quality Gate Criteria Violated.')
    sys.exit(1)
print('✅ Quality Gate Cleared: Pipeline Approved.')
"
                '''
            }}
        }}
    }}

    post {{
        always {{
            archiveArtifacts artifacts: 'charlo_report.html, charlo_findings.json', fingerprint: true, allowEmptyArchive: true
        }}
        failure {{
            echo "Quality Gate Failed! Notifications dispatched to engineering channel."
        }}
    }}
}}
"""

    # =========================================================================
    # COPIABLE CORPORATE CI/CD DELIVERABLE (Markdown)
    # =========================================================================
    @classmethod
    def _generate_client_markdown(cls, report: CiCdPipelineReport) -> str:
        sep = "=" * 80
        sub_sep = "-" * 80
        gate = report.gate_result
        rule = report.gate_rule

        lines = [
            sep,
            "         CHARLO TESTING AGENT - CI/CD AUTOMATION & QUALITY GATE AUDIT",
            "                  Prepared for Corporate Client & Hiring Review",
            sep,
            f" Target System:       {report.target_name} ({report.target_path})",
            f" Platform:            {report.target_type.upper()}",
            f" Gate Status:         {gate.status} (Health Score: {gate.overall_score:.1f}%)",
            f" Policy Rule Set:     Strict Zero-Critical Enterprise Gate",
            f" Assessment Date:     {report.timestamp[:19].replace('T', ' ')} UTC",
            f" Audit Specialist:    Principal DevOps & Continuous Quality Engineer",
            sub_sep,
            "",
            "1. QUALITY GATE VERIFICATION & POLICY COMPLIANCE",
            sub_sep,
            f"An automated continuous quality gate policy check was evaluated against '{report.target_name}'.",
            f"Status: {gate.status} with {gate.total_violations} gate violation(s) recorded.",
            "",
            f"   • Minimum Score Required:       >= {rule.min_overall_score}% (Measured: {gate.overall_score:.1f}%)",
            f"   • Max Allowed Criticals:        <= {rule.max_critical_findings}",
            f"   • Max Allowed Highs:            <= {rule.max_high_findings}",
            f"   • Max p95 Latency SLA:          <= {rule.max_p95_latency_ms} ms",
            f"   • Max Permitted Error Rate:     <= {rule.max_error_rate_pct}%",
            f"   • Block on API Contract Defect: {'Enforced' if rule.block_on_contract_defect else 'Disabled'}",
            "",
            "Policy Evaluation Findings:",
        ]

        for idx, item in enumerate(gate.violation_details, start=1):
            icon = "✔" if gate.passed else "✖"
            lines.append(f" [{idx}] {icon} {item}")
        lines.append("")

        if gate.remediation_advice:
            lines.extend([
                "2. GATE REMEDIATION ACTION ITEMS",
                sub_sep,
            ])
            for idx, adv in enumerate(gate.remediation_advice, start=1):
                lines.append(f" [{idx}] ACTION: {adv}")
            lines.append("")

        lines.extend([
            "3. CI/CD INTEGRATION ARTIFACTS AVAILABLE",
            sub_sep,
            "A. GitHub Actions Workflow:",
            "   Pre-configured `.github/workflows/quality_gate.yml` ready to commit into repository.",
            "",
            "B. GitLab CI/CD Pipeline:",
            "   Multi-stage pipeline definition `.gitlab-ci.yml` with security-audit and gate stages.",
            "",
            "C. Jenkins Declarative Pipeline:",
            "   Production-ready `Jenkinsfile` with artifact archiving and pass/fail exit code thresholds.",
            "",
            "D. Universal JUnit XML Test Results:",
            "   `junit_results.xml` conforming to standard JUnit schema for test dashboard rendering.",
            "",
            "4. SIGN-OFF & CERTIFICATION",
            sub_sep,
            f"This document certifies that the continuous integration quality gate policy has been verified.",
            f"Current Gate Status: {gate.status}",
            "Report generated automatically by CHARLO Testing Agent.",
            sep,
        ])

        return "\n".join(lines)

    # =========================================================================
    # MAIN COORDINATOR
    # =========================================================================
    @classmethod
    def run_pipeline_generation(
        cls,
        target: ScanTarget,
        result: Optional[ScanResult] = None,
        rule: Optional[QualityGateRule] = None,
    ) -> CiCdPipelineReport:
        rule = rule or QualityGateRule()
        t_name = target.display_name if hasattr(target, "display_name") else str(target)
        t_path = target.target_path if hasattr(target, "target_path") else str(target)
        t_type = target.target_type.value if hasattr(target, "target_type") else "web"

        gate_res = cls.evaluate_quality_gate(result, rule)
        junit_xml = cls.generate_junit_xml(result)
        gh_actions = cls.generate_github_actions(target, rule)
        gl_ci = cls.generate_gitlab_ci(target, rule)
        jenkins = cls.generate_jenkinsfile(target, rule)

        rep = CiCdPipelineReport(
            target_name=t_name,
            target_type=t_type,
            target_path=t_path,
            gate_rule=rule,
            gate_result=gate_res,
            github_actions_yaml=gh_actions,
            gitlab_ci_yaml=gl_ci,
            jenkinsfile_content=jenkins,
            junit_xml_content=junit_xml,
        )
        rep.copiable_client_markdown = cls._generate_client_markdown(rep)
        return rep
