"""
Risk and Security Posture Scoring Engine for CHARLO Testing Agent.
"""

from typing import List, Tuple
from .models import CheckFinding, CheckStatus, Severity, ScanMetrics


class RiskCalculator:
    """
    Computes deterministic, evidence-grounded risk scores and security grades.
    """

    @staticmethod
    def calculate_metrics(findings: List[CheckFinding]) -> ScanMetrics:
        metrics = ScanMetrics(total_checks=len(findings))

        deduction = 0.0

        for f in findings:
            if f.status == CheckStatus.PASSED:
                metrics.passed += 1
            elif f.status == CheckStatus.FAILED:
                metrics.failed += 1
                factor = 1.0 * f.confidence
                deduction += f.severity.score_weight * factor
            elif f.status == CheckStatus.WARNING:
                metrics.warnings += 1
                factor = 0.5 * f.confidence
                deduction += f.severity.score_weight * factor
            elif f.status == CheckStatus.NOT_APPLICABLE:
                metrics.not_applicable += 1
            elif f.status == CheckStatus.INCONCLUSIVE:
                metrics.inconclusive += 1

            # Count by severity (for failed and warning findings)
            if f.status in (CheckStatus.FAILED, CheckStatus.WARNING):
                if getattr(f, "is_bug", False):
                    metrics.total_bugs += 1
                if f.severity == Severity.CRITICAL:
                    metrics.critical_count += 1
                elif f.severity == Severity.HIGH:
                    metrics.high_count += 1
                elif f.severity == Severity.MEDIUM:
                    metrics.medium_count += 1
                elif f.severity == Severity.LOW:
                    metrics.low_count += 1
                elif f.severity == Severity.INFO:
                    metrics.info_count += 1

        # Deductions capped at 100
        score = max(0.0, min(100.0, 100.0 - deduction))
        metrics.security_score = round(score, 1)

        # Grade assignment
        if metrics.critical_count > 0:
            # Having an unmitigated critical vulnerability caps the grade at D or F
            if score >= 50.0:
                metrics.posture_grade = "D"
            else:
                metrics.posture_grade = "F"
        else:
            if score >= 92.0:
                metrics.posture_grade = "A+"
            elif score >= 80.0:
                metrics.posture_grade = "A"
            elif score >= 70.0:
                metrics.posture_grade = "B"
            elif score >= 55.0:
                metrics.posture_grade = "C"
            elif score >= 40.0:
                metrics.posture_grade = "D"
            else:
                metrics.posture_grade = "F"

        return metrics

    @staticmethod
    def get_risk_label(score: float, critical_count: int = 0) -> Tuple[str, str]:
        """
        Returns (Risk Level Label, Hex Color).
        """
        if critical_count > 0 or score < 40.0:
            return "CRITICAL RISK", "#FF3366"
        if score < 60.0:
            return "HIGH RISK", "#FF6B22"
        if score < 75.0:
            return "MODERATE RISK", "#FFB800"
        if score < 90.0:
            return "LOW RISK", "#00D4FF"
        return "HARDENED", "#00FF9D"
