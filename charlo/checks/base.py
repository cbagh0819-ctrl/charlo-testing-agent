"""
Base class definition for all CHARLO security checks.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from ..core.models import (
    TargetType,
    ScanLevel,
    Severity,
    CheckStatus,
    CheckFinding,
    ScanTarget,
)


class BaseCheck(ABC):
    """
    Abstract base class for all security testing checks.
    """

    check_id: str = "GEN-000"
    name: str = "Generic Security Check"
    description: str = "Checks for generic security properties."
    target_type: TargetType = TargetType.EXE
    level: ScanLevel = ScanLevel.BASIC
    category: str = "General"
    default_severity: Severity = Severity.MEDIUM
    standards: List[str] = []

    def __init__(self):
        pass

    @abstractmethod
    def run(self, target: ScanTarget, context: Dict[str, Any]) -> CheckFinding:
        """
        Executes the security check against the given target and context.
        Must return a structured CheckFinding.
        """
        pass

    def create_finding(
        self,
        status: CheckStatus,
        severity: Optional[Severity] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        affected_component: str = "Target",
        evidence: str = "",
        impact: str = "No critical impact identified.",
        remediation: str = "No action required.",
        confidence: float = 1.0,
        code_example: Optional[str] = None,
        verification_step: Optional[str] = None,
    ) -> CheckFinding:
        return CheckFinding(
            check_id=self.check_id,
            check_name=self.name,
            target_type=self.target_type,
            category=self.category,
            status=status,
            severity=severity or self.default_severity,
            title=title or f"{self.name} - {status.value.upper()}",
            description=description or self.description,
            affected_component=affected_component,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            confidence=confidence,
            code_example=code_example,
            verification_step=verification_step,
            standards=self.standards,
        )
