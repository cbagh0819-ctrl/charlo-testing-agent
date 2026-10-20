"""
Data models and taxonomy for CHARLO Testing Agent.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import datetime
import uuid


class TargetType(str, Enum):
    APK = "apk"
    EXE = "exe"
    WEB = "web"

    @classmethod
    def from_string(cls, val: Any) -> "TargetType":
        if isinstance(val, TargetType):
            return val
        val_clean = str(val).strip().lower()
        if val_clean in ("apk", "android") or val_clean.endswith(".apk") or ".apk" in val_clean:
            return cls.APK
        if val_clean in ("exe", "pe", "dll") or val_clean.endswith(".exe") or val_clean.endswith(".dll") or ".exe" in val_clean or ".dll" in val_clean:
            return cls.EXE
        if val_clean in ("web", "url") or val_clean.startswith("http://") or val_clean.startswith("https://") or "www." in val_clean:
            return cls.WEB
        if "." in val_clean and "/" not in val_clean and "\\" not in val_clean and not val_clean.endswith((".exe", ".dll", ".apk")):
            return cls.WEB
        return cls.EXE


class ScanLevel(str, Enum):
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"

    @classmethod
    def from_string(cls, val: Any) -> "ScanLevel":
        if isinstance(val, ScanLevel):
            return val
        val_clean = str(val).strip().lower()
        if "basic" in val_clean:
            return cls.BASIC
        if "adv" in val_clean:
            return cls.ADVANCED
        return cls.INTERMEDIATE

    @property
    def rank(self) -> int:
        val = getattr(self, "value", str(self))
        ranks = {"basic": 1, "intermediate": 2, "advanced": 3}
        return ranks.get(val, 1)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_weight(self) -> float:
        weights = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.5,
            "info": 0.0,
        }
        return weights.get(self.value, 0.0)

    @property
    def badge_color(self) -> str:
        colors = {
            "critical": "#FF3366",  # Vibrant Cyber Red
            "high": "#FF6B22",      # Deep Safety Orange
            "medium": "#FFB800",    # Amber / Warning Yellow
            "low": "#00D4FF",       # Electric Cyan
            "info": "#7B889B",      # Slate Muted
        }
        return colors.get(self.value, "#7B889B")


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"


@dataclass
class CheckFinding:
    check_id: str
    check_name: str
    target_type: TargetType
    category: str
    status: CheckStatus
    severity: Severity
    title: str
    description: str
    affected_component: str
    evidence: str
    impact: str
    remediation: str
    confidence: float = 1.0  # 0.0 to 1.0
    code_example: Optional[str] = None
    verification_step: Optional[str] = None
    standards: List[str] = field(default_factory=list)  # CWE, OWASP, NIST
    finding_type: str = "security"  # "security" or "bug"
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    @property
    def is_bug(self) -> bool:
        return (
            getattr(self, "finding_type", "security") == "bug"
            or "bug" in self.category.lower()
            or "defect" in self.category.lower()
            or self.check_id.startswith("BUG-")
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["target_type"] = self.target_type.value
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        d["finding_type"] = getattr(self, "finding_type", "security")
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckFinding":
        data_copy = dict(data)
        data_copy["target_type"] = TargetType(data_copy["target_type"])
        data_copy["status"] = CheckStatus(data_copy["status"])
        data_copy["severity"] = Severity(data_copy["severity"])
        if "finding_type" not in data_copy:
            data_copy["finding_type"] = "security"
        return cls(**data_copy)


@dataclass
class ScanTarget:
    target_type: TargetType
    target_path: str
    display_name: str
    size_bytes: int = 0
    sha256: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["target_type"] = self.target_type.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanTarget":
        data_copy = dict(data)
        data_copy["target_type"] = TargetType(data_copy["target_type"])
        return cls(**data_copy)


@dataclass
class ScanMetrics:
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    inconclusive: int = 0
    not_applicable: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_bugs: int = 0
    security_score: float = 100.0  # 0 to 100
    posture_grade: str = "A+"      # A+, A, B, C, D, F

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanMetrics":
        return cls(**data)


@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: Optional[ScanTarget] = None
    level: ScanLevel = ScanLevel.BASIC
    start_time: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    end_time: str = ""
    duration_seconds: float = 0.0
    findings: List[CheckFinding] = field(default_factory=list)
    metrics: ScanMetrics = field(default_factory=ScanMetrics)
    logs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target.to_dict() if self.target else None,
            "level": self.level.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "metrics": self.metrics.to_dict(),
            "logs": self.logs,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        target = ScanTarget.from_dict(data["target"]) if data.get("target") else None
        level = ScanLevel(data.get("level", "basic"))
        findings = [CheckFinding.from_dict(f) for f in data.get("findings", [])]
        metrics = ScanMetrics.from_dict(data.get("metrics", {})) if data.get("metrics") else ScanMetrics()
        return cls(
            scan_id=data.get("scan_id", str(uuid.uuid4())),
            target=target,
            level=level,
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
            findings=findings,
            metrics=metrics,
            logs=data.get("logs", []),
        )
