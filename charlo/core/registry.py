"""
Central Check Registry for CHARLO Testing Agent.
"""

from typing import Dict, List, Type, Optional, Any
from ..core.models import TargetType, ScanLevel

# Avoid circular import by using Any for check typing at runtime
BaseCheckType = Any



class CheckRegistry:
    """
    Registry holding all implemented security checks.
    """

    _checks: Dict[str, Any] = {}

    @classmethod
    def register(cls, check_cls: Any) -> Any:
        if not check_cls.check_id or check_cls.check_id == "GEN-000":
            raise ValueError(f"Invalid check_id on {check_cls}")
        cls._checks[check_cls.check_id] = check_cls
        return check_cls

    @classmethod
    def get_check(cls, check_id: str) -> Optional[Any]:
        check_cls = cls._checks.get(check_id)
        return check_cls() if check_cls else None

    @classmethod
    def list_all(cls) -> List[Any]:
        return [c_cls() for c_cls in cls._checks.values()]

    @classmethod
    def get_checks_for_target(
        cls,
        target_type: Any,
        max_level: Any = ScanLevel.ADVANCED,
    ) -> List[Any]:
        """
        Retrieves instantiated checks applicable to target_type within max_level rank.
        """
        if isinstance(target_type, str) and not isinstance(target_type, TargetType):
            target_type = TargetType.from_string(target_type)
        if isinstance(max_level, str) and not isinstance(max_level, ScanLevel):
            max_level = ScanLevel.from_string(max_level)

        max_rank = max_level.rank if hasattr(max_level, "rank") else 2

        applicable: List[Any] = []
        for check_cls in cls._checks.values():
            if check_cls.target_type == target_type:
                c_rank = check_cls.level.rank if hasattr(check_cls.level, "rank") else 1
                if c_rank <= max_rank:
                    applicable.append(check_cls())
        # Sort by check_id
        applicable.sort(key=lambda c: c.check_id)
        return applicable

    @classmethod
    def clear(cls):
        cls._checks.clear()
