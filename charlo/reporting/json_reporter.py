"""
JSON Security Assessment Exporter for CHARLO Testing Agent.
"""

import json
from ..core.models import ScanResult


class JSONReporter:
    """
    Exports scan result in structured JSON.
    """

    @classmethod
    def export(cls, result: ScanResult, indent: int = 2) -> str:
        return json.dumps(result.to_dict(), indent=indent)
