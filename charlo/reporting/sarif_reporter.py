"""
CHARLO Testing Agent - Universal OASIS SARIF 2.1.0 Exporter.
Exports scan findings to official Static Analysis Results Interchange Format (SARIF)
for native ingestion into GitHub Code Scanning, GitLab Security Dashboard,
Azure DevOps pipelines, SonarQube, and VS Code SARIF viewers.
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from ..core.models import ScanResult, CheckFinding, Severity, CheckStatus


class SarifReporter:
    """OASIS SARIF 2.1.0 compliance generator for CHARLO Testing Agent."""

    SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "CHARLO Testing Agent"
    TOOL_VERSION = "2.4.0"
    TOOL_URL = "https://charlo.security"

    # Map CHARLO Severities to SARIF notification levels
    SEVERITY_MAP = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    @classmethod
    def generate_sarif(cls, result: ScanResult) -> Dict[str, Any]:
        """Converts ScanResult findings and telemetry into standard SARIF v2.1.0 object."""
        rules_dict: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        target_uri = result.target.display_name if result.target else "target"

        for f in result.findings:
            rule_id = f.check_id
            sarif_level = cls.SEVERITY_MAP.get(f.severity, "warning")

            # Register rule if not yet seen
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": f.check_name.replace(" ", "_"),
                    "shortDescription": {
                        "text": f.title
                    },
                    "fullDescription": {
                        "text": f.description
                    },
                    "defaultConfiguration": {
                        "level": sarif_level
                    },
                    "help": {
                        "text": f"Remediation Guidance:\n{f.remediation}\n\nObserved Impact:\n{f.impact}",
                        "markdown": f"### Remediation Guidance\n{f.remediation}\n\n**Observed Impact:**\n{f.impact}"
                    },
                    "properties": {
                        "category": f.category,
                        "precision": "very-high",
                        "tags": ["security", f.category.lower().replace(" ", "-"), f.target_type.value]
                    }
                }

            # Only record non-passed findings as active SARIF defect results
            if f.status in (CheckStatus.FAILED, CheckStatus.WARNING):
                sarif_results.append({
                    "ruleId": rule_id,
                    "ruleIndex": list(rules_dict.keys()).index(rule_id),
                    "level": sarif_level,
                    "message": {
                        "text": f"{f.title}: {f.description}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.affected_component or target_uri,
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 1
                                }
                            }
                        }
                    ],
                    "properties": {
                        "charlo_severity": f.severity.value,
                        "charlo_status": f.status.value,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "impact": f.impact
                    }
                })

        sarif_doc = {
            "$schema": cls.SARIF_SCHEMA,
            "version": cls.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": cls.TOOL_NAME,
                            "semanticVersion": cls.TOOL_VERSION,
                            "informationUri": cls.TOOL_URL,
                            "rules": list(rules_dict.values())
                        }
                    },
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": result.start_time,
                            "endTimeUtc": result.end_time or datetime.now().isoformat()
                        }
                    ]
                }
            ]
        }
        return sarif_doc

    @classmethod
    def generate(cls, result: ScanResult) -> str:
        """Returns formatted SARIF v2.1.0 JSON string for downstream consumers."""
        sarif_data = cls.generate_sarif(result)
        return json.dumps(sarif_data, indent=2, ensure_ascii=False)

    @classmethod
    def export_to_file(cls, result: ScanResult, output_path: str) -> str:
        """Serializes SARIF report directly to disk."""
        sarif_data = cls.generate_sarif(result)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
        return output_path

    @classmethod
    def export_file(cls, result: ScanResult, output_path: str) -> str:
        """Convenience alias for export_to_file."""
        return cls.export_to_file(result, output_path)
