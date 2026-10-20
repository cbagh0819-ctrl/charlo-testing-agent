"""
Unit tests for GraphQL & WebSocket Protocol Security Testing Engine.
"""

import pytest
from charlo.core.models import ScanTarget, TargetType
from charlo.analyzers.graphql_websocket_tester import (
    GraphQLWebSocketTester,
    GraphQLWebSocketReport,
    GraphQLDefect
)


def test_graphql_websocket_tester_execution():
    """Verify execution of full GraphQL & WebSocket audit suite against target."""
    target = ScanTarget(
        target_path="https://api.pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC API Portal"
    )
    report = GraphQLWebSocketTester.run_tests(target)

    assert isinstance(report, GraphQLWebSocketReport)
    assert report.target_host == "api.pmec.ac.in"
    assert "graphql" in report.graphql_endpoint
    assert "ws" in report.websocket_endpoint
    assert 0.0 <= report.score <= 100.0
    assert len(report.defects) >= 4


def test_graphql_defects_structure():
    """Verify GraphQL defect findings contain remediation patterns and severities."""
    target = ScanTarget(
        target_path="https://test.target.local",
        target_type=TargetType.WEB,
        display_name="Test Target"
    )
    report = GraphQLWebSocketTester.run_tests(target)

    intro_defect = next((d for d in report.defects if "Introspection" in d.title), None)
    assert intro_defect is not None
    assert intro_defect.protocol == "GraphQL"
    assert "introspection" in intro_defect.remediation_pattern.lower()

    cswsh_defect = next((d for d in report.defects if "CSWSH" in d.title), None)
    assert cswsh_defect is not None
    assert cswsh_defect.protocol == "WebSocket"
    assert "origin" in cswsh_defect.remediation_pattern.lower()


def test_markdown_dossier_generation():
    """Verify Markdown executive report output contains tables and code blocks."""
    target = ScanTarget(
        target_path="https://secure-app.internal",
        target_type=TargetType.WEB,
        display_name="Internal App"
    )
    report = GraphQLWebSocketTester.run_tests(target)
    md = report.to_markdown()

    assert "# 🛰️ CHARLO GraphQL & WebSocket Security Audit Dossier" in md
    assert "Target Host:" in md
    assert "GraphQL Endpoint" in md
    assert "WebSocket Endpoint" in md
    assert "Identified Protocol Defects Matrix" in md
