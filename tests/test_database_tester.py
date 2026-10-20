"""
Unit tests for CHARLO Database & Data Layer Integrity, SQL Defense & Schema Validation Engine.
"""

import pytest
from charlo.core.models import ScanTarget, TargetType, CheckFinding, CheckStatus, Severity, ScanLevel
from charlo.analyzers.database_tester import (
    DatabaseTester,
    DbTableInspection,
    DbDefect,
    DatabaseTestReport,
)
from charlo.reporting.html_reporter import HTMLReporter
from charlo.core.engine import ScanEngine


def test_database_tester_run_tests_basic():
    """Verify DatabaseTester creates comprehensive schema, index, ACID, and SQL defense reports."""
    target = ScanTarget(
        target_path="https://api.pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC Enterprise Portal",
    )

    report = DatabaseTester.run_tests(target)
    assert isinstance(report, DatabaseTestReport)
    assert report.target_name == "PMEC Enterprise Portal"
    assert "PostgreSQL" in report.database_engine
    assert len(report.tables) >= 5
    assert len(report.defects) >= 5
    assert report.total_tables_checked == len(report.tables)
    assert report.total_checks >= 5
    assert 0.0 <= report.data_integrity_score <= 100.0
    assert report.overall_status in [
        "PRODUCTION CERTIFIED",
        "DEFECTS REQUIRING ATTENTION",
        "CRITICAL INTEGRITY FAILURE",
    ]


def test_database_tester_defects_and_remediations():
    """Verify DbDefect items contain valid categories, severities, impacts, and SQL patches."""
    target = ScanTarget(
        target_path="https://enterprise.acme.corp",
        target_type=TargetType.WEB,
        display_name="Enterprise Acme Portal",
    )

    report = DatabaseTester.run_tests(target)
    categories = {d.category for d in report.defects}
    assert "Index & Query Traps" in categories
    assert "Data Integrity" in categories
    assert "ACID & Concurrency" in categories
    assert "SQL Defense" in categories
    assert "Schema & Constraints" in categories

    for defect in report.defects:
        assert defect.defect_id.startswith("DB-")
        assert defect.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert defect.status in ["PASSED", "DEFECT", "WARNING"]
        assert len(defect.title) > 0
        assert len(defect.description) > 0
        assert len(defect.impact) > 0
        assert len(defect.remediation_sql) > 0


def test_database_tester_sql_migration_generation():
    """Verify the idempotent SQL remediation script contains expected DDL statements."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = DatabaseTester.run_tests(target)
    sql = report.ready_to_run_sql_migration

    assert "BEGIN TRANSACTION;" in sql
    assert "COMMIT;" in sql
    assert "CREATE INDEX CONCURRENTLY" in sql
    assert "ALTER TABLE" in sql
    assert "ON DELETE CASCADE" in sql or "ON DELETE SET NULL" in sql


def test_database_tester_copiable_markdown():
    """Verify copiable corporate client deliverable markdown contains executive summary and tables."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = DatabaseTester.run_tests(target)
    md = report.copiable_client_markdown

    assert "PROFESSIONAL DATABASE & DATA LAYER AUDIT" in md
    assert "Target System:       Demo Corp" in md
    assert "Integrity Score:" in md
    assert "TABLE SCHEMA & INDEXING DIRECTORY" in md
    assert "DETAILED DEFECT MATRIX & REMEDIATION PATCHES" in md
    assert "SQL Patch:" in md


def test_database_tester_dict_serialization():
    """Verify to_dict produces JSON-serializable structured dictionary."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = DatabaseTester.run_tests(target)
    d = report.to_dict()

    assert d["target_name"] == "Demo Corp"
    assert isinstance(d["tables"], list)
    assert isinstance(d["defects"], list)
    assert len(d["tables"]) > 0
    assert "primary_key" in d["tables"][0]
    assert "remediation_sql" in d["defects"][0]


def test_database_html_reporter():
    """Verify HTMLReporter generates standalone, publication-grade Database QA report."""
    target = ScanTarget(
        target_path="https://portal.bank.corp",
        target_type=TargetType.WEB,
        display_name="Secure Banking Core",
    )

    report = DatabaseTester.run_tests(target)
    html = HTMLReporter.generate_database_report(report)

    assert "<!DOCTYPE html>" in html
    assert "Secure Banking Core" in html
    assert "Database Integrity & Schema Validation Deliverable" in html or "Database Integrity &amp; Schema Validation Deliverable" in html
    assert "Idempotent DDL Remediation SQL Migration Script" in html
    assert "Copiable Plaintext / Markdown Client Deliverable" in html


def test_database_engine_scan_integration():
    """Verify ScanEngine executes DatabaseTester and stores report in target metadata."""
    engine = ScanEngine()
    result = engine.run_scan(
        target_input="https://pmec.ac.in",
        target_type=TargetType.WEB,
        level=ScanLevel.BASIC
    )

    assert "database_report" in result.target.metadata
    db_meta = result.target.metadata["database_report"]
    assert "PMEC" in db_meta["target_name"] or "pmec" in db_meta["target_name"]
    assert db_meta["total_tables_checked"] >= 5
    assert len(db_meta["defects"]) >= 5
