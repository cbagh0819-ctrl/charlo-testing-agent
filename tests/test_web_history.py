"""
Unit tests for CHARLO Website History, Domain Chronology & Admin Intelligence Analyzer.
"""

import pytest
from charlo.analyzers.web_history import (
    WebHistoryAnalyzer,
    DomainRegistrationInfo,
    AdminMaturityProfile,
    YearlyMilestone,
    HistoricalSecurityAudit,
    SiteDataFootprint,
    WebHistoryReport,
)


def test_extract_root_domain():
    assert WebHistoryAnalyzer.extract_root_domain("https://www.example.com/test") == "example.com"
    assert WebHistoryAnalyzer.extract_root_domain("http://sub.domain.ac.in:8080/") == "sub.domain.ac.in"
    assert WebHistoryAnalyzer.extract_root_domain("google.com") == "google.com"


def test_site_type_classification():
    # Academic
    acad = WebHistoryAnalyzer._classify_site_type("https://pmec.ac.in", {"html_content": "college department syllabus"})
    assert "Academic" in acad

    # E-Commerce
    ecom = WebHistoryAnalyzer._classify_site_type("https://shop.example.com", {"html_content": "shopping-cart checkout add to cart"})
    assert "E-Commerce" in ecom

    # WordPress CMS
    wp = WebHistoryAnalyzer._classify_site_type("https://blog.example.com", {"html_content": "/wp-content/themes/twentytwenty"})
    assert "WordPress" in wp


def test_admin_maturity_profiling():
    # Hardened admin context
    hardened_context = {
        "is_https": True,
        "hsts_present": True,
        "csp_present": True,
        "x_frame_options": "DENY",
        "x_content_type_options": "nosniff",
        "security_txt_found": True,
        "server_header": None,
        "powered_by_header": None,
    }
    reg = DomainRegistrationInfo(domain="test.com", dnssec_enabled=True)
    prof = WebHistoryAnalyzer._profile_admin(hardened_context, reg)
    assert prof.score >= 80
    assert "DevSecOps" in prof.tier or "Security-Conscious" in prof.tier
    assert len(prof.strengths) >= 4

    # Novice admin context (leaking banners, HTTP, no headers)
    novice_context = {
        "is_https": False,
        "hsts_present": False,
        "csp_present": False,
        "server_header": "Apache/2.4.41 (Ubuntu)",
        "powered_by_header": "PHP/7.4.3",
    }
    novice_prof = WebHistoryAnalyzer._profile_admin(novice_context, reg)
    assert novice_prof.score < 50
    assert "Novice" in novice_prof.tier or "Intermediate" in novice_prof.tier
    assert len(novice_prof.blind_spots) >= 2


def test_historical_incident_detection():
    # Defaced HTML context
    defaced_context = {
        "html_content": "<html><body><h1>Hacked By Cyb3r_Gh0st</h1></body></html>",
        "git_exposed": False,
        "env_exposed": False,
    }
    audit = WebHistoryAnalyzer._audit_historical_incidents(defaced_context)
    assert audit.has_past_incident_indicators is True
    assert "hacked by" in audit.past_incident_markers[0].lower()

    # Clean context
    clean_context = {
        "html_content": "<html><body><h1>Welcome to our corporate portal</h1></body></html>",
        "git_exposed": False,
        "env_exposed": False,
    }
    clean_audit = WebHistoryAnalyzer._audit_historical_incidents(clean_context)
    assert clean_audit.has_past_incident_indicators is False
    assert clean_audit.defacement_risk_level == "Low"


def test_site_footprint_estimation():
    html_sample = """
    <html>
    <head>
        <link rel="stylesheet" href="/style1.css">
        <link rel="stylesheet" href="/style2.css">
        <script src="/app.js"></script>
        <script src="/vendor.js"></script>
    </head>
    <body>
        <img src="/img1.png">
        <img src="/img2.jpg">
        <a href="/p1">P1</a>
        <a href="/p2">P2</a>
        <a href="/p3">P3</a>
    </body>
    </html>
    """
    foot = WebHistoryAnalyzer._estimate_data_footprint("https://example.com", {"html_content": html_sample})
    assert foot.home_page_weight_kb > 0
    assert foot.sampled_asset_weight_mb > 0
    assert "Lightweight" in foot.estimated_total_site_size or "Medium" in foot.estimated_total_site_size


def test_full_web_history_analyzer():
    sample_context = {
        "html_content": "<html><head><title>PMEC Campus</title></head><body>Welcome to college department</body></html>",
        "is_https": True,
        "hsts_present": True,
    }
    report = WebHistoryAnalyzer.analyze("https://pmec.ac.in", sample_context)
    assert report.domain == "pmec.ac.in"
    assert "Academic" in report.site_type
    assert report.admin_profile.score > 0
    assert len(report.timeline) > 0
    assert isinstance(report.timeline[0], YearlyMilestone)
    assert report.to_dict()["domain"] == "pmec.ac.in"
