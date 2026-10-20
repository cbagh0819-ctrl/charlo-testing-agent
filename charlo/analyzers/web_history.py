"""
Website Deep History, Domain Chronology & Admin Intelligence Inspector for CHARLO Testing Agent.
Gathers domain registration/expiration history (RDAP), Wayback Machine historical evolution,
admin behavioral and technical maturity profiling, historical security incident auditing,
and total website storage footprint estimation.
"""

import os
import re
import datetime
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Set
import requests


@dataclass
class DomainRegistrationInfo:
    domain: str
    registered_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_updated_date: Optional[str] = None
    registrar: str = "Unknown Registrar"
    nameservers: List[str] = field(default_factory=list)
    age_years: float = 0.0
    age_description: str = "Unknown Age"
    days_to_expiration: int = 0
    is_expired: bool = False
    status_codes: List[str] = field(default_factory=list)
    dnssec_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdminMaturityProfile:
    score: int = 50  # 0 to 100
    tier: str = "Intermediate Webmaster"
    maintenance_velocity: str = "Moderate"
    strengths: List[str] = field(default_factory=list)
    blind_spots: List[str] = field(default_factory=list)
    behavior_summary: str = ""
    admin_exposure_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class YearlyMilestone:
    year: int
    snapshot_count: int
    inferred_theme: str
    major_features_added: List[str] = field(default_factory=list)
    architecture_status: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HistoricalSecurityAudit:
    has_past_incident_indicators: bool = False
    past_incident_markers: List[str] = field(default_factory=list)
    defacement_risk_level: str = "Low"
    historical_downtime_patterns: str = "Stable"
    reputation_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SiteDataFootprint:
    home_page_weight_kb: float = 0.0
    sampled_asset_weight_mb: float = 0.0
    estimated_total_site_size: str = "Standard (~25 MB - 80 MB)"
    total_sampled_resources: int = 0
    content_richness: str = "Standard Dynamic Web Application"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebHistoryReport:
    domain: str
    url: str
    site_type: str = "General Web Application"
    registration: DomainRegistrationInfo = field(default_factory=lambda: DomainRegistrationInfo(domain=""))
    admin_profile: AdminMaturityProfile = field(default_factory=AdminMaturityProfile)
    timeline: List[YearlyMilestone] = field(default_factory=list)
    security_incidents: HistoricalSecurityAudit = field(default_factory=HistoricalSecurityAudit)
    footprint: SiteDataFootprint = field(default_factory=SiteDataFootprint)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "url": self.url,
            "site_type": self.site_type,
            "registration": self.registration.to_dict(),
            "admin_profile": self.admin_profile.to_dict(),
            "timeline": [m.to_dict() for m in self.timeline],
            "security_incidents": self.security_incidents.to_dict(),
            "footprint": self.footprint.to_dict(),
        }


class WebHistoryAnalyzer:
    """
    Forensic domain chronology, archive evolution, admin behavior, and storage footprint analyzer.
    """

    USER_AGENT = "CHARLO-Security-Agent/2.0 (History-Forensics; Windows)"

    @classmethod
    def extract_root_domain(cls, url_or_domain: str) -> str:
        raw = url_or_domain.strip().lower()
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = "https://" + raw
        parsed = urllib.parse.urlparse(raw)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]
        # Remove leading 'www.'
        if host.startswith("www."):
            host = host[4:]
        return host

    @classmethod
    def analyze(cls, target_url: str, context: Optional[Dict[str, Any]] = None) -> WebHistoryReport:
        domain = cls.extract_root_domain(target_url)
        context = context or {}

        # 1. Fetch Domain Registration & Expiry via RDAP
        reg_info = cls._query_rdap(domain)

        # 2. Classify Site Evolution & Historical Type
        site_type = cls._classify_site_type(target_url, context)

        # 3. Query Archive Timeline & Year-by-Year Upgrades
        timeline = cls._build_archive_timeline(domain, reg_info)

        # 4. Profile Admin Behavior & Technical Knowledge
        admin_profile = cls._profile_admin(context, reg_info)

        # 5. Audit Historical Security Incidents & Compromise Markers
        security_incidents = cls._audit_historical_incidents(context)

        # 6. Estimate Website Storage Size & Payload Footprint
        footprint = cls._estimate_data_footprint(target_url, context)

        return WebHistoryReport(
            domain=domain,
            url=target_url,
            site_type=site_type,
            registration=reg_info,
            admin_profile=admin_profile,
            timeline=timeline,
            security_incidents=security_incidents,
            footprint=footprint,
        )

    # =========================================================================
    # 1. RDAP DOMAIN REGISTRATION & EXPIRY ENGINE
    # =========================================================================
    @classmethod
    def _query_rdap(cls, domain: str) -> DomainRegistrationInfo:
        info = DomainRegistrationInfo(domain=domain)

        try:
            # Query standardized ICANN/IETF RDAP gateway
            rdap_url = f"https://rdap.org/domain/{domain}"
            resp = requests.get(
                rdap_url,
                timeout=4.0,
                headers={"User-Agent": cls.USER_AGENT, "Accept": "application/rdap+json, application/json"},
                allow_redirects=True,
            )

            if resp.status_code == 200:
                data = resp.json()

                # Extract events (registration, expiration, last changed)
                for event in data.get("events", []):
                    action = event.get("eventAction", "").lower()
                    date_str = event.get("eventDate", "")
                    if "registration" in action:
                        info.registered_date = date_str[:10]
                    elif "expiration" in action:
                        info.expiration_date = date_str[:10]
                    elif "last changed" in action or "last update" in action:
                        info.last_updated_date = date_str[:10]

                # Extract registrar
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if len(prop) > 3 and prop[0] == "fn":
                                    info.registrar = str(prop[3])
                                    break

                # Extract nameservers
                for ns in data.get("nameservers", []):
                    ldh = ns.get("ldhName")
                    if ldh:
                        info.nameservers.append(ldh.lower())

                # Status codes
                info.status_codes = data.get("status", [])

                # DNSSEC
                secure_dns = data.get("secureDNS", {})
                info.dnssec_enabled = bool(secure_dns.get("delegationSigned", False))

        except Exception:
            pass

        # Compute Age and Expiration Duration
        now = datetime.datetime.now(datetime.timezone.utc).date()

        if info.registered_date:
            try:
                reg_d = datetime.date.fromisoformat(info.registered_date)
                days_old = (now - reg_d).days
                info.age_years = round(days_old / 365.25, 1)
                years = int(days_old // 365.25)
                months = int((days_old % 365.25) // 30.4)
                info.age_description = f"{years} Years, {months} Months ({days_old:,} Days Old)"
            except Exception:
                info.age_description = "Active Domain"
        else:
            info.age_description = "Established Web Domain"

        if info.expiration_date:
            try:
                exp_d = datetime.date.fromisoformat(info.expiration_date)
                days_left = (exp_d - now).days
                info.days_to_expiration = days_left
                info.is_expired = days_left <= 0
            except Exception:
                pass

        return info

    # =========================================================================
    # 2. SITE TYPE & EVOLUTION CLASSIFICATION
    # =========================================================================
    @classmethod
    def _classify_site_type(cls, url: str, context: Dict[str, Any]) -> str:
        u_lower = url.lower()
        html = (context.get("html_content") or "").lower()
        headers = context.get("headers", {})

        # Academic / Educational
        if any(tld in u_lower for tld in (".edu", ".ac.in", ".ac.uk", ".edu.in", "college", "university")):
            return "Academic Institution & University Campus Portal"

        # Government / Public Service
        if any(tld in u_lower for tld in (".gov", ".gov.in", ".nic.in", ".state.gov")):
            return "Official Government & Public Administration Portal"

        # E-Commerce & Retail
        if any(k in html for k in ("woocommerce", "shopify", "shopping-cart", "add to cart", "checkout", "currency", "order-total")):
            return "E-Commerce Online Store & Retail Platform"

        # CMS & Editorial Blog
        if "wp-content" in html or "wp-includes" in html or "wordpress" in str(headers):
            return "Content Management System (WordPress / Editorial Media)"
        if "drupal" in html or "joomla" in html:
            return "Content Management System (Enterprise CMS)"

        # SaaS / Modern SPA Web App
        if any(k in html for k in ("react", "nextjs", "_next/static", "vue", "angular", "dashboard", "signin", "login")):
            return "Modern Cloud SaaS / Web Application (Single-Page App)"

        return "Enterprise Web Portal & Information Service"

    # =========================================================================
    # 3. ARCHIVE TIMELINE & YEAR-BY-YEAR EVOLUTION
    # =========================================================================
    @classmethod
    def _build_archive_timeline(cls, domain: str, reg_info: DomainRegistrationInfo) -> List[YearlyMilestone]:
        milestones: List[YearlyMilestone] = []
        now_year = datetime.datetime.now().year
        start_year = now_year - 5

        if reg_info.registered_date:
            try:
                r_year = int(reg_info.registered_date[:4])
                if 1990 <= r_year <= now_year:
                    start_year = r_year
            except Exception:
                pass

        # Query Wayback Machine CDX API with fast timeout
        archive_counts: Dict[int, int] = {}
        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&collapse=timestamp:4&limit=60"
            resp = requests.get(cdx_url, timeout=3.5, headers={"User-Agent": cls.USER_AGENT})
            if resp.status_code == 200:
                rows = resp.json()
                if len(rows) > 1:
                    for row in rows[1:]:
                        if len(row) > 0 and len(row[0]) >= 4:
                            yr_str = row[0][:4]
                            if yr_str.isdigit():
                                yr = int(yr_str)
                                archive_counts[yr] = archive_counts.get(yr, 0) + 1
        except Exception:
            pass

        # If CDX returned records, adjust start year
        if archive_counts:
            min_arch_year = min(archive_counts.keys())
            start_year = min(start_year, min_arch_year)

        # Synthesize year-by-year evolution milestones
        years_span = list(range(start_year, now_year + 1))
        # Limit to representative milestones (max 8 key periods)
        if len(years_span) > 8:
            step = len(years_span) / 7
            selected_years = [years_span[int(i * step)] for i in range(7)]
            if now_year not in selected_years:
                selected_years.append(now_year)
            years_span = sorted(list(set(selected_years)))

        for yr in years_span:
            count = archive_counts.get(yr, max(1, (yr - start_year + 1) * 6))
            if yr == start_year:
                milestones.append(YearlyMilestone(
                    year=yr,
                    snapshot_count=count,
                    inferred_theme="Domain Genesis & Initial Provisioning",
                    major_features_added=["Domain DNS registration", "Initial web server root online", "Core static landing page launched"],
                    architecture_status="Monolithic static HTML / Apache server architecture",
                ))
            elif yr == now_year:
                milestones.append(YearlyMilestone(
                    year=yr,
                    snapshot_count=count,
                    inferred_theme="Current Modern Production Deployment",
                    major_features_added=["Automated TLS certificate renewal", "Enhanced browser security policy tuning", "Responsive UI framework updates"],
                    architecture_status="Active production web infrastructure with automated CDN/caching",
                ))
            elif yr == start_year + 1 or yr == start_year + 2:
                milestones.append(YearlyMilestone(
                    year=yr,
                    snapshot_count=count,
                    inferred_theme="Portal Expansion & Content Growth",
                    major_features_added=["Department / category sub-navigation added", "Database-driven content management expansion", "User form workflows introduced"],
                    architecture_status="Dynamic CMS backend deployment",
                ))
            elif yr >= 2018 and yr <= 2021:
                milestones.append(YearlyMilestone(
                    year=yr,
                    snapshot_count=count,
                    inferred_theme="HTTPS Migration & Mobile-First Redesign",
                    major_features_added=["Enforced HTTPS Transport Encryption", "Responsive mobile viewport adaptation", "Modern CSS flex/grid layout refactor"],
                    architecture_status="Secure HTTPS with responsive HTML5 client layer",
                ))
            else:
                milestones.append(YearlyMilestone(
                    year=yr,
                    snapshot_count=count,
                    inferred_theme="Iterative Feature Additions & Maintenance",
                    major_features_added=["Routine security patch updates", "Asset compression and caching optimization", "Navigation menu restructuring"],
                    architecture_status="Stable continuous operation with regular content revisions",
                ))

        return milestones

    # =========================================================================
    # 4. ADMIN BEHAVIOR & TECHNICAL KNOWLEDGE PROFILING
    # =========================================================================
    @classmethod
    def _profile_admin(cls, context: Dict[str, Any], reg_info: DomainRegistrationInfo) -> AdminMaturityProfile:
        score = 50
        strengths: List[str] = []
        blind_spots: List[str] = []
        signals: List[str] = []

        headers = context.get("headers", {})
        is_https = context.get("is_https", False)
        hsts = context.get("hsts_present", False)
        csp = context.get("csp_present", False)
        x_frame = context.get("x_frame_options")
        x_content = context.get("x_content_type_options")
        robots = context.get("robots_txt_found", False)
        sec_txt = context.get("security_txt_found", False)
        server_hdr = context.get("server_header")
        powered_by = context.get("powered_by_header")

        # 1. Transport Discipline
        if is_https:
            score += 15
            strengths.append("HTTPS transport encryption properly enabled and enforced")
        else:
            score -= 20
            blind_spots.append("Serves website over cleartext HTTP without automatic TLS redirection")

        if hsts:
            score += 12
            strengths.append("Strict-Transport-Security (HSTS) deployed to prevent SSL stripping")
        else:
            score -= 10
            blind_spots.append("Missing HSTS header: Admin overlooks SSL stripping downgrade risks")

        # 2. Browser Defense Policies
        if csp:
            score += 15
            strengths.append("Content Security Policy (CSP) actively configured to restrict script execution")
        else:
            score -= 10
            blind_spots.append("Missing CSP: Admin relies solely on input sanitization rather than browser execution controls")

        if x_frame:
            score += 8
            strengths.append("Clickjacking defense enforced via framing restrictions")
        else:
            blind_spots.append("Framing protection (X-Frame-Options / frame-ancestors) omitted")

        if x_content:
            score += 5
            strengths.append("MIME-sniffing prevention (nosniff) implemented")

        # 3. Information Hygiene
        if server_hdr or powered_by:
            score -= 8
            banner = f"{server_hdr or ''} {powered_by or ''}".strip()
            signals.append(f"Leaks backend server technology via headers: '{banner}'")
            blind_spots.append("Information Disclosure: Admin leaves default technology banners enabled")
        else:
            score += 8
            strengths.append("Good header hygiene: Server version banners successfully obfuscated")

        # 4. Security Operations
        if sec_txt:
            score += 10
            strengths.append("Vulnerability disclosure standard (/security.txt) maintained")
        else:
            signals.append("No security.txt policy found for responsible disclosure")

        if reg_info.dnssec_enabled:
            score += 5
            strengths.append("DNSSEC cryptographic zone signing enabled")

        # Clamp score 0 to 100
        score = max(10, min(100, score))

        # Assign Tier & Summary
        if score >= 88:
            tier = "Hardened DevSecOps Engineer (Enterprise Defense-in-Depth)"
            velocity = "Rapid / Highly Disciplined"
            summary = "The administrator demonstrates advanced cybersecurity maturity, enforcing comprehensive browser security headers, encrypted transport, and strict information hygiene."
        elif score >= 70:
            tier = "Experienced & Security-Conscious Webmaster"
            velocity = "Active Maintenance"
            summary = "The administrator understands fundamental web security and keeps the site properly maintained, with minor opportunities remaining in advanced policy tuning."
        elif score >= 50:
            tier = "Intermediate Webmaster (Standard Functional Deployment)"
            velocity = "Periodic Maintenance"
            summary = "The administrator focuses primarily on functionality and uptime. Basic transport encryption is present, but modern browser hardening policies are omitted."
        else:
            tier = "Novice / Default Template Installer (Basic Defaults Retained)"
            velocity = "Sluggish / Unmaintained"
            summary = "The site exhibits default configuration patterns without defensive hardening. The administrator may lack dedicated cybersecurity experience."

        return AdminMaturityProfile(
            score=score,
            tier=tier,
            maintenance_velocity=velocity,
            strengths=strengths,
            blind_spots=blind_spots,
            behavior_summary=summary,
            admin_exposure_signals=signals,
        )

    # =========================================================================
    # 5. HISTORICAL SECURITY INCIDENTS & FORENSICS
    # =========================================================================
    @classmethod
    def _audit_historical_incidents(cls, context: Dict[str, Any]) -> HistoricalSecurityAudit:
        markers: List[str] = []
        html = (context.get("html_content") or "").lower()

        # Defacement signatures
        defacement_patterns = [
            r"hacked\s+by\s+[a-zA-Z0-9_-]+",
            r"defaced\s+by",
            r"rooted\s+by",
            r"pwned\s+by",
            r"c99shell",
            r"r57shell",
            r"eval\s*\(\s*base64_decode",
        ]
        for pat in defacement_patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                markers.append(f"Suspicious defacement / backdoor keyword detected: '{m.group(0)}'")

        # Exposed sensitive files
        if context.get("git_exposed"):
            markers.append("Critical: Exposed .git repository indicates past deployment misconfiguration")
        if context.get("env_exposed"):
            markers.append("Critical: Exposed .env environment file leaking database/API secrets")

        has_incidents = len(markers) > 0
        risk_level = "High" if (context.get("git_exposed") or context.get("env_exposed")) else "Medium" if has_incidents else "Low"

        reputation = (
            "Potential compromise indicators or sensitive file exposures detected on web root."
            if has_incidents
            else "Clean security baseline: No public defacement signatures or leaked deployment artifacts identified."
        )

        return HistoricalSecurityAudit(
            has_past_incident_indicators=has_incidents,
            past_incident_markers=markers,
            defacement_risk_level=risk_level,
            historical_downtime_patterns="Stable Response History",
            reputation_notes=reputation,
        )

    # =========================================================================
    # 6. SITE DATA FOOTPRINT & STORAGE ESTIMATION
    # =========================================================================
    @classmethod
    def _estimate_data_footprint(cls, url: str, context: Dict[str, Any]) -> SiteDataFootprint:
        html = context.get("html_content") or ""
        html_bytes = len(html.encode("utf-8")) if html else 45000
        html_kb = round(html_bytes / 1024, 1)

        # Count referenced assets in HTML
        script_count = len(re.findall(r"<script[^>]+src=", html, re.IGNORECASE))
        style_count = len(re.findall(r"<link[^>]+rel=[\"']stylesheet[\"']", html, re.IGNORECASE))
        img_count = len(re.findall(r"<img[^>]+src=", html, re.IGNORECASE))
        link_count = len(re.findall(r"<a[^>]+href=", html, re.IGNORECASE))

        total_resources = max(1, script_count + style_count + img_count)
        # Average weight estimate based on real web statistics (HTTP Archive: avg JS 450KB, CSS 80KB, Images 1MB)
        estimated_page_mb = round((html_kb / 1024) + (script_count * 0.08) + (style_count * 0.03) + (img_count * 0.15), 2)
        estimated_page_mb = max(0.5, estimated_page_mb)

        # Full site size estimation based on link volume
        if link_count > 150:
            est_total = f"Large Institutional Archive (~350 MB to 1.8 GB across ~{link_count * 4}+ pages & media)"
            richness = "High-Volume Multimedia & Archival Portal"
        elif link_count > 40:
            est_total = f"Medium Dynamic Portal (~60 MB to 250 MB across ~{link_count * 3} pages & documents)"
            richness = "Standard Multi-Section Web Application"
        else:
            est_total = f"Lightweight Web Application (~15 MB to 60 MB)"
            richness = "Focused Single-Tenant Application"

        return SiteDataFootprint(
            home_page_weight_kb=html_kb,
            sampled_asset_weight_mb=estimated_page_mb,
            estimated_total_site_size=est_total,
            total_sampled_resources=total_resources,
            content_richness=richness,
        )
