"""
CHARLO Testing Agent - Webhook Alerting & Continuous Watchdog Dispatcher.
Dispatches enterprise security alerts to Slack, Discord, Microsoft Teams,
or custom SIEM/DevOps webhook endpoints upon scan completion or quality gate breach.
"""

import json
import urllib.request
import urllib.error
import ssl
from typing import Dict, Any, Optional
from datetime import datetime
from ..core.models import ScanResult, Severity, CheckStatus


class WebhookNotifier:
    """Dispatches formatted security alert cards to team collaboration channels."""

    TIMEOUT_SEC = 4.0

    @classmethod
    def detect_channel_type(cls, webhook_url: str) -> str:
        """Determines whether the URL is Slack, Discord, Teams, or Generic."""
        url_lower = webhook_url.lower()
        if "hooks.slack.com" in url_lower:
            return "slack"
        elif "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
            return "discord"
        elif "webhook.office.com" in url_lower or "outlook.office.com" in url_lower:
            return "teams"
        return "generic"

    @classmethod
    def dispatch_alert(
        cls,
        webhook_url: str,
        result: ScanResult,
        custom_title: Optional[str] = None
    ) -> Dict[str, Any]:
        """Formats and sends alert payload to the target webhook."""
        if not webhook_url:
            return {"success": False, "status_code": None, "message": "No webhook URL provided."}

        channel_type = cls.detect_channel_type(webhook_url)
        target_name = result.target.display_name if result.target else "Target"
        score = result.metrics.security_score if result.metrics else 0.0

        # Tally severities
        crit_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL and f.status != CheckStatus.PASSED)
        high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH and f.status != CheckStatus.PASSED)
        med_count = sum(1 for f in result.findings if f.severity == Severity.MEDIUM and f.status != CheckStatus.PASSED)
        total_defects = crit_count + high_count + med_count

        color_hex = "#ff2a44" if (crit_count > 0 or high_count > 0) else "#ffb800" if med_count > 0 else "#00ff9d"
        color_int = 16722500 if (crit_count > 0 or high_count > 0) else 16758784 if med_count > 0 else 65437

        title = custom_title or f"🛡️ CHARLO Security Audit: {target_name}"

        # Construct platform-specific payload
        if channel_type == "slack":
            payload = {
                "attachments": [
                    {
                        "color": color_hex,
                        "title": title,
                        "text": f"*Security Score:* `{score:.1f}%` | *Status:* `{'CRITICAL' if crit_count > 0 else 'DEFECTS FOUND' if total_defects > 0 else 'SECURE'}`",
                        "fields": [
                            {"title": "Target", "value": target_name, "short": True},
                            {"title": "Total Defects", "value": str(total_defects), "short": True},
                            {"title": "Critical / High", "value": f"{crit_count} Critical, {high_count} High", "short": True},
                            {"title": "Audit Level", "value": result.level.value.upper(), "short": True}
                        ],
                        "footer": "CHARLO Testing Agent AI Security Workstation",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
        elif channel_type == "discord":
            payload = {
                "embeds": [
                    {
                        "title": title,
                        "color": color_int,
                        "description": f"**Security Score:** `{score:.1f}%`\n**Audit Level:** `{result.level.value.upper()}`",
                        "fields": [
                            {"name": "Target", "value": f"`{target_name}`", "inline": True},
                            {"name": "Critical Defects", "value": f"**{crit_count}**", "inline": True},
                            {"name": "High Defects", "value": f"**{high_count}**", "inline": True},
                            {"name": "Medium Defects", "value": str(med_count), "inline": True},
                            {"name": "Total Findings", "value": str(len(result.findings)), "inline": True}
                        ],
                        "footer": {"text": "CHARLO Testing Agent • AI-Powered Security Lab"},
                        "timestamp": datetime.now().isoformat()
                    }
                ]
            }
        elif channel_type == "teams":
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color_hex.replace("#", ""),
                "summary": title,
                "sections": [
                    {
                        "activityTitle": title,
                        "activitySubtitle": f"Security Score: {score:.1f}%",
                        "facts": [
                            {"name": "Target:", "value": target_name},
                            {"name": "Total Defects:", "value": str(total_defects)},
                            {"name": "Critical / High:", "value": f"{crit_count} / {high_count}"},
                            {"name": "Audit Level:", "value": result.level.value.upper()}
                        ],
                        "markdown": True
                    }
                ]
            }
        else:
            # Generic Webhook
            payload = {
                "event": "charlo_scan_completed",
                "timestamp": datetime.now().isoformat(),
                "target": target_name,
                "security_score": score,
                "defects_summary": {
                    "critical": crit_count,
                    "high": high_count,
                    "medium": med_count,
                    "total": total_defects
                },
                "findings_count": len(result.findings)
            }

        # Send HTTP POST
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "CHARLO-Webhook-Dispatcher/2.4"}
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=cls.TIMEOUT_SEC, context=ctx) as resp:
                code = getattr(resp, "status", None)
                if code is None or not isinstance(code, int):
                    code = resp.getcode() if hasattr(resp, "getcode") else 200
                return {
                    "success": code in (200, 201, 202, 204),
                    "status_code": code,
                    "message": f"Alert successfully dispatched to {channel_type.upper()} (HTTP {code})."
                }
        except urllib.error.HTTPError as e:
            return {
                "success": False,
                "status_code": e.code,
                "message": f"Webhook returned HTTP error {e.code}: {e.reason}"
            }
        except Exception as e:
            return {
                "success": False,
                "status_code": None,
                "message": f"Webhook dispatch failed: {str(e)}"
            }
