import os, json, logging, html
from typing import Dict, List, Optional
from datetime import datetime, timezone
from analyzers.base import Finding

logger = logging.getLogger(__name__)

DISCORD_COLORS = {
    "Critical": 15158332,
    "High": 15105570,
    "Medium": 15844367,
    "Low": 3066993,
    "Info": 1752220,
    "Gas": 10181046,
}

SLACK_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#3498db",
    "Info": "#95a5a6",
    "Gas": "#9b59b6",
}


def _severity_emoji(sev: str) -> str:
    return {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🔵",
        "Info": "ℹ️",
        "Gas": "⛽",
    }.get(sev, "⚪")


def _truncate(text: str, maxlen: int = 500) -> str:
    return text[:maxlen] + "..." if len(text) > maxlen else text


# ──────────────────────────────────────────
# Discord
# ──────────────────────────────────────────

def send_discord_webhook(
    webhook_url: str,
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
):
    if not webhook_url:
        return
    payload = _build_discord_payload(findings, project, summary)
    if payload and "embeds" in payload:
        _post_webhook(webhook_url, payload)


def _build_discord_payload(
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
) -> Dict:
    if not findings:
        return {"embeds": [{"title": "✅ No vulnerabilities found", "color": 3066993}]}

    embeds = []
    color = DISCORD_COLORS.get(findings[0].severity, 1752220)

    embed = {
        "title": f"Smart Contract Audit Report{' - ' + project if project else ''}",
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }

    if summary:
        total = summary.get("total", len(findings))
        embed["description"] = (
            f"**{total}** findings: "
            + " ".join(
                f"{_severity_emoji(k)} **{k}**: {v}"
                for k, v in summary.get("severity", {}).items()
            )
        )

    details = []
    for f in findings[:10]:
        details.append(
            f"{_severity_emoji(f.severity)} **[{f.severity}]** {_truncate(f.description, 200)}\n"
            f"└ {f.file}:{f.line} | {f.category}"
        )

    if len(findings) > 10:
        details.append(f"\n... and {len(findings) - 10} more findings")

    embed["fields"] = [
        {"name": "Findings", "value": "\n\n".join(details), "inline": False}
    ]
    embed["footer"] = {"text": "Smart Contract Auditor"}

    embeds.append(embed)

    return {"embeds": embeds}


# ──────────────────────────────────────────
# Slack
# ──────────────────────────────────────────

def send_slack_webhook(
    webhook_url: str,
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
):
    if not webhook_url:
        return
    payload = _build_slack_payload(findings, project, summary)
    if payload:
        _post_webhook(webhook_url, payload)


def _build_slack_payload(
    findings: List[Finding],
    project: str = "",
    summary: Optional[Dict] = None,
) -> Dict:
    if not findings:
        return {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "✅ No vulnerabilities found"}}]}

    blocks = []

    title = f"*Smart Contract Audit Report{' - ' + project if project else ''}*"
    blocks.append({"type": "header", "text": {"type": "plain_text", "text": f"Audit Report {project}" if project else "Audit Report", "emoji": True}})

    if summary:
        sev_parts = []
        for k, v in summary.get("severity", {}).items():
            color = SLACK_COLORS.get(k, "#95a5a6")
            sev_parts.append(f"*{k}*: {v}")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{summary.get('total', len(findings))}* findings | {' · '.join(sev_parts)}"},
        })

    blocks.append({"type": "divider"})

    for f in findings[:10]:
        color = SLACK_COLORS.get(f.severity, "#95a5a6")
        emoji = _severity_emoji(f.severity)
        text = (
            f"{emoji} *[{f.severity}]* {_truncate(f.description, 300)}\n"
            f"`{f.file}:{f.line}` • {f.category}"
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        })

    if len(findings) > 10:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"... and {len(findings) - 10} more findings"},
        })

    return {"text": f"Audit Report: {len(findings)} findings", "blocks": blocks}


# ──────────────────────────────────────────
# Common
# ──────────────────────────────────────────

def _post_webhook(url: str, payload: Dict):
    try:
        import requests
        resp = requests.post(url, json=payload, timeout=15)
        if resp.status_code not in (200, 204):
            logger.warning(f"Webhook returned {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"Webhook error: {e}")


def send_report(
    webhook_url: str,
    findings: List[Finding],
    webhook_type: str = "discord",
    project: str = "",
    summary: Optional[Dict] = None,
):
    if webhook_type == "slack":
        send_slack_webhook(webhook_url, findings, project, summary)
    else:
        send_discord_webhook(webhook_url, findings, project, summary)
