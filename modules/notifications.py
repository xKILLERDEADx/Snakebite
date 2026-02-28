import aiohttp
import json
from datetime import datetime
from modules.core import console

async def send_telegram(token, chat_id, message):
    """Send alert via Telegram Bot API."""
    if not token or not chat_id:
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return True
                else:
                    console.print(f"[dim]Telegram API error: {resp.status}[/dim]")
                    return False
    except Exception as e:
        console.print(f"[dim]Telegram send failed: {e}[/dim]")
        return False


async def send_discord(webhook_url, title, description, color=0xFF0000, fields=None):
    """Send alert via Discord Webhook (embed)."""
    if not webhook_url:
        return False
    try:
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "Snakebite v2.0 Security Scanner"}
        }
        if fields:
            embed["fields"] = fields

        payload = {"embeds": [embed]}
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    headers={"Content-Type": "application/json"}) as resp:
                if resp.status in [200, 204]:
                    return True
                else:
                    console.print(f"[dim]Discord webhook error: {resp.status}[/dim]")
                    return False
    except Exception as e:
        console.print(f"[dim]Discord send failed: {e}[/dim]")
        return False


SEVERITY_COLORS = {
    "Critical": 0xFF0000,
    "High": 0xFF6600,
    "Medium": 0xFFCC00,
    "Low": 0x00CCFF,
    "Info": 0x808080,
}

SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Info": "⚪",
}


async def alert_vulnerability(vuln_data, config):
    """Format and send vulnerability alert to configured channels.

    vuln_data should be a dict with keys:
        type: str (e.g., "SQL Injection", "XSS")
        url: str
        severity: str (Critical/High/Medium/Low/Info)
        payload: str (optional)
        evidence: str (optional)
        cve: str (optional)
        exploit_cmd: str (optional)
    """
    vuln_type = vuln_data.get("type", "Unknown")
    url = vuln_data.get("url", "N/A")
    severity = vuln_data.get("severity", "Medium")
    payload = vuln_data.get("payload", "")
    evidence = vuln_data.get("evidence", "")
    cve = vuln_data.get("cve", "")
    exploit_cmd = vuln_data.get("exploit_cmd", "")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")

    telegram_token = getattr(config, 'telegram_token', None)
    telegram_chat = getattr(config, 'telegram_chat', None)
    discord_webhook = getattr(config, 'discord_webhook', None)

    if telegram_token and telegram_chat:
        msg = f"{emoji} <b>SNAKEBITE ALERT</b>\n\n"
        msg += f"<b>Type:</b> {vuln_type}\n"
        msg += f"<b>Severity:</b> {severity}\n"
        msg += f"<b>URL:</b> <code>{url}</code>\n"
        if payload:
            msg += f"<b>Payload:</b> <code>{payload[:200]}</code>\n"
        if evidence:
            msg += f"<b>Evidence:</b> {evidence[:200]}\n"
        if cve:
            msg += f"<b>CVE:</b> {cve}\n"
        if exploit_cmd:
            msg += f"\n<b>Exploit:</b>\n<code>{exploit_cmd[:300]}</code>"
        msg += f"\n\n🐍 Snakebite v2.0"

        await send_telegram(telegram_token, telegram_chat, msg)

    if discord_webhook:
        fields = [
            {"name": "Target URL", "value": f"`{url}`", "inline": False},
        ]
        if payload:
            fields.append({"name": "Payload", "value": f"`{payload[:200]}`", "inline": False})
        if evidence:
            fields.append({"name": "Evidence", "value": evidence[:200], "inline": True})
        if cve:
            fields.append({"name": "CVE", "value": cve, "inline": True})
        if exploit_cmd:
            fields.append({"name": "Exploit Command", "value": f"```{exploit_cmd[:300]}```", "inline": False})

        color = SEVERITY_COLORS.get(severity, 0x808080)
        title = f"{emoji} {severity}: {vuln_type}"
        description = f"Vulnerability discovered on target"

        await send_discord(discord_webhook, title, description, color, fields)


async def send_scan_summary(config, target, total_vulns, severity_counts, scan_duration):
    """Send scan completion summary to notification channels."""
    telegram_token = getattr(config, 'telegram_token', None)
    telegram_chat = getattr(config, 'telegram_chat', None)
    discord_webhook = getattr(config, 'discord_webhook', None)

    if telegram_token and telegram_chat:
        msg = "📊 <b>SNAKEBITE SCAN COMPLETE</b>\n\n"
        msg += f"<b>Target:</b> {target}\n"
        msg += f"<b>Duration:</b> {scan_duration}\n"
        msg += f"<b>Total Vulnerabilities:</b> {total_vulns}\n\n"
        msg += f"🔴 Critical: {severity_counts.get('Critical', 0)}\n"
        msg += f"🟠 High: {severity_counts.get('High', 0)}\n"
        msg += f"🟡 Medium: {severity_counts.get('Medium', 0)}\n"
        msg += f"🔵 Low: {severity_counts.get('Low', 0)}\n"
        msg += f"⚪ Info: {severity_counts.get('Info', 0)}\n"
        msg += f"\n🐍 Snakebite v2.0"

        await send_telegram(telegram_token, telegram_chat, msg)

    if discord_webhook:
        fields = [
            {"name": "🔴 Critical", "value": str(severity_counts.get('Critical', 0)), "inline": True},
            {"name": "🟠 High", "value": str(severity_counts.get('High', 0)), "inline": True},
            {"name": "🟡 Medium", "value": str(severity_counts.get('Medium', 0)), "inline": True},
            {"name": "🔵 Low", "value": str(severity_counts.get('Low', 0)), "inline": True},
            {"name": "⏱ Duration", "value": scan_duration, "inline": True},
            {"name": "Total", "value": str(total_vulns), "inline": True},
        ]
        color = 0xFF0000 if severity_counts.get('Critical', 0) > 0 else 0x00FF00
        await send_discord(discord_webhook,
                           "📊 Scan Complete",
                           f"Target: `{target}`",
                           color, fields)
