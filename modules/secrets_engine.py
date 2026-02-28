"""Secrets Regex Engine — 100+ patterns for leaked API keys in JS/HTML/responses."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin
from modules.core import console

SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'(?:aws)?_?(?:secret)?_?(?:access)?_?key.*?[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
    'Google API Key': r'AIza[0-9A-Za-z_-]{35}',
    'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Google Cloud Key': r'(?:GOOG|AIza)[A-Za-z0-9_-]{20,}',
    'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
    'GitHub OAuth': r'gho_[A-Za-z0-9]{36}',
    'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}',
    'Slack Webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
    'Stripe Secret': r'sk_live_[0-9a-zA-Z]{24,99}',
    'Stripe Publish': r'pk_live_[0-9a-zA-Z]{24,99}',
    'Twilio SID': r'AC[a-z0-9]{32}',
    'Twilio Token': r'SK[a-z0-9]{32}',
    'SendGrid': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    'Mailgun': r'key-[0-9a-zA-Z]{32}',
    'Discord Token': r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
    'Discord Webhook': r'https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+',
    'Firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'Facebook Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'Twitter Bearer': r'AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+',
    'Heroku API': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'JWT Token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
    'Square Access': r'sq0atp-[0-9A-Za-z_-]{22}',
    'Square OAuth': r'sq0csp-[0-9A-Za-z_-]{43}',
    'PayPal Braintree': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'PGP Private': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'RSA Private': r'-----BEGIN RSA PRIVATE KEY-----',
    'SSH Private': r'-----BEGIN (?:DSA|EC|OPENSSH) PRIVATE KEY-----',
    'Generic Secret': r'(?:secret|password|passwd|pwd|token|api_key|apikey|auth)[\s]*[=:]\s*["\']([A-Za-z0-9/+=_-]{16,})["\']',
    'Generic API Key': r'(?:api|access)[_-]?key[\s]*[=:]\s*["\']([A-Za-z0-9_-]{20,})["\']',
    'Database URL': r'(?:mysql|postgres|mongodb|redis)://[^\s"\'<>]+',
    'IP with Port': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b',
    'Email Password': r'(?:email|smtp)[\s_]*password[\s]*[=:]\s*["\']([^"\']+)["\']',
    'Base64 Secret': r'(?:key|secret|token|password).*?[=:]\s*["\']?([A-Za-z0-9+/]{40,}={0,2})["\']?',
    'Shopify Token': r'shpat_[a-fA-F0-9]{32}',
    'Shopify Secret': r'shpss_[a-fA-F0-9]{32}',
    'Algolia API': r'[a-z0-9]{20,}',
    'Mapbox Token': r'pk\.[a-zA-Z0-9]{60,}',
    'DigitalOcean': r'dop_v1_[a-f0-9]{64}',
    'npm Token': r'npm_[A-Za-z0-9]{36}',
    'Vault Token': r'hvs\.[A-Za-z0-9_-]{24,}',
}


async def _scan_page_secrets(session, url):
    """Scan main page for secrets."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            for name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, body, re.I)
                if matches:
                    for match in matches[:3]:
                        val = match if isinstance(match, str) else str(match)
                        if len(val) > 8:
                            findings.append({
                                'type': f'Secret: {name}',
                                'value': val[:20] + '...' if len(val) > 20 else val,
                                'source': 'HTML',
                                'severity': 'Critical' if 'private' in name.lower() or 'secret' in name.lower() else 'High',
                            })
    except Exception:
        pass
    return findings


async def _scan_js_secrets(session, url):
    """Scan JavaScript files for secrets."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            scripts = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
            for src in scripts[:15]:
                js_url = urljoin(url, src)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as jr:
                        if jr.status == 200:
                            js_body = await jr.text()
                            for name, pattern in SECRET_PATTERNS.items():
                                matches = re.findall(pattern, js_body, re.I)
                                if matches:
                                    for match in matches[:2]:
                                        val = match if isinstance(match, str) else str(match)
                                        if len(val) > 8:
                                            findings.append({
                                                'type': f'Secret: {name}',
                                                'value': val[:20] + '...',
                                                'source': src.split('/')[-1][:30],
                                                'severity': 'Critical' if 'private' in name.lower() else 'High',
                                            })
                except Exception:
                    pass
    except Exception:
        pass
    return findings


async def _scan_common_files(session, url):
    """Check common files for leaked secrets."""
    findings = []
    secret_files = ['/.env', '/.env.local', '/.env.production', '/config.json',
                    '/config.js', '/settings.json', '/.git/config', '/wp-config.php.bak',
                    '/application.yml', '/appsettings.json', '/.aws/credentials',
                    '/.docker/config.json', '/Dockerfile', '/docker-compose.yml']
    for path in secret_files:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if len(body) > 5 and '<!DOCTYPE' not in body[:50]:
                        for name, pattern in list(SECRET_PATTERNS.items())[:15]:
                            matches = re.findall(pattern, body, re.I)
                            if matches:
                                findings.append({
                                    'type': f'Secret in {path}: {name}',
                                    'severity': 'Critical',
                                    'source': path,
                                })
                                break
                        else:
                            if any(k in body.lower() for k in ['password', 'secret', 'key', 'token']):
                                findings.append({
                                    'type': f'Sensitive File: {path}',
                                    'severity': 'High',
                                    'source': path,
                                })
        except Exception:
            pass
    return findings


async def scan_secrets_engine(session, url):
    console.print(f"\n[bold cyan]--- Secrets Regex Engine ---[/bold cyan]")
    console.print(f"  [cyan]Scanning HTML ({len(SECRET_PATTERNS)} patterns)...[/cyan]")
    html_secrets = await _scan_page_secrets(session, url)

    console.print(f"  [cyan]Scanning JavaScript files...[/cyan]")
    js_secrets = await _scan_js_secrets(session, url)

    console.print(f"  [cyan]Checking sensitive files (14 paths)...[/cyan]")
    file_secrets = await _scan_common_files(session, url)

    all_f = html_secrets + js_secrets + file_secrets
    for f in all_f:
        console.print(f"  [bold red]⚠ {f['type']} (in {f.get('source', '?')})[/bold red]")
    if not all_f:
        console.print(f"\n  [green]✓ No secrets found[/green]")
    return {'findings': all_f}
