"""JavaScript File Analyzer — extract secrets, API endpoints, tokens from JS files."""

import aiohttp
import asyncio
import re
from urllib.parse import urlparse, urljoin
from modules.core import console


SECRET_PATTERNS = {
    'AWS Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret': r'(?i)aws(.{0,20})?["\'][0-9a-zA-Z/+]{40}["\']',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
    'Slack Token': r'xox[bpors]-[0-9a-zA-Z]{10,48}',
    'Stripe Key': r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
    'Private Key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    'JWT Token': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    'Bearer Token': r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*',
    'Basic Auth': r'(?i)basic\s+[a-zA-Z0-9+/]+=*',
    'Password': r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']',
    'API Key Generic': r'(?i)(?:api_?key|apikey|api_secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
    'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
    'Firebase Config': r'(?i)firebase[A-Za-z]*\s*[:=]\s*["\'][^"\']+["\']',
    'Mailgun Key': r'key-[0-9a-zA-Z]{32}',
    'Twilio SID': r'AC[a-zA-Z0-9]{32}',
    'SendGrid Key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    'Telegram Token': r'[0-9]+:AA[0-9A-Za-z_-]{33}',
    'Discord Token': r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
    'Heroku Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
}

ENDPOINT_PATTERNS = [
    r'(?:"|\')/api/[a-zA-Z0-9/_\-\.]+(?:"|\')',
    r'(?:"|\')/v[0-9]+/[a-zA-Z0-9/_\-\.]+(?:"|\')',
    r'(?:"|\')https?://[^"\'>\s]{10,}(?:"|\')',
    r'(?:"|\')/graphql(?:"|\')',
    r'(?:"|\')/rest/[a-zA-Z0-9/_\-\.]+(?:"|\')',
    r'(?:"|\')/admin/[a-zA-Z0-9/_\-\.]+(?:"|\')',
    r'(?:"|\')/internal/[a-zA-Z0-9/_\-\.]+(?:"|\')',
    r'(?:"|\')/private/[a-zA-Z0-9/_\-\.]+(?:"|\')',
    r'(?:"|\')/debug/[a-zA-Z0-9/_\-\.]+(?:"|\')',
    r'(?:"|\')/config[a-zA-Z0-9/_\-\.]*(?:"|\')',
]

INFO_PATTERNS = {
    'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'IP Address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'S3 Bucket': r'[a-zA-Z0-9.-]+\.s3\.amazonaws\.com',
    'Internal URL': r'(?:https?://)?(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)',
    'Debug Flag': r'(?i)(?:debug|verbose|test_mode)\s*[=:]\s*(?:true|1|yes)',
}


async def _find_js_files(session, url):
    """Find JavaScript files linked from the target page."""
    js_files = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            html = await resp.text()
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                src = match.group(1)
                if src.endswith('.js') or '.js?' in src:
                    full_url = urljoin(url, src)
                    js_files.add(full_url)

            for match in re.finditer(r'(?:href|src|import)\s*[=(]\s*["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
                full_url = urljoin(url, match.group(1))
                js_files.add(full_url)

    except Exception:
        pass
    return list(js_files)


async def _analyze_js(session, js_url):
    """Analyze a single JavaScript file for secrets and endpoints."""
    findings = {
        'url': js_url,
        'secrets': [],
        'endpoints': [],
        'info': [],
        'size': 0,
    }

    try:
        async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status != 200:
                return findings
            content = await resp.text()
            findings['size'] = len(content)

            for name, pattern in SECRET_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    value = match.group()[:100]
                    findings['secrets'].append({
                        'type': name,
                        'value': value,
                        'file': js_url,
                    })

            for pattern in ENDPOINT_PATTERNS:
                for match in re.finditer(pattern, content):
                    endpoint = match.group().strip('"\'')
                    findings['endpoints'].append(endpoint)

            for name, pattern in INFO_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    value = match.group()
                    if name == 'Email' and '@example.com' in value:
                        continue
                    findings['info'].append({
                        'type': name,
                        'value': value[:80],
                    })

            findings['endpoints'] = list(set(findings['endpoints']))[:50]
            seen_secrets = set()
            unique_secrets = []
            for s in findings['secrets']:
                key = f"{s['type']}:{s['value'][:30]}"
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    unique_secrets.append(s)
            findings['secrets'] = unique_secrets

    except Exception:
        pass

    return findings


async def scan_js_files(session, url):
    """Scan JavaScript files for secrets, endpoints, and sensitive info."""
    console.print(f"\n[bold cyan]--- JavaScript File Analyzer ---[/bold cyan]")
    console.print(f"  [cyan]Finding JavaScript files...[/cyan]")
    js_files = await _find_js_files(session, url)

    if not js_files:
        console.print(f"  [dim]No JavaScript files found[/dim]")
        return {'js_files': [], 'total_secrets': 0, 'total_endpoints': 0}

    console.print(f"  [green]Found {len(js_files)} JS files[/green]")

    results = {
        'js_files': [],
        'total_secrets': 0,
        'total_endpoints': 0,
        'total_info': 0,
    }

    tasks = [_analyze_js(session, js_url) for js_url in js_files[:30]]
    analyses = await asyncio.gather(*tasks)

    for analysis in analyses:
        if analysis['secrets'] or analysis['endpoints'] or analysis['info']:
            results['js_files'].append(analysis)

        if analysis['secrets']:
            results['total_secrets'] += len(analysis['secrets'])
            for secret in analysis['secrets'][:3]:
                console.print(f"  [bold red]🔑 {secret['type']}:[/bold red] {secret['value'][:60]}")
                console.print(f"     [dim]File: {analysis['url'][-50:]}[/dim]")

        if analysis['endpoints']:
            results['total_endpoints'] += len(analysis['endpoints'])

        if analysis['info']:
            results['total_info'] += len(analysis['info'])

    console.print(f"\n  [bold]Summary:[/bold]")
    console.print(f"    JS Files Analyzed: {len(analyses)}")
    console.print(f"    [red]Secrets Found: {results['total_secrets']}[/red]")
    console.print(f"    [cyan]API Endpoints: {results['total_endpoints']}[/cyan]")
    console.print(f"    [yellow]Info Leaks: {results['total_info']}[/yellow]")

    if results['total_endpoints'] > 0:
        console.print(f"\n  [bold yellow]Top API Endpoints:[/bold yellow]")
        all_endpoints = []
        for f in results['js_files']:
            all_endpoints.extend(f['endpoints'])
        for ep in sorted(set(all_endpoints))[:15]:
            console.print(f"    [dim]{ep}[/dim]")

    return results
