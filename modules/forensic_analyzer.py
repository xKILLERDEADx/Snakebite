"""Forensic Analyzer — IOC extraction, evidence collection, compromise timeline."""

import aiohttp, asyncio, re, hashlib, time
from datetime import datetime
from urllib.parse import urljoin, urlparse
from modules.core import console

IOC_PATTERNS = {
    'IP Address': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'MD5 Hash': r'\b[a-fA-F0-9]{32}\b',
    'SHA256 Hash': r'\b[a-fA-F0-9]{64}\b',
    'URL': r'https?://[^\s"\'<>]+',
    'Domain': r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b',
    'File Path': r'(?:/(?:etc|var|tmp|home|usr|opt|root)/[\w./]+)',
    'Base64 Blob': r'[A-Za-z0-9+/]{40,}={0,2}',
}

EVIDENCE_PATHS = [
    'wp-content/debug.log', 'debug.log', 'error.log', 'error_log',
    '.htaccess', 'wp-config.php.bak', '.env', '.git/config',
    'access.log', 'access_log', 'wp-content/uploads/',
]

WP_MODIFIED_INDICATORS = [
    ('index.php', r'<?php\s*/\*\*.*?@package\s+WordPress', 'WP core header'),
    ('wp-login.php', r'WordPress', 'WP login page'),
    ('wp-blog-header.php', r'wp-load\.php', 'Blog header loader'),
]


async def _extract_iocs(session, url):
    """Extract Indicators of Compromise from page."""
    iocs = {}
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            domain = urlparse(url).hostname

            for ioc_type, pattern in IOC_PATTERNS.items():
                matches = list(set(re.findall(pattern, body)))
                filtered = []
                for m in matches:
                    if ioc_type == 'Domain' and (m == domain or len(m) < 4):
                        continue
                    if ioc_type == 'IP Address' and m.startswith('0.') or m == '127.0.0.1':
                        continue
                    if ioc_type == 'URL' and domain in m:
                        continue
                    filtered.append(m)
                if filtered:
                    iocs[ioc_type] = filtered[:10]
    except Exception:
        pass
    return iocs


async def _collect_evidence(session, url):
    """Collect evidence from exposed files."""
    evidence = []
    for path in EVIDENCE_PATHS:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    ct = resp.headers.get('Content-Type', '')
                    last_mod = resp.headers.get('Last-Modified', '')

                    if len(body) > 10 and '<!DOCTYPE' not in body[:50]:
                        evidence.append({
                            'path': path, 'size': len(body),
                            'last_modified': last_mod or 'Unknown',
                            'hash': hashlib.sha256(body.encode()).hexdigest()[:16],
                            'preview': body[:100].replace('\n', ' '),
                            'severity': 'High',
                        })
        except Exception:
            pass
    return evidence


async def _check_http_headers_forensics(session, url):
    """Analyze HTTP headers for forensic clues."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            headers = dict(resp.headers)

            server = headers.get('Server', '')
            if server:
                findings.append({'type': f'Server: {server}', 'severity': 'Info'})
                if any(v in server.lower() for v in ['apache/2.2', 'nginx/1.0', 'php/5']):
                    findings.append({'type': f'Outdated Server: {server}', 'severity': 'High'})

            powered = headers.get('X-Powered-By', '')
            if powered:
                findings.append({'type': f'X-Powered-By: {powered}', 'severity': 'Medium'})

            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-XSS-Protection': 'XSS filter',
                'Referrer-Policy': 'Referrer control',
                'Permissions-Policy': 'Feature control',
            }
            missing = [name for name, desc in security_headers.items() if name not in headers]
            if missing:
                findings.append({
                    'type': f'Missing Security Headers ({len(missing)})',
                    'severity': 'Medium',
                    'missing': missing,
                })
    except Exception:
        pass
    return findings


async def _build_timeline(session, url, evidence):
    """Build compromise timeline from evidence."""
    timeline = []
    for ev in evidence:
        if ev.get('last_modified'):
            timeline.append({
                'time': ev['last_modified'],
                'event': f'File modified: {ev["path"]}',
                'severity': ev.get('severity', 'Medium'),
            })

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
            last_mod = resp.headers.get('Last-Modified', '')
            date_header = resp.headers.get('Date', '')
            if last_mod:
                timeline.append({'time': last_mod, 'event': 'Main page last modified', 'severity': 'Info'})
    except Exception:
        pass

    return sorted(timeline, key=lambda x: x.get('time', ''), reverse=True)


async def scan_forensic(session, url):
    console.print(f"\n[bold cyan]--- Forensic Analyzer ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Extracting IOCs...[/cyan]")
    iocs = await _extract_iocs(session, url)
    for ioc_type, values in iocs.items():
        console.print(f"  [dim]{ioc_type}: {len(values)} found[/dim]")

    console.print(f"  [cyan]Collecting evidence ({len(EVIDENCE_PATHS)} paths)...[/cyan]")
    evidence = await _collect_evidence(session, url)
    for ev in evidence:
        all_findings.append({'type': f'Evidence: {ev["path"]}', 'severity': ev['severity'],
                             'size': ev['size'], 'hash': ev['hash']})
        console.print(f"  [red]⚠ Evidence: {ev['path']} ({ev['size']} bytes)[/red]")

    console.print(f"  [cyan]HTTP header forensics...[/cyan]")
    headers_f = await _check_http_headers_forensics(session, url)
    all_findings.extend(headers_f)

    console.print(f"  [cyan]Building timeline...[/cyan]")
    timeline = await _build_timeline(session, url, evidence)

    if not all_findings:
        console.print(f"\n  [green]✓ No forensic evidence found[/green]")
    return {'iocs': iocs, 'evidence': evidence, 'timeline': timeline, 'findings': all_findings}
