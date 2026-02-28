"""Phishing Detector — detect fake login forms, credential harvesters, lookalike pages."""

import aiohttp, asyncio, re
from urllib.parse import urljoin, urlparse
from modules.core import console

PHISHING_PATHS = ['/login', '/signin', '/account', '/verify', '/secure', '/update',
                  '/confirm', '/validate', '/banking', '/paypal', '/apple', '/microsoft',
                  '/google', '/facebook', '/instagram', '/webmail', '/portal']

PHISHING_INDICATORS = [
    (r'<form[^>]*action\s*=\s*["\']https?://(?!.*{domain})', 'Form submits to external domain'),
    (r'password.*password.*password', 'Multiple password fields'),
    (r'(?:credit.card|card.number|cvv|expiry|expiration)', 'Credit card fields'),
    (r'(?:ssn|social.security|national.id)', 'SSN/National ID collection'),
    (r'data:text/html', 'Data URI phishing'),
    (r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*value\s*=\s*["\'][^"\']{50,}', 'Long hidden value (exfil)'),
]

FAKE_LOGIN_SIGS = [
    'Your account has been compromised', 'verify your identity',
    'confirm your account', 'update your information', 'suspended',
    'unusual activity', 'unauthorized access', 'security alert',
]

async def _scan_phishing_pages(session, url):
    findings = []
    parsed = urlparse(url)
    domain = parsed.hostname

    for path in PHISHING_PATHS:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    for pattern, desc in PHISHING_INDICATORS:
                        p = pattern.replace('{domain}', re.escape(domain))
                        if re.search(p, body, re.I):
                            findings.append({'type': f'Phishing: {desc} ({path})', 'severity': 'Critical'})
                    for sig in FAKE_LOGIN_SIGS:
                        if sig.lower() in body.lower():
                            findings.append({'type': f'Fake Login Page: {path}', 'severity': 'Critical',
                                             'detail': f'Contains: {sig}'})
                            break
        except Exception:
            pass
    return findings

async def _check_form_targets(session, url):
    findings = []
    parsed = urlparse(url)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            body = await resp.text()
            forms = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', body, re.I)
            for action in forms:
                if action.startswith('http') and parsed.hostname not in action:
                    findings.append({'type': f'External Form Target: {action[:60]}', 'severity': 'High',
                                     'detail': 'Form data sent to different domain'})
    except Exception:
        pass
    return findings

async def _check_ssl_phishing(session, url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme == 'http':
        findings.append({'type': 'No SSL (HTTP only)', 'severity': 'High',
                         'detail': 'Login pages should always use HTTPS'})
    return findings

async def scan_phishing_detect(session, url):
    console.print(f"\n[bold cyan]--- Phishing Detector ---[/bold cyan]")
    all_f = []
    console.print(f"  [cyan]Scanning phishing pages ({len(PHISHING_PATHS)})...[/cyan]")
    all_f.extend(await _scan_phishing_pages(session, url))
    console.print(f"  [cyan]Checking form targets...[/cyan]")
    all_f.extend(await _check_form_targets(session, url))
    console.print(f"  [cyan]SSL check...[/cyan]")
    all_f.extend(await _check_ssl_phishing(session, url))
    for f in all_f:
        color = 'red' if f['severity'] == 'Critical' else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not all_f:
        console.print(f"\n  [green]✓ No phishing detected[/green]")
    return {'findings': all_f}
