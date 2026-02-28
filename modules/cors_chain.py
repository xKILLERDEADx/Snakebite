"""CORS Chain Exploiter — preflight bypass, credential theft, null origin, regex bypass."""

import aiohttp
import asyncio
import re
from urllib.parse import urlparse
from modules.core import console


async def _test_cors_origins(session, url):
    findings = []
    parsed = urlparse(url)
    domain = parsed.hostname

    evil_origins = [
        ('https://evil.com', 'Arbitrary Origin'),
        ('null', 'Null Origin'),
        (f'https://{domain}.evil.com', 'Subdomain Prefix'),
        (f'https://evil{domain}', 'Domain Suffix'),
        (f'https://{domain}evil.com', 'No Dot Separation'),
        (f'https://evil.com/{domain}', 'Path Confusion'),
        (f'https://{domain}.', 'Trailing Dot'),
        (f'http://{domain}', 'HTTP Downgrade'),
        ('https://evil.com%60', 'Backtick Bypass'),
        (f'https://{domain}_.evil.com', 'Underscore Bypass'),
    ]

    for origin, desc in evil_origins:
        try:
            headers = {'Origin': origin}
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if acao == origin or acao == '*':
                    severity = 'Critical' if acac.lower() == 'true' else 'High'
                    findings.append({
                        'type': f'CORS: {desc}',
                        'origin': origin, 'reflected': acao,
                        'credentials': acac, 'severity': severity,
                    })
                elif origin in acao:
                    findings.append({
                        'type': f'CORS Partial Match: {desc}',
                        'origin': origin, 'reflected': acao,
                        'severity': 'Medium',
                    })
        except Exception:
            pass
    return findings


async def _test_preflight_bypass(session, url):
    findings = []
    parsed = urlparse(url)
    try:
        headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'PUT',
            'Access-Control-Request-Headers': 'X-Custom-Header, Authorization',
        }
        async with session.options(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
            allow_methods = resp.headers.get('Access-Control-Allow-Methods', '')
            allow_headers = resp.headers.get('Access-Control-Allow-Headers', '')
            acao = resp.headers.get('Access-Control-Allow-Origin', '')

            if 'evil.com' in acao:
                methods = [m.strip() for m in allow_methods.split(',')]
                dangerous = [m for m in methods if m in ('PUT', 'DELETE', 'PATCH')]
                if dangerous:
                    findings.append({
                        'type': f'Preflight Allows: {dangerous}',
                        'severity': 'Critical',
                        'detail': f'Methods: {allow_methods}, Headers: {allow_headers[:50]}',
                    })
                if 'authorization' in allow_headers.lower() or '*' in allow_headers:
                    findings.append({
                        'type': 'Preflight Allows Authorization Header',
                        'severity': 'Critical',
                    })
    except Exception:
        pass
    return findings


async def _test_cors_vary(session, url):
    findings = []
    try:
        h1 = {'Origin': 'https://a.com'}
        h2 = {'Origin': 'https://b.com'}
        async with session.get(url, headers=h1, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as r1:
            acao1 = r1.headers.get('Access-Control-Allow-Origin', '')
            vary = r1.headers.get('Vary', '')
        async with session.get(url, headers=h2, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as r2:
            acao2 = r2.headers.get('Access-Control-Allow-Origin', '')

        if acao1 and acao2 and acao1 != acao2 and 'Origin' not in vary:
            findings.append({
                'type': 'CORS Without Vary: Origin',
                'severity': 'High',
                'detail': 'Dynamic ACAO without Vary header — cache poisoning risk',
            })
    except Exception:
        pass
    return findings


async def scan_cors_chain(session, url):
    console.print(f"\n[bold cyan]--- CORS Chain Exploiter ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Testing 10 origin bypass techniques...[/cyan]")
    origins = await _test_cors_origins(session, url)
    all_findings.extend(origins)

    console.print(f"  [cyan]Testing preflight bypass...[/cyan]")
    preflight = await _test_preflight_bypass(session, url)
    all_findings.extend(preflight)

    console.print(f"  [cyan]Testing Vary header...[/cyan]")
    vary = await _test_cors_vary(session, url)
    all_findings.extend(vary)

    for f in all_findings:
        color = 'red' if f['severity'] in ('Critical', 'High') else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not all_findings:
        console.print(f"\n  [green]✓ CORS configuration secure[/green]")
    return {'findings': all_findings}
