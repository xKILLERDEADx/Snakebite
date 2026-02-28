"""Cache Deception Scanner — web cache poisoning, path confusion, parameter cloaking."""

import aiohttp
import asyncio
import random
import string
from urllib.parse import urlparse
from modules.core import console

async def _test_cache_deception(session, url):
    findings = []
    for ext in ['/x.css', '/x.js', '/x.jpg', '/x.woff', '/x.png', '/x.svg', '/x.json', '/x.gif']:
        try:
            async with session.get(url.rstrip('/') + ext, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                body = await resp.text()
                ct = resp.headers.get('Content-Type', '')
                cache = resp.headers.get('X-Cache', resp.headers.get('CF-Cache-Status', ''))
                if resp.status == 200 and 'text/html' in ct:
                    sev = 'Critical' if any(k in cache.upper() for k in ['HIT', 'MISS', 'CACHED']) else 'Medium'
                    findings.append({'type': f'Cache Deception ({ext})', 'severity': sev, 'cache': cache})
        except Exception:
            pass
    return findings


async def _test_cache_poisoning(session, url):
    findings = []
    canary = ''.join(random.choices(string.ascii_lowercase, k=8))
    headers_map = {
        'X-Forwarded-Host': f'{canary}.evil.com', 'X-Host': f'{canary}.evil.com',
        'X-Forwarded-Scheme': 'nothttps', 'X-Original-URL': '/admin',
        'X-Rewrite-URL': '/admin', 'X-Forwarded-Port': '1337',
        'X-Forwarded-Prefix': f'/{canary}', 'X-Custom-IP-Authorization': '127.0.0.1',
    }
    for header, value in headers_map.items():
        try:
            buster = ''.join(random.choices(string.ascii_lowercase, k=6))
            async with session.get(f"{url}?cb={buster}", headers={header: value},
                                   timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                body = await resp.text()
                if canary in body:
                    findings.append({'type': f'Cache Poisoning: {header}', 'severity': 'Critical',
                                     'detail': f'Canary reflected from unkeyed header'})
        except Exception:
            pass
    return findings


async def _test_param_cloak(session, url):
    findings = []
    for param, payload in [('utm_content', '<script>'), ('callback', 'evil'), ('_', '<img/src=x>'), ('cb', '"><svg>')]:
        try:
            async with session.get(url, params={param: payload},
                                   timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                body = await resp.text()
                if payload in body:
                    findings.append({'type': f'Param Cloaking: {param}', 'severity': 'High'})
        except Exception:
            pass
    return findings


async def _test_fat_get(session, url):
    findings = []
    try:
        async with session.get(url, data='admin=true&debug=1',
                               headers={'Content-Type': 'application/x-www-form-urlencoded'},
                               timeout=aiohttp.ClientTimeout(total=8), ssl=False) as r1:
            b1 = await r1.text()
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as r2:
            b2 = await r2.text()
        if b1 != b2 and len(b1) != len(b2):
            findings.append({'type': 'Fat GET Accepted', 'severity': 'Medium'})
    except Exception:
        pass
    return findings


async def scan_cache_deception(session, url):
    console.print(f"\n[bold cyan]--- Cache Deception Scanner ---[/bold cyan]")
    all_f = []
    console.print(f"  [cyan]Testing cache deception (8 extensions)...[/cyan]")
    all_f.extend(await _test_cache_deception(session, url))
    console.print(f"  [cyan]Testing cache poisoning (8 headers)...[/cyan]")
    all_f.extend(await _test_cache_poisoning(session, url))
    console.print(f"  [cyan]Testing parameter cloaking...[/cyan]")
    all_f.extend(await _test_param_cloak(session, url))
    console.print(f"  [cyan]Testing fat GET...[/cyan]")
    all_f.extend(await _test_fat_get(session, url))
    for f in all_f:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")
    if not all_f:
        console.print(f"\n  [green]✓ No cache vulnerabilities[/green]")
    return {'findings': all_f}
