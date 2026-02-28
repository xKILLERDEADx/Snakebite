"""Web Cache Poisoning Scanner — detect cache key confusion and header injection."""

import aiohttp
import asyncio
import random
import string
import hashlib
from urllib.parse import urlparse
from modules.core import console

UNKEYED_HEADERS = [
    'X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Forwarded-Proto',
    'X-Original-URL', 'X-Rewrite-URL', 'X-Host', 'X-Forwarded-Server',
    'X-HTTP-Method-Override', 'X-Forwarded-Port', 'X-Forwarded-Ssl',
    'Fastly-SSL', 'X-Custom-Header', 'X-Override-URL',
    'X-ARR-SSL', 'X-Azure-Ref', 'CF-Connecting-IP',
]

POISON_PAYLOADS = {
    'xss_reflection': '<script>alert(1)</script>',
    'redirect_injection': 'https://evil.com',
    'header_injection': 'evil.com',
    'proto_downgrade': 'http',
    'port_injection': '443@evil.com',
}


def _generate_cache_buster():
    """Generate a unique cache buster parameter."""
    return ''.join(random.choices(string.ascii_lowercase, k=8))


async def _detect_caching(session, url):
    """Detect if the target uses caching."""
    cache_info = {'has_cache': False, 'cache_headers': {}}
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cache_headers = ['x-cache', 'cf-cache-status', 'x-varnish', 'age',
                             'x-cache-hits', 'x-served-by', 'x-proxy-cache',
                             'x-fastly-request-id', 'x-drupal-cache']
            for h in cache_headers:
                if h in headers:
                    cache_info['cache_headers'][h] = headers[h]
                    cache_info['has_cache'] = True

            cc = headers.get('cache-control', '')
            if 'public' in cc or 'max-age' in cc:
                cache_info['has_cache'] = True
                cache_info['cache_headers']['cache-control'] = cc

    except Exception:
        pass
    return cache_info


async def _test_unkeyed_header(session, url, header_name, payload):
    """Test if a header value gets cached (unkeyed header poisoning)."""
    cb = _generate_cache_buster()
    test_url = f"{url}{'&' if '?' in url else '?'}cb={cb}"

    try:
        headers = {header_name: payload}
        async with session.get(test_url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            body1 = await resp.text()
            status1 = resp.status

        await asyncio.sleep(0.5)

        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            body2 = await resp.text()

            if payload in body2 and payload not in test_url:
                return {
                    'type': 'Cache Poisoning via Unkeyed Header',
                    'header': header_name,
                    'payload': payload[:60],
                    'severity': 'Critical',
                    'detail': f'Payload reflected in cached response without header',
                }
    except Exception:
        pass
    return None


async def _test_parameter_cloaking(session, url):
    """Test for parameter cloaking (different param parsing)."""
    findings = []
    cb = _generate_cache_buster()

    cloaking_payloads = [
        f'?cb={cb}&param=value;injected=true',
        f'?cb={cb}&param=value%26injected=true',
        f'?cb={cb}&param=value%0d%0aInjected: true',
    ]

    for payload_url in cloaking_payloads:
        try:
            test_url = url.rstrip('/') + payload_url
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                body = await resp.text()
                if 'injected' in body.lower():
                    findings.append({
                        'type': 'Parameter Cloaking',
                        'url': test_url[:100],
                        'severity': 'High',
                    })
        except Exception:
            pass
    return findings


async def scan_cache_poisoning(session, url):
    """Scan for web cache poisoning vulnerabilities."""
    console.print(f"\n[bold cyan]--- Web Cache Poisoning Scanner ---[/bold cyan]")

    results = {'cache_detected': False, 'findings': [], 'cache_info': {}}

    console.print(f"  [cyan]Detecting cache infrastructure...[/cyan]")
    cache_info = await _detect_caching(session, url)
    results['cache_info'] = cache_info

    if cache_info['has_cache']:
        results['cache_detected'] = True
        console.print(f"  [green]Cache detected![/green]")
        for h, v in cache_info['cache_headers'].items():
            console.print(f"    [dim]{h}: {v}[/dim]")
    else:
        console.print(f"  [dim]No obvious caching detected[/dim]")

    console.print(f"\n  [cyan]Testing {len(UNKEYED_HEADERS)} unkeyed headers...[/cyan]")
    all_findings = []

    for header in UNKEYED_HEADERS:
        for payload_name, payload in POISON_PAYLOADS.items():
            result = await _test_unkeyed_header(session, url, header, payload)
            if result:
                all_findings.append(result)
                console.print(f"  [bold red]⚠ {result['type']}[/bold red]")
                console.print(f"    [red]Header: {header} → {payload[:40]}[/red]")
        await asyncio.sleep(0.1)

    console.print(f"\n  [cyan]Testing parameter cloaking...[/cyan]")
    cloaking = await _test_parameter_cloaking(session, url)
    all_findings.extend(cloaking)

    results['findings'] = all_findings

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} cache poisoning vectors found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No cache poisoning vulnerabilities detected[/green]")

    return results
