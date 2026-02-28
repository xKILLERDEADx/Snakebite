"""API Rate Limit Bypass — header rotation, IP spoofing, endpoint variation."""

import aiohttp
import asyncio
import time
import random
from modules.core import console

IP_SPOOF_HEADERS = [
    'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
    'X-Client-IP', 'X-Remote-IP', 'X-Remote-Addr',
    'CF-Connecting-IP', 'True-Client-IP', 'Forwarded',
    'X-Forwarded-Host', 'X-Custom-IP-Authorization',
]

BYPASS_STRATEGIES = {
    'ip_rotation': 'Rotate source IP via headers',
    'case_change': 'Change URL path casing',
    'path_variation': 'Add trailing slashes, dots, encodings',
    'method_change': 'Switch HTTP method',
    'header_removal': 'Remove rate-limit tracking headers',
}


def _generate_random_ip():
    """Generate a random IP for header spoofing."""
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


async def _detect_rate_limit(session, url, num_requests=30):
    """Send rapid requests to detect rate limiting."""
    results = {'total': num_requests, 'blocked': 0, 'success': 0, 'limit_detected': False}

    for i in range(num_requests):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status == 429:
                    results['blocked'] += 1
                    results['limit_detected'] = True
                    retry = resp.headers.get('Retry-After', 'unknown')
                    limit = resp.headers.get('X-RateLimit-Limit', resp.headers.get('RateLimit-Limit', ''))
                    remaining = resp.headers.get('X-RateLimit-Remaining', resp.headers.get('RateLimit-Remaining', ''))
                    results['retry_after'] = retry
                    results['rate_limit'] = limit
                    results['remaining'] = remaining
                elif resp.status == 403:
                    results['blocked'] += 1
                else:
                    results['success'] += 1
        except Exception:
            pass

    return results


async def _bypass_via_ip_headers(session, url, requests_per_ip=5):
    """Attempt rate limit bypass via IP header rotation."""
    findings = []
    total_success = 0

    for batch in range(6):
        fake_ip = _generate_random_ip()
        headers = {}
        for header in IP_SPOOF_HEADERS:
            headers[header] = fake_ip

        for i in range(requests_per_ip):
            try:
                async with session.get(url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False) as resp:
                    if resp.status != 429:
                        total_success += 1
            except Exception:
                pass

    if total_success >= 25:
        findings.append({
            'type': 'Rate Limit Bypass via IP Headers',
            'severity': 'High',
            'detail': f'{total_success}/30 requests succeeded with rotated IPs',
            'technique': 'IP header rotation',
        })

    return findings


async def _bypass_via_path_variation(session, url):
    """Attempt bypass via URL path variations."""
    findings = []
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path.rstrip('/')

    variations = [
        f'{path}/',
        f'{path}/.',
        f'{path}%20',
        f'{path}%00',
        f'{path}?',
        f'{path}#',
        f'{path};',
        path.upper() if path else '/',
        f'//{path}',
        f'{path}/..',
    ]

    success = 0
    for var_path in variations:
        try:
            test_url = f'{parsed.scheme}://{parsed.netloc}{var_path}'
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status not in (429, 403, 404):
                    success += 1
        except Exception:
            pass

    if success >= 5:
        findings.append({
            'type': 'Rate Limit Bypass via Path Variation',
            'severity': 'Medium',
            'detail': f'{success}/{len(variations)} path variations accepted',
            'technique': 'URL path manipulation',
        })

    return findings


async def _bypass_via_method(session, url):
    """Attempt bypass via HTTP method switching."""
    findings = []
    methods = ['GET', 'POST', 'PUT', 'PATCH', 'HEAD', 'OPTIONS']

    success = 0
    for method in methods:
        try:
            async with session.request(method, url,
                                       timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False) as resp:
                if resp.status not in (429, 403, 405):
                    success += 1
        except Exception:
            pass

    if success >= 4:
        findings.append({
            'type': 'Rate Limit Not Method-Aware',
            'severity': 'Medium',
            'detail': f'{success}/{len(methods)} methods not rate limited',
        })

    return findings


async def scan_rate_bypass(session, url):
    """API rate limit bypass scanner."""
    console.print(f"\n[bold cyan]--- Rate Limit Bypass Scanner ---[/bold cyan]")

    console.print(f"  [cyan]Detecting rate limiting (30 rapid requests)...[/cyan]")
    detection = await _detect_rate_limit(session, url)

    if detection['limit_detected']:
        console.print(f"  [yellow]Rate limit detected at ~{detection['blocked']}/{detection['total']} blocked[/yellow]")
        if detection.get('rate_limit'):
            console.print(f"  [dim]Limit: {detection['rate_limit']}, Remaining: {detection.get('remaining', '?')}[/dim]")
    else:
        console.print(f"  [red]No rate limiting detected ({detection['success']}/{detection['total']} success)[/red]")
        return {
            'rate_limited': False,
            'findings': [{'type': 'No Rate Limiting', 'severity': 'High',
                          'detail': f'All {detection["success"]} requests succeeded'}],
        }

    all_findings = []

    console.print(f"  [cyan]Testing IP header rotation ({len(IP_SPOOF_HEADERS)} headers)...[/cyan]")
    ip_bypass = await _bypass_via_ip_headers(session, url)
    all_findings.extend(ip_bypass)
    for f in ip_bypass:
        console.print(f"  [red]⚠ {f['type']}[/red]")

    console.print(f"  [cyan]Testing path variations...[/cyan]")
    path_bypass = await _bypass_via_path_variation(session, url)
    all_findings.extend(path_bypass)

    console.print(f"  [cyan]Testing method switching...[/cyan]")
    method_bypass = await _bypass_via_method(session, url)
    all_findings.extend(method_bypass)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} bypass techniques found![/bold red]")
    else:
        console.print(f"\n  [green]✓ Rate limiting appears robust[/green]")

    return {'rate_limited': True, 'detection': detection, 'findings': all_findings}
