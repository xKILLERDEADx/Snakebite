"""DNS Rebinding Attack Tester — test for DNS rebinding bypass of same-origin."""

import aiohttp
import asyncio
import socket
import time
from urllib.parse import urlparse
from modules.core import console

REBINDING_SERVICES = [
    {'name': 'rbndr.us', 'url': 'https://lock.cmpxchg8b.com/rebinder.html', 'type': 'service'},
    {'name': '1u.ms', 'url': 'http://1u.ms', 'type': 'service'},
]

INTERNAL_IPS = [
    '127.0.0.1', '0.0.0.0', '10.0.0.1', '192.168.1.1',
    '172.16.0.1', '169.254.169.254', '::1',
]


async def _check_dns_pinning(session, url):
    """Check if target implements DNS pinning protection."""
    findings = []
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]

    try:
        ip1 = socket.gethostbyname(hostname)
        await asyncio.sleep(1)
        ip2 = socket.gethostbyname(hostname)
        
        if ip1 != ip2:
            findings.append({
                'type': 'DNS Round-Robin Detected',
                'detail': f'IP changed: {ip1} → {ip2}',
                'severity': 'Low',
                'risk': 'DNS rebinding might be easier with round-robin DNS',
            })
    except Exception:
        pass

    return findings


async def _check_host_header_validation(session, url):
    """Check if server validates Host header (rebinding defense)."""
    findings = []
    parsed = urlparse(url)

    test_hosts = [
        '127.0.0.1', 'localhost', 'evil.com',
        f'{parsed.netloc}.evil.com', 'internal.network',
    ]

    for test_host in test_hosts:
        try:
            headers = {'Host': test_host}
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status == 200:
                    findings.append({
                        'type': 'Weak Host Header Validation',
                        'host': test_host,
                        'status': resp.status,
                        'severity': 'Medium',
                        'detail': f'Server accepted Host: {test_host}',
                    })
        except Exception:
            pass

    return findings


async def _check_cors_for_rebinding(session, url):
    """Check CORS headers that could enable rebinding attacks."""
    findings = []

    try:
        headers = {'Origin': 'http://127.0.0.1'}
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                findings.append({
                    'type': 'CORS Wildcard (Rebinding Risk)',
                    'severity': 'Medium',
                    'detail': 'Wildcard CORS allows any origin including rebinding domains',
                })
            if acao == 'http://127.0.0.1' and acac.lower() == 'true':
                findings.append({
                    'type': 'CORS Trusts Localhost (Rebinding Risk)',
                    'severity': 'High',
                    'detail': 'Server trusts localhost origin — rebinding can exploit this',
                })
    except Exception:
        pass

    return findings


async def _check_ttl_manipulation(session, url):
    """Check DNS TTL which affects rebinding feasibility."""
    findings = []
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]

    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            ttl = answers.rrset.ttl
            if ttl <= 60:
                findings.append({
                    'type': 'Low DNS TTL',
                    'ttl': ttl,
                    'severity': 'Medium',
                    'detail': f'DNS TTL is {ttl}s — makes rebinding attacks faster',
                })
            elif ttl <= 300:
                findings.append({
                    'type': 'Moderate DNS TTL',
                    'ttl': ttl,
                    'severity': 'Low',
                    'detail': f'DNS TTL is {ttl}s — rebinding possible with patience',
                })
            break
    except ImportError:
        pass
    except Exception:
        pass

    return findings


async def scan_dns_rebinding(session, url):
    """Test for DNS rebinding vulnerabilities."""
    console.print(f"\n[bold cyan]--- DNS Rebinding Attack Tester ---[/bold cyan]")

    results = {'findings': [], 'rebinding_risk': 'Low'}
    all_findings = []

    console.print(f"  [cyan]Checking DNS pinning...[/cyan]")
    dns_findings = await _check_dns_pinning(session, url)
    all_findings.extend(dns_findings)

    console.print(f"  [cyan]Testing Host header validation...[/cyan]")
    host_findings = await _check_host_header_validation(session, url)
    all_findings.extend(host_findings)

    console.print(f"  [cyan]Checking CORS for rebinding risk...[/cyan]")
    cors_findings = await _check_cors_for_rebinding(session, url)
    all_findings.extend(cors_findings)

    console.print(f"  [cyan]Analyzing DNS TTL...[/cyan]")
    ttl_findings = await _check_ttl_manipulation(session, url)
    all_findings.extend(ttl_findings)

    for f in all_findings:
        sev_color = {'High': 'red', 'Medium': 'yellow', 'Low': 'blue'}.get(f['severity'], 'dim')
        console.print(f"  [{sev_color}]⚠ {f['type']}[/{sev_color}]")
        console.print(f"    [dim]{f.get('detail', '')}[/dim]")

    results['findings'] = all_findings
    high_count = sum(1 for f in all_findings if f['severity'] in ('High', 'Critical'))
    med_count = sum(1 for f in all_findings if f['severity'] == 'Medium')

    if high_count > 0:
        results['rebinding_risk'] = 'High'
    elif med_count >= 2:
        results['rebinding_risk'] = 'Medium'

    risk_color = {'High': 'red', 'Medium': 'yellow', 'Low': 'green'}.get(results['rebinding_risk'], 'dim')
    console.print(f"\n  [bold {risk_color}]DNS Rebinding Risk: {results['rebinding_risk']}[/bold {risk_color}]")

    if not all_findings:
        console.print(f"  [green]✓ No DNS rebinding vulnerabilities detected[/green]")

    return results
