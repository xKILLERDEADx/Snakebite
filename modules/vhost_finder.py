"""Virtual Host Discovery — find hidden vhosts via real HTTP Host header testing."""

import aiohttp
import asyncio
from urllib.parse import urlparse
from modules.core import console

COMMON_VHOST_PREFIXES = [
    'admin', 'api', 'app', 'backend', 'beta', 'blog', 'cdn', 'cms',
    'cpanel', 'dashboard', 'db', 'debug', 'demo', 'dev', 'docs',
    'email', 'ftp', 'git', 'gitlab', 'grafana', 'help', 'internal',
    'jenkins', 'jira', 'login', 'mail', 'manage', 'monitor', 'mysql',
    'new', 'ns1', 'ns2', 'old', 'panel', 'portal', 'private', 'prod',
    'proxy', 'qa', 'secure', 'smtp', 'staging', 'stage', 'static',
    'status', 'store', 'support', 'test', 'testing', 'upload', 'vpn',
    'webmail', 'wiki', 'www', 'www2', 'api-v1', 'api-v2', 'sandbox',
    'preview', 'auth', 'sso', 'id', 'accounts', 'payments', 'billing',
    'shop', 'assets', 'media', 'images', 'video', 'files', 'download',
    'mobile', 'm', 'wap', 'intranet', 'extranet', 'remote', 'gateway',
    'ci', 'cd', 'docker', 'k8s', 'registry', 'vault', 'consul',
    'prometheus', 'kibana', 'elastic', 'redis', 'rabbitmq', 'kafka',
]


async def _get_baseline(session, url, ip):
    """Get baseline response for invalid host to compare against."""
    try:
        headers = {'Host': 'invalid-nonexistent-host.example.com'}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=False) as resp:
            body = await resp.text()
            return {
                'status': resp.status,
                'length': len(body),
                'headers': dict(resp.headers),
            }
    except Exception:
        return {'status': 0, 'length': 0, 'headers': {}}


async def _check_vhost(session, url, vhost, baseline):
    """Check if a virtual host exists by comparing response to baseline."""
    try:
        headers = {'Host': vhost}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=False) as resp:
            body = await resp.text()
            response_length = len(body)
            length_diff = abs(response_length - baseline['length'])
            status_diff = resp.status != baseline['status']
            is_different = (
                (status_diff and resp.status in [200, 301, 302, 401, 403]) or
                (length_diff > 100 and resp.status in [200, 301, 302, 401, 403])
            )

            if is_different:
                return {
                    'vhost': vhost,
                    'status': resp.status,
                    'length': response_length,
                    'length_diff': length_diff,
                    'redirect': resp.headers.get('Location', ''),
                    'server': resp.headers.get('Server', ''),
                    'title': '',
                }
    except Exception:
        pass
    return None


async def scan_vhost(session, url):
    """Discover virtual hosts on the target."""
    console.print(f"\n[bold cyan]--- Virtual Host Discovery ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == 'https' else 80)

    try:
        ip = await asyncio.get_event_loop().run_in_executor(
            None, lambda: __import__('socket').gethostbyname(domain)
        )
        target_url = f"{scheme}://{ip}:{port}/"
        console.print(f"  [green]Resolved {domain} → {ip}[/green]")
    except Exception:
        target_url = url
        ip = domain

    console.print(f"  [cyan]Getting baseline response...[/cyan]")
    baseline = await _get_baseline(session, target_url, ip)
    console.print(f"  [dim]Baseline: status={baseline['status']}, length={baseline['length']}[/dim]")

    vhosts = []
    for prefix in COMMON_VHOST_PREFIXES:
        vhosts.append(f"{prefix}.{base_domain}")

    console.print(f"  [cyan]Testing {len(vhosts)} virtual hosts...[/cyan]")

    results = []
    batch_size = 20
    for i in range(0, len(vhosts), batch_size):
        batch = vhosts[i:i + batch_size]
        tasks = [_check_vhost(session, target_url, vh, baseline) for vh in batch]
        batch_results = await asyncio.gather(*tasks)
        for r in batch_results:
            if r:
                results.append(r)
                console.print(f"    [bold green]✓ {r['vhost']}[/bold green] — Status: {r['status']}, Size: {r['length']}B")
        await asyncio.sleep(0.1)

    if results:
        console.print(f"\n  [bold green]Found {len(results)} virtual hosts![/bold green]")
    else:
        console.print(f"\n  [dim]No hidden virtual hosts detected[/dim]")

    return results
