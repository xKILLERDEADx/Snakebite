"""Multi-Target Correlator — scan multiple targets, correlate shared infrastructure."""

import aiohttp
import asyncio
import socket
from urllib.parse import urlparse
from modules.core import console

async def _resolve_target(session, target):
    """Resolve target information."""
    parsed = urlparse(target if '://' in target else f'http://{target}')
    domain = parsed.netloc.split(':')[0] or parsed.path.split('/')[0]

    info = {'domain': domain, 'url': target, 'ip': None, 'headers': {},
            'technologies': [], 'server': '', 'alive': False}

    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        info['ip'] = ip
    except Exception:
        return info

    try:
        url = target if '://' in target else f'http://{target}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False, allow_redirects=True) as resp:
            info['alive'] = True
            info['status'] = resp.status

            for h in ['Server', 'X-Powered-By', 'X-Generator']:
                val = resp.headers.get(h, '')
                if val:
                    info['headers'][h] = val
                    info['technologies'].append(val)

            info['server'] = resp.headers.get('Server', '')
    except Exception:
        pass

    return info


async def scan_multi_target(session, targets):
    """Scan multiple targets and find shared infrastructure."""
    console.print(f"\n[bold cyan]--- Multi-Target Correlator ---[/bold cyan]")

    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split(',') if t.strip()]

    if len(targets) < 2:
        console.print(f"  [dim]Need 2+ targets for correlation. Use comma-separated URLs.[/dim]")
        return {'targets': [], 'correlations': []}

    console.print(f"  [cyan]Resolving {len(targets)} targets...[/cyan]")

    results = []
    for target in targets:
        info = await _resolve_target(session, target)
        results.append(info)
        status = '[green]✓[/green]' if info['alive'] else '[red]✗[/red]'
        console.print(f"  {status} {info['domain']} → {info.get('ip', '?')} [{info.get('server', '?')}]")

    correlations = []

    ip_groups = {}
    for r in results:
        if r['ip']:
            ip_groups.setdefault(r['ip'], []).append(r['domain'])
    for ip, domains in ip_groups.items():
        if len(domains) > 1:
            correlations.append({
                'type': 'Shared IP',
                'ip': ip,
                'domains': domains,
                'severity': 'Medium',
            })
            console.print(f"  [yellow]Shared IP {ip}: {', '.join(domains)}[/yellow]")

    server_groups = {}
    for r in results:
        if r['server']:
            server_groups.setdefault(r['server'], []).append(r['domain'])
    for server, domains in server_groups.items():
        if len(domains) > 1:
            correlations.append({
                'type': 'Shared Server',
                'server': server,
                'domains': domains,
            })

    subnet_groups = {}
    for r in results:
        if r['ip']:
            subnet = '.'.join(r['ip'].split('.')[:3])
            subnet_groups.setdefault(subnet, []).append(r['domain'])
    for subnet, domains in subnet_groups.items():
        if len(domains) > 1:
            correlations.append({
                'type': 'Same Subnet',
                'subnet': f'{subnet}.0/24',
                'domains': domains,
            })

    console.print(f"\n  [bold]{len(correlations)} correlations found[/bold]")

    return {
        'targets': results,
        'correlations': correlations,
        'alive': sum(1 for r in results if r['alive']),
        'total': len(results),
    }
