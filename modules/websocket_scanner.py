"""WebSocket Security Scanner — test WebSocket endpoints for vulnerabilities."""

import aiohttp
import asyncio
import json
from urllib.parse import urlparse
from modules.core import console


WS_PATHS = [
    '/ws', '/websocket', '/socket.io/', '/sockjs/', '/realtime',
    '/live', '/stream', '/push', '/events', '/notifications',
    '/chat', '/mqtt', '/stomp', '/cable', '/hub',
    '/signalr', '/signalr/negotiate', '/graphql-ws',
]


async def _check_ws_endpoint(session, url, path):
    """Check if a WebSocket endpoint exists and is accessible."""
    parsed = urlparse(url)
    ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'
    http_scheme = parsed.scheme
    ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
    http_url = f"{http_scheme}://{parsed.netloc}{path}"

    result = None

    try:
        headers = {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
        }
        async with session.get(http_url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=False) as resp:
            if resp.status == 101:
                result = {
                    'path': path,
                    'ws_url': ws_url,
                    'status': 101,
                    'type': 'WebSocket Upgrade Success',
                    'server': resp.headers.get('Server', ''),
                    'protocol': resp.headers.get('Sec-WebSocket-Protocol', ''),
                }
            elif resp.status == 200:
                body = await resp.text()
                if any(kw in body.lower() for kw in ['websocket', 'socket.io', 'sockjs', 'ws://']):
                    result = {
                        'path': path,
                        'ws_url': ws_url,
                        'status': 200,
                        'type': 'WebSocket Related Endpoint',
                        'server': resp.headers.get('Server', ''),
                    }
            elif resp.status == 400 and 'websocket' in resp.headers.get('X-Error', '').lower():
                result = {
                    'path': path,
                    'ws_url': ws_url,
                    'status': 400,
                    'type': 'WebSocket Endpoint (Bad Request)',
                }
    except Exception:
        pass

    if not result:
        try:
            ws_session = aiohttp.ClientSession()
            async with ws_session.ws_connect(ws_url, timeout=8, ssl=False) as ws:
                result = {
                    'path': path,
                    'ws_url': ws_url,
                    'status': 101,
                    'type': 'WebSocket Connection Open',
                    'protocol': ws.protocol or '',
                }
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=3)
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        result['initial_message'] = msg.data[:200]
                except asyncio.TimeoutError:
                    pass
                await ws.close()
            await ws_session.close()
        except Exception:
            try:
                await ws_session.close()
            except Exception:
                pass

    return result


async def _test_ws_security(session, ws_info):
    """Test WebSocket endpoint for security issues."""
    issues = []

    parsed = urlparse(ws_info.get('ws_url', ''))
    http_url = f"{'https' if 'wss' in parsed.scheme else 'http'}://{parsed.netloc}{parsed.path}"

    try:
        evil_headers = {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
            'Origin': 'https://evil-attacker.com',
        }
        async with session.get(http_url, headers=evil_headers,
                               timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=False) as resp:
            if resp.status == 101:
                issues.append({
                    'type': 'Cross-Site WebSocket Hijacking (CSWSH)',
                    'severity': 'High',
                    'detail': 'WebSocket accepts connections from arbitrary origins',
                })
    except Exception:
        pass

    if 'ws://' in ws_info.get('ws_url', '') and ws_info.get('ws_url', '').replace('ws://', 'https://').startswith('https'):
        issues.append({
            'type': 'Unencrypted WebSocket',
            'severity': 'Medium',
            'detail': 'WebSocket uses ws:// instead of wss:// (no encryption)',
        })

    return issues


async def scan_websocket(session, url):
    """Scan for WebSocket vulnerabilities."""
    console.print(f"\n[bold cyan]--- WebSocket Security Scanner ---[/bold cyan]")
    console.print(f"  [cyan]Checking {len(WS_PATHS)} WebSocket paths...[/cyan]")

    results = {
        'endpoints': [],
        'security_issues': [],
    }

    tasks = [_check_ws_endpoint(session, url, path) for path in WS_PATHS]
    found = await asyncio.gather(*tasks)

    for ws_info in found:
        if ws_info:
            results['endpoints'].append(ws_info)
            console.print(f"  [bold green]✓ {ws_info['path']}[/bold green] — {ws_info['type']}")
            if ws_info.get('protocol'):
                console.print(f"    [dim]Protocol: {ws_info['protocol']}[/dim]")
            if ws_info.get('initial_message'):
                console.print(f"    [dim]Message: {ws_info['initial_message'][:80]}[/dim]")

    if results['endpoints']:
        console.print(f"\n  [yellow]Testing security on {len(results['endpoints'])} endpoints...[/yellow]")
        for ws_info in results['endpoints']:
            issues = await _test_ws_security(session, ws_info)
            results['security_issues'].extend(issues)
            for issue in issues:
                sev_color = 'red' if issue['severity'] == 'High' else 'yellow'
                console.print(f"  [{sev_color}]⚠ {issue['type']}[/{sev_color}]")
                console.print(f"    [dim]{issue['detail']}[/dim]")

    if not results['endpoints']:
        console.print(f"  [dim]No WebSocket endpoints found[/dim]")

    return results
