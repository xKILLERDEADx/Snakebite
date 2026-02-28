"""WebSocket Hijacker — WS upgrade, origin bypass, message injection, CSWSH."""

import aiohttp
import asyncio
import json
import hashlib
import base64
from urllib.parse import urlparse, urljoin
from modules.core import console

WS_PATHS = ['/ws', '/websocket', '/socket', '/ws/', '/socket.io/',
            '/signalr', '/hub', '/realtime', '/live', '/stream',
            '/api/ws', '/api/websocket', '/chat', '/notifications']


async def _discover_websockets(session, url):
    """Discover WebSocket endpoints."""
    found = []
    parsed = urlparse(url)

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            body = await resp.text()
            import re
            ws_refs = re.findall(r'wss?://[^\s"\'<>]+', body)
            for ws in ws_refs:
                if ws not in found:
                    found.append(ws)

            ws_paths_in_js = re.findall(r'["\'](/(?:ws|websocket|socket|signalr|hub)[/\w]*)["\']', body, re.I)
            for path in ws_paths_in_js:
                ws_url = f"{'wss' if parsed.scheme == 'https' else 'ws'}://{parsed.netloc}{path}"
                if ws_url not in found:
                    found.append(ws_url)
    except Exception:
        pass

    for path in WS_PATHS:
        ws_url = f"{'wss' if parsed.scheme == 'https' else 'ws'}://{parsed.netloc}{path}"
        http_url = urljoin(url, path)

        try:
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': base64.b64encode(b'snakebite-test!!').decode(),
                'Sec-WebSocket-Version': '13',
            }
            async with session.get(http_url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status == 101 or 'upgrade' in resp.headers.get('Connection', '').lower():
                    if ws_url not in found:
                        found.append(ws_url)
        except Exception:
            pass

    return found


async def _test_origin_bypass(session, ws_url, original_url):
    """Test WebSocket origin bypass."""
    findings = []
    parsed = urlparse(original_url)

    evil_origins = [
        'https://evil.com',
        'https://attacker.com',
        f'https://{parsed.hostname}.evil.com',
        'null',
        '',
        f'https://evil.{parsed.hostname}',
    ]

    http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')

    for origin in evil_origins:
        try:
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': base64.b64encode(b'snakebite-test!!').decode(),
                'Sec-WebSocket-Version': '13',
                'Origin': origin,
            }
            async with session.get(http_url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status == 101:
                    findings.append({
                        'type': 'WebSocket Origin Bypass',
                        'origin': origin or '(empty)',
                        'severity': 'Critical',
                        'detail': 'Server accepted WebSocket with evil origin',
                    })
                    break
        except Exception:
            pass

    return findings


async def _test_cswsh(session, ws_url, original_url):
    """Test Cross-Site WebSocket Hijacking."""
    findings = []
    http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')

    try:
        headers = {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': base64.b64encode(b'cswsh-test-key!!').decode(),
            'Sec-WebSocket-Version': '13',
            'Origin': 'https://evil.com',
            'Cookie': '',
        }
        async with session.get(http_url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=5),
                               ssl=False) as resp:
            if resp.status == 101:
                findings.append({
                    'type': 'CSWSH (Cross-Site WebSocket Hijacking)',
                    'severity': 'Critical',
                    'detail': 'WS connection accepted without auth from cross-origin',
                })
    except Exception:
        pass

    return findings


async def _test_message_injection(session, ws_url):
    """Test WebSocket message injection patterns."""
    findings = []
    ws_url_clean = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')

    injection_payloads = [
        {'type': 'XSS via WS', 'data': json.dumps({'message': '<script>alert(1)</script>'})},
        {'type': 'SQLi via WS', 'data': json.dumps({'query': "' OR 1=1--"})},
        {'type': 'Command Injection', 'data': json.dumps({'cmd': '; id'})},
        {'type': 'Path Traversal', 'data': json.dumps({'file': '../../../etc/passwd'})},
        {'type': 'SSTI via WS', 'data': json.dumps({'template': '{{7*7}}'})},
    ]

    try:
        ws_session = aiohttp.ClientSession()
        try:
            async with ws_session.ws_connect(ws_url, timeout=5, ssl=False,
                                              origin='https://evil.com') as ws:
                for payload in injection_payloads:
                    try:
                        await ws.send_str(payload['data'])
                        msg = await asyncio.wait_for(ws.receive(), timeout=3)
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            resp_data = msg.data
                            if '<script>' in resp_data or '49' in resp_data or 'root:' in resp_data:
                                findings.append({
                                    'type': f'WS {payload["type"]}',
                                    'severity': 'Critical',
                                    'detail': f'Payload reflected: {resp_data[:60]}',
                                })
                    except (asyncio.TimeoutError, Exception):
                        pass
        except Exception:
            pass
        finally:
            await ws_session.close()
    except Exception:
        pass

    return findings


async def scan_websocket_hijack(session, url):
    """WebSocket security scanner."""
    console.print(f"\n[bold cyan]--- WebSocket Hijacker ---[/bold cyan]")

    console.print(f"  [cyan]Discovering WebSocket endpoints...[/cyan]")
    endpoints = await _discover_websockets(session, url)

    if not endpoints:
        console.print(f"  [dim]No WebSocket endpoints found[/dim]")
        return {'endpoints': [], 'findings': []}

    console.print(f"  [green]Found {len(endpoints)} WS endpoint(s)[/green]")
    all_findings = []

    for ws_url in endpoints[:5]:
        console.print(f"\n  [green]{ws_url}[/green]")

        console.print(f"  [cyan]Testing origin bypass (6 origins)...[/cyan]")
        origin = await _test_origin_bypass(session, ws_url, url)
        all_findings.extend(origin)

        console.print(f"  [cyan]Testing CSWSH...[/cyan]")
        cswsh = await _test_cswsh(session, ws_url, url)
        all_findings.extend(cswsh)

        console.print(f"  [cyan]Testing message injection (5 payloads)...[/cyan]")
        inject = await _test_message_injection(session, ws_url)
        all_findings.extend(inject)

    for f in all_findings:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

    if not all_findings:
        console.print(f"\n  [green]✓ WebSocket security looks clean[/green]")

    return {'endpoints': endpoints, 'findings': all_findings}
