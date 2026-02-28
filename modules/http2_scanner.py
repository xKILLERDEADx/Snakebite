"""HTTP/2 Protocol Scanner — test for HTTP/2 specific vulnerabilities."""

import aiohttp
import asyncio
import ssl
import socket
from urllib.parse import urlparse
from modules.core import console

async def check_http2_support(session, url):
    """Check if target supports HTTP/2 via ALPN negotiation."""
    parsed = urlparse(url)
    host = parsed.netloc.split(':')[0]
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    results = {
        'h2_supported': False,
        'alpn_protocols': [],
        'h1_supported': True,
    }

    if parsed.scheme == 'https':
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2', 'http/1.1'])

            def _check():
                conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
                conn.settimeout(10)
                conn.connect((host, port))
                protocol = conn.selected_alpn_protocol()
                conn.close()
                return protocol

            protocol = await asyncio.get_event_loop().run_in_executor(None, _check)
            if protocol:
                results['alpn_protocols'].append(protocol)
                results['h2_supported'] = protocol == 'h2'

        except Exception as e:
            results['error'] = str(e)[:50]

    return results


async def test_request_smuggling(session, url):
    """Test for HTTP/2 request smuggling indicators."""
    findings = []

    smuggle_payloads = [
        {
            'name': 'CL.TE Header Injection',
            'headers': {
                'Transfer-Encoding': 'chunked',
                'Content-Length': '6',
            },
        },
        {
            'name': 'TE.CL Header confusion',
            'headers': {
                'Transfer-Encoding': ['chunked', 'identity'],
            },
        },
        {
            'name': 'Header Folding',
            'headers': {
                'X-Test': 'value\r\n injected: true',
            },
        },
    ]

    for payload in smuggle_payloads:
        try:
            safe_headers = {}
            for k, v in payload['headers'].items():
                if isinstance(v, list):
                    safe_headers[k] = v[0]
                else:
                    safe_headers[k] = str(v).split('\r\n')[0]

            async with session.get(url, headers=safe_headers,
                                   timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status not in [400, 501]:
                    findings.append({
                        'test': payload['name'],
                        'status': resp.status,
                        'potential': True,
                    })
        except Exception:
            pass
        await asyncio.sleep(0.2)

    return findings


async def test_header_size_limit(session, url):
    """Test for oversized header handling (potential DoS or bypass)."""
    results = {'max_header_size': 0, 'behavior': 'unknown'}

    sizes = [1000, 4000, 8000, 16000, 32000, 65000]
    for size in sizes:
        try:
            headers = {'X-Large-Header': 'A' * size}
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status in [200, 301, 302]:
                    results['max_header_size'] = size
                elif resp.status in [400, 413, 431]:
                    results['behavior'] = f'Rejected at {size} bytes (Status {resp.status})'
                    break
        except Exception:
            results['behavior'] = f'Connection failed at {size} bytes'
            break

    return results


async def scan_http2(session, url):
    """Run HTTP/2 protocol vulnerability scans."""
    console.print(f"\n[bold cyan]--- HTTP/2 Protocol Scanner ---[/bold cyan]")
    console.print(f"  [cyan]Checking HTTP/2 support...[/cyan]")
    h2_results = await check_http2_support(session, url)

    results = {
        'h2_support': h2_results,
        'smuggling': [],
        'header_limits': {},
    }

    if h2_results['h2_supported']:
        console.print(f"  [bold green]✓ HTTP/2 supported (ALPN: h2)[/bold green]")
    else:
        proto = h2_results['alpn_protocols'][0] if h2_results['alpn_protocols'] else 'http/1.1'
        console.print(f"  [dim]HTTP/2 not detected (Protocol: {proto})[/dim]")

    console.print(f"  [cyan]Testing request smuggling indicators...[/cyan]")
    smuggling = await test_request_smuggling(session, url)
    results['smuggling'] = smuggling

    if smuggling:
        console.print(f"  [bold red]⚠ {len(smuggling)} potential smuggling vectors![/bold red]")
        for s in smuggling:
            console.print(f"    [red]{s['test']} — Status {s['status']}[/red]")
    else:
        console.print(f"  [green]✓ No smuggling indicators found[/green]")

    console.print(f"  [cyan]Testing header size limits...[/cyan]")
    header_limits = await test_header_size_limit(session, url)
    results['header_limits'] = header_limits

    if header_limits['max_header_size'] > 0:
        console.print(f"  [dim]Max header accepted: {header_limits['max_header_size']:,} bytes[/dim]")
    console.print(f"  [dim]Behavior: {header_limits['behavior']}[/dim]")

    return results
