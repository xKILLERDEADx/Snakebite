"""Advanced Protocol Fuzzer — deep HTTP/protocol-level fuzzing."""

import aiohttp
import asyncio
import string
import random
from modules.core import console

FUZZ_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT', 'PROPFIND', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
FUZZ_HEADERS = {
    'X-Forwarded-For': ['127.0.0.1', '::1', 'localhost', '10.0.0.1', '192.168.1.1', '0.0.0.0'],
    'X-Forwarded-Host': ['127.0.0.1', 'localhost', 'evil.com'],
    'X-Original-URL': ['/admin', '/internal', '/debug', '/server-status'],
    'X-Rewrite-URL': ['/admin', '/internal', '/actuator'],
    'X-Custom-IP-Authorization': ['127.0.0.1'],
    'X-Real-IP': ['127.0.0.1'],
    'X-Client-IP': ['127.0.0.1'],
    'True-Client-IP': ['127.0.0.1'],
    'Cluster-Client-IP': ['127.0.0.1'],
    'X-ProxyUser-Ip': ['127.0.0.1'],
    'Content-Type': ['application/json', 'application/xml', 'text/xml', 'multipart/form-data',
                     'application/x-www-form-urlencoded', '../etc/passwd', '${7*7}'],
    'Accept': ['../etc/passwd', '${7*7}', '{{7*7}}', '<script>alert(1)</script>'],
}

BOUNDARY_PAYLOADS = [
    'A' * 100,
    'A' * 1000,
    'A' * 10000,
    '\x00' * 100,
    '%00' * 50,
    '%n' * 20,
    '../' * 50,
    '{{' * 50 + '}}' * 50,
    '${' + 'A' * 100 + '}',
    '\r\n' * 20,
    '<' * 100,
    "'" * 100,
    '"' * 100,
]

PATH_FUZZ = [
    '/%2e%2e/', '/.%2e/', '/..;/', '/%2e%2e%2f',
    '/;/', '/.//', '/../', '/..%00/',
    '/%00/', '/%0a/', '/%0d%0a/',
    '/~/', '/!/', '/?/', '/#/',
]


async def _fuzz_methods(session, url):
    """Test unusual HTTP methods for access bypass."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            normal_status = resp.status
    except Exception:
        return findings

    for method in FUZZ_METHODS:
        if method in ('GET', 'HEAD', 'OPTIONS'):
            continue
        try:
            async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False, allow_redirects=False) as resp:
                if resp.status != normal_status and resp.status < 500:
                    body = await resp.text()
                    findings.append({
                        'type': 'HTTP Method Bypass',
                        'method': method,
                        'status': resp.status,
                        'normal_status': normal_status,
                        'length': len(body),
                        'severity': 'Medium' if resp.status == 200 else 'Low',
                    })
        except Exception:
            pass
    return findings


async def _fuzz_headers(session, url):
    """Test header injection and bypass techniques."""
    findings = []

    for header_name, values in FUZZ_HEADERS.items():
        for value in values:
            try:
                headers = {header_name: value}
                async with session.get(url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()

                    if resp.status == 200 and header_name in ('X-Original-URL', 'X-Rewrite-URL'):
                        if value in body or ('admin' in body.lower() and '/admin' in value):
                            findings.append({
                                'type': 'Header-Based Access Bypass',
                                'header': f'{header_name}: {value}',
                                'status': resp.status,
                                'severity': 'High',
                            })

                    if value in body and value not in ('127.0.0.1',):
                        findings.append({
                            'type': 'Header Value Reflection',
                            'header': f'{header_name}: {value}',
                            'status': resp.status,
                            'severity': 'Medium',
                        })
            except Exception:
                pass
    return findings


async def _fuzz_paths(session, url):
    """Test path normalization bypass techniques."""
    findings = []
    base_url = url.rstrip('/')

    for path in PATH_FUZZ:
        test_url = base_url + path
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status == 200:
                    findings.append({
                        'type': 'Path Normalization Bypass',
                        'path': path,
                        'url': test_url,
                        'status': resp.status,
                        'severity': 'Low',
                    })
        except Exception:
            pass
    return findings


async def _fuzz_boundaries(session, url):
    """Test input boundary conditions (buffer overflow, format string, etc.)."""
    findings = []

    for payload in BOUNDARY_PAYLOADS:
        try:
            test_url = f"{url}?input={payload[:500]}"
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                body = await resp.text()

                if resp.status == 500:
                    findings.append({
                        'type': 'Server Error on Boundary Input',
                        'payload': repr(payload[:50]),
                        'status': resp.status,
                        'severity': 'Medium',
                    })
                elif '49' in body and '7*7' in payload:
                    findings.append({
                        'type': 'Template/Expression Injection',
                        'payload': payload[:60],
                        'status': resp.status,
                        'severity': 'High',
                    })
        except Exception:
            pass
    return findings


async def scan_protocol_fuzzer(session, url):
    """Run advanced protocol-level fuzzing."""
    console.print(f"\n[bold cyan]--- Advanced Protocol Fuzzer ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Fuzzing HTTP methods ({len(FUZZ_METHODS)})...[/cyan]")
    method_findings = await _fuzz_methods(session, url)
    all_findings.extend(method_findings)
    for f in method_findings:
        console.print(f"  [yellow]{f['method']} → Status {f['status']} (normal: {f['normal_status']})[/yellow]")

    console.print(f"  [cyan]Fuzzing headers ({len(FUZZ_HEADERS)} headers)...[/cyan]")
    header_findings = await _fuzz_headers(session, url)
    all_findings.extend(header_findings)
    for f in header_findings:
        sev_color = 'red' if f['severity'] == 'High' else 'yellow'
        console.print(f"  [{sev_color}]{f['type']}: {f['header']}[/{sev_color}]")

    console.print(f"  [cyan]Fuzzing path normalization ({len(PATH_FUZZ)} paths)...[/cyan]")
    path_findings = await _fuzz_paths(session, url)
    all_findings.extend(path_findings)
    for f in path_findings:
        console.print(f"  [yellow]Path bypass: {f['path']}[/yellow]")

    console.print(f"  [cyan]Testing boundary conditions ({len(BOUNDARY_PAYLOADS)} payloads)...[/cyan]")
    boundary_findings = await _fuzz_boundaries(session, url)
    all_findings.extend(boundary_findings)
    for f in boundary_findings:
        sev_color = 'red' if f['severity'] == 'High' else 'yellow'
        console.print(f"  [{sev_color}]{f['type']}: {f['payload']}[/{sev_color}]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} protocol fuzzing findings![/bold red]")
    else:
        console.print(f"\n  [green]No protocol-level issues found[/green]")

    return all_findings
