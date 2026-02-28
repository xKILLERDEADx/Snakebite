"""BOLA/BFLA Scanner — Broken Object Level Authorization (OWASP API Top 10)."""

import aiohttp
import asyncio
import json
import re
from urllib.parse import urljoin
from modules.core import console

API_ENDPOINTS = [
    '/api/users/{id}', '/api/user/{id}', '/api/accounts/{id}',
    '/api/orders/{id}', '/api/invoices/{id}', '/api/payments/{id}',
    '/api/documents/{id}', '/api/files/{id}', '/api/messages/{id}',
    '/api/posts/{id}', '/api/comments/{id}', '/api/tickets/{id}',
    '/api/v1/users/{id}', '/api/v1/orders/{id}', '/api/v1/accounts/{id}',
    '/api/v2/users/{id}', '/api/v2/resources/{id}',
    '/users/{id}', '/accounts/{id}', '/orders/{id}',
    '/profile/{id}', '/settings/{id}', '/data/{id}',
]

BFLA_ACTIONS = [
    {'method': 'DELETE', 'path': '/api/users/{id}'},
    {'method': 'PUT', 'path': '/api/users/{id}', 'body': {'role': 'admin'}},
    {'method': 'PATCH', 'path': '/api/users/{id}', 'body': {'is_admin': True}},
    {'method': 'POST', 'path': '/api/admin/users', 'body': {'username': 'test'}},
    {'method': 'DELETE', 'path': '/api/orders/{id}'},
    {'method': 'PUT', 'path': '/api/settings/{id}', 'body': {'debug': True}},
]


async def _test_bola(session, url, endpoint, test_ids):
    """Test BOLA by accessing resources with different IDs."""
    findings = []
    accessible_ids = []

    for tid in test_ids:
        path = endpoint.format(id=tid)
        test_url = urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6),
                                   ssl=False) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json()
                        if isinstance(data, dict) and len(data) > 0:
                            has_pii = any(k in str(data).lower() for k in
                                          ['email', 'phone', 'address', 'ssn', 'password', 'credit'])
                            accessible_ids.append({
                                'id': tid,
                                'has_pii': has_pii,
                                'fields': list(data.keys())[:10] if isinstance(data, dict) else [],
                            })
                    except Exception:
                        body = await resp.text()
                        if len(body) > 50:
                            accessible_ids.append({'id': tid, 'has_pii': False})
        except Exception:
            pass

    if len(accessible_ids) >= 2:
        has_pii = any(a.get('has_pii') for a in accessible_ids)
        findings.append({
            'type': 'BOLA — Multiple Object Access',
            'endpoint': endpoint,
            'accessible_ids': [a['id'] for a in accessible_ids],
            'pii_exposed': has_pii,
            'severity': 'Critical' if has_pii else 'High',
            'fields': accessible_ids[0].get('fields', []),
        })

    return findings


async def _test_bfla(session, url):
    """Test BFLA — unauthorized function-level actions."""
    findings = []

    for action in BFLA_ACTIONS:
        path = action['path'].format(id=1)
        test_url = urljoin(url, path)
        method = action['method']
        body = action.get('body', {})

        try:
            async with session.request(method, test_url, json=body,
                                       timeout=aiohttp.ClientTimeout(total=6),
                                       ssl=False) as resp:
                if resp.status in [200, 201, 204]:
                    findings.append({
                        'type': f'BFLA — {method} Accepted',
                        'endpoint': path,
                        'method': method,
                        'severity': 'Critical' if method == 'DELETE' else 'High',
                    })
        except Exception:
            pass

    return findings


async def scan_bola(session, url):
    """Scan for BOLA/BFLA (OWASP API Security Top 10)."""
    console.print(f"\n[bold cyan]--- BOLA/BFLA Scanner (API Top 10) ---[/bold cyan]")

    test_ids = [1, 2, 3, 100, 999, 0]
    all_findings = []

    console.print(f"  [cyan]Testing {len(API_ENDPOINTS)} endpoints for BOLA...[/cyan]")
    for endpoint in API_ENDPOINTS:
        findings = await _test_bola(session, url, endpoint, test_ids)
        all_findings.extend(findings)
        for f in findings:
            pii_tag = ' [PII!]' if f.get('pii_exposed') else ''
            console.print(f"  [red]⚠ {f['type']}: {f['endpoint']}{pii_tag}[/red]")
            if f.get('fields'):
                console.print(f"    [dim]Fields: {', '.join(f['fields'][:5])}[/dim]")

    console.print(f"\n  [cyan]Testing {len(BFLA_ACTIONS)} admin actions for BFLA...[/cyan]")
    bfla_findings = await _test_bfla(session, url)
    all_findings.extend(bfla_findings)
    for f in bfla_findings:
        console.print(f"  [bold red]⚠ {f['type']}: {f['method']} {f['endpoint']}[/bold red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} authorization failures![/bold red]")
    else:
        console.print(f"\n  [green]✓ No BOLA/BFLA vulnerabilities detected[/green]")

    return {'findings': all_findings}
