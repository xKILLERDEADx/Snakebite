"""Broken Access Control Scanner — test vertical and horizontal access control."""

import aiohttp
import asyncio
from urllib.parse import urljoin
from modules.core import console

ADMIN_PATHS = [
    '/admin', '/admin/', '/administrator', '/admin/dashboard',
    '/admin/users', '/admin/settings', '/admin/config',
    '/manage', '/management', '/dashboard', '/internal',
    '/api/admin', '/api/admin/users', '/api/internal',
    '/api/v1/admin', '/v1/admin', '/panel',
    '/backend', '/console', '/system', '/debug',
]

IDOR_PATTERNS = [
    '/api/users/{id}', '/api/user/{id}', '/api/account/{id}',
    '/api/orders/{id}', '/api/invoices/{id}',
    '/api/documents/{id}', '/api/files/{id}',
    '/user/{id}', '/profile/{id}', '/account/{id}',
]

BYPASS_TECHNIQUES = [
    {'name': 'Method Override', 'headers': {'X-HTTP-Method-Override': 'GET'}},
    {'name': 'URL Path Override', 'headers': {'X-Original-URL': '/admin'}},
    {'name': 'Rewrite Override', 'headers': {'X-Rewrite-URL': '/admin'}},
    {'name': 'IP Spoof Localhost', 'headers': {'X-Forwarded-For': '127.0.0.1'}},
    {'name': 'Custom IP Auth', 'headers': {'X-Custom-IP-Authorization': '127.0.0.1'}},
    {'name': 'Real IP Spoof', 'headers': {'X-Real-IP': '127.0.0.1'}},
    {'name': 'Host Override', 'headers': {'X-Forwarded-Host': 'localhost'}},
]

PATH_TRAVERSAL_BYPASSES = [
    '/admin', '/Admin', '/ADMIN', '/aDmIn',
    '/%61dmin', '/admin%20', '/admin%09',
    '/admin..;/', '/admin;/', '/admin/.',
    '//admin', '/./admin', '/../admin',
    '/admin%00', '/admin#', '/admin?',
]


async def _test_admin_access(session, url):
    """Test direct admin panel access."""
    findings = []

    for path in ADMIN_PATHS:
        test_url = urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if len(body) > 100 and 'login' not in body.lower()[:200]:
                        findings.append({
                            'type': 'Admin Panel Accessible',
                            'path': path,
                            'status': resp.status,
                            'severity': 'Critical',
                        })
                elif resp.status == 403:
                    for bypass in BYPASS_TECHNIQUES:
                        try:
                            async with session.get(test_url, headers=bypass['headers'],
                                                   timeout=aiohttp.ClientTimeout(total=5),
                                                   ssl=False, allow_redirects=False) as bypass_resp:
                                if bypass_resp.status == 200:
                                    findings.append({
                                        'type': f"Admin Bypass ({bypass['name']})",
                                        'path': path,
                                        'technique': bypass['name'],
                                        'severity': 'Critical',
                                    })
                        except Exception:
                            pass
        except Exception:
            pass
    return findings


async def _test_idor(session, url):
    """Test for IDOR by accessing sequential IDs."""
    findings = []

    for pattern in IDOR_PATTERNS:
        for test_id in [1, 2, 100, 999, 0]:
            path = pattern.format(id=test_id)
            test_url = urljoin(url, path)
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6),
                                       ssl=False) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            if isinstance(data, dict) and any(k in data for k in ['email', 'name', 'username', 'phone']):
                                findings.append({
                                    'type': 'IDOR — User Data Exposure',
                                    'path': path,
                                    'id': test_id,
                                    'severity': 'High',
                                })
                        except Exception:
                            pass
            except Exception:
                pass
    return findings


async def _test_path_traversal_bypass(session, url):
    """Test access control bypass via path manipulation."""
    findings = []

    for path in PATH_TRAVERSAL_BYPASSES:
        test_url = urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if len(body) > 200 and 'login' not in body.lower()[:200]:
                        findings.append({
                            'type': 'Path Traversal Access Bypass',
                            'path': path,
                            'status': resp.status,
                            'severity': 'High',
                        })
        except Exception:
            pass
    return findings


async def scan_broken_access(session, url):
    """Scan for broken access control vulnerabilities."""
    console.print(f"\n[bold cyan]--- Broken Access Control Scanner ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Testing {len(ADMIN_PATHS)} admin paths...[/cyan]")
    admin_findings = await _test_admin_access(session, url)
    all_findings.extend(admin_findings)
    for f in admin_findings:
        console.print(f"  [bold red]{f['type']}: {f['path']}[/bold red]")

    console.print(f"  [cyan]Testing IDOR ({len(IDOR_PATTERNS)} patterns)...[/cyan]")
    idor_findings = await _test_idor(session, url)
    all_findings.extend(idor_findings)
    for f in idor_findings:
        console.print(f"  [red]IDOR: {f['path']} (ID={f['id']})[/red]")

    console.print(f"  [cyan]Testing {len(PATH_TRAVERSAL_BYPASSES)} path bypasses...[/cyan]")
    path_findings = await _test_path_traversal_bypass(session, url)
    all_findings.extend(path_findings)
    for f in path_findings:
        console.print(f"  [yellow]Path Bypass: {f['path']}[/yellow]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} access control failures![/bold red]")
    else:
        console.print(f"\n  [green]No broken access control detected[/green]")

    return {'findings': all_findings}
