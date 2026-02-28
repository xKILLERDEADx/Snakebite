"""OAuth2 Full Chain — authorization code theft, PKCE bypass, token exchange abuse."""

import aiohttp
import asyncio
import re
import hashlib
import base64
import secrets
from urllib.parse import urljoin, urlparse, parse_qs
from modules.core import console

OAUTH_ENDPOINTS = {
    'authorize': ['/oauth/authorize', '/authorize', '/auth', '/oauth2/authorize',
                  '/api/oauth/authorize', '/connect/authorize', '/oauth/auth'],
    'token': ['/oauth/token', '/token', '/api/token', '/oauth2/token',
              '/connect/token', '/api/oauth/token'],
    'userinfo': ['/oauth/userinfo', '/userinfo', '/api/me', '/oauth2/userinfo',
                 '/connect/userinfo', '/api/user'],
    'openid': ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server'],
}

async def _discover_oauth(session, url):
    """Discover OAuth2/OIDC endpoints."""
    discovered = {}

    for endpoint_type, paths in OAUTH_ENDPOINTS.items():
        for path in paths:
            test_url = urljoin(url, path)
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6),
                                       ssl=False, allow_redirects=False) as resp:
                    if resp.status in (200, 302, 400, 401):
                        if endpoint_type not in discovered:
                            discovered[endpoint_type] = test_url

                        if endpoint_type == 'openid' and resp.status == 200:
                            try:
                                data = await resp.json(content_type=None)
                                if 'authorization_endpoint' in data:
                                    discovered['authorize'] = data['authorization_endpoint']
                                if 'token_endpoint' in data:
                                    discovered['token'] = data['token_endpoint']
                                if 'userinfo_endpoint' in data:
                                    discovered['userinfo'] = data['userinfo_endpoint']
                                discovered['openid_config'] = data
                            except Exception:
                                pass
            except Exception:
                pass

    return discovered


async def _test_redirect_manipulation(session, auth_url):
    """Test for OAuth redirect_uri manipulation."""
    findings = []
    evil_redirects = [
        'https://evil.com/callback',
        'https://evil.com%40legitimate.com/callback',
        'https://legitimate.com.evil.com/callback',
        'https://legitimate.com/callback/../../../evil',
        'https://legitimate.com/callback%23@evil.com',
        'http://legitimate.com/callback',
        'https://legitimate.com/callback?next=https://evil.com',
    ]

    for redirect in evil_redirects:
        try:
            params = {
                'response_type': 'code',
                'client_id': 'test',
                'redirect_uri': redirect,
                'scope': 'openid',
            }
            async with session.get(auth_url, params=params,
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status in (302, 301):
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location:
                        findings.append({
                            'type': 'OAuth Redirect URI Bypass',
                            'redirect': redirect[:50],
                            'severity': 'Critical',
                            'detail': f'Server redirected to: {location[:60]}',
                        })
                elif resp.status == 200:
                    body = await resp.text()
                    if 'error' not in body.lower():
                        findings.append({
                            'type': 'OAuth Redirect URI Not Validated',
                            'redirect': redirect[:50],
                            'severity': 'High',
                        })
        except Exception:
            pass

    return findings


async def _test_pkce_bypass(session, auth_url, token_url):
    """Test PKCE bypass — authorization without code_verifier."""
    findings = []
    if not token_url:
        return findings

    try:
        params = {
            'response_type': 'code',
            'client_id': 'test',
            'redirect_uri': 'http://localhost/callback',
            'code_challenge': base64.urlsafe_b64encode(hashlib.sha256(b'test').digest()).rstrip(b'=').decode(),
            'code_challenge_method': 'S256',
        }
        async with session.get(auth_url, params=params,
                               timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=False) as resp:
            if resp.status in (302, 200):
                token_data = {
                    'grant_type': 'authorization_code',
                    'code': 'test_code',
                    'client_id': 'test',
                    'redirect_uri': 'http://localhost/callback',
                }
                async with session.post(token_url, data=token_data,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as token_resp:
                    body = await token_resp.text()
                    if token_resp.status == 200 and 'access_token' in body:
                        findings.append({
                            'type': 'PKCE Bypass — No code_verifier Required',
                            'severity': 'Critical',
                        })
                    elif 'invalid_grant' in body and 'code_verifier' not in body.lower():
                        findings.append({
                            'type': 'PKCE May Be Bypassable',
                            'severity': 'Medium',
                            'detail': 'Server did not mention code_verifier in error',
                        })
    except Exception:
        pass

    return findings


async def _test_token_leakage(session, auth_url):
    """Test implicit flow token leakage."""
    findings = []
    try:
        params = {
            'response_type': 'token',
            'client_id': 'test',
            'redirect_uri': 'http://localhost/callback',
            'scope': 'openid profile',
        }
        async with session.get(auth_url, params=params,
                               timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=False) as resp:
            if resp.status in (302, 301):
                location = resp.headers.get('Location', '')
                if 'access_token=' in location:
                    findings.append({
                        'type': 'Implicit Flow Token Leakage',
                        'severity': 'High',
                        'detail': 'Token exposed in URL fragment',
                    })
            if resp.status == 200:
                body = await resp.text()
                if 'implicit' not in body.lower() or 'error' not in body.lower():
                    findings.append({
                        'type': 'Implicit Flow Allowed',
                        'severity': 'Medium',
                    })
    except Exception:
        pass

    return findings


async def scan_oauth2_chain(session, url):
    """Full OAuth2/OIDC security chain analysis."""
    console.print(f"\n[bold cyan]--- OAuth2 Full Chain Scanner ---[/bold cyan]")

    console.print(f"  [cyan]Discovering OAuth endpoints...[/cyan]")
    endpoints = await _discover_oauth(session, url)

    if not endpoints:
        console.print(f"  [dim]No OAuth endpoints found[/dim]")
        return {'endpoints': {}, 'findings': []}

    console.print(f"  [green]Found: {', '.join(endpoints.keys())}[/green]")
    all_findings = []

    auth_url = endpoints.get('authorize')
    token_url = endpoints.get('token')

    if auth_url:
        console.print(f"  [cyan]Testing redirect URI manipulation (7 bypasses)...[/cyan]")
        redirect = await _test_redirect_manipulation(session, auth_url)
        all_findings.extend(redirect)
        for f in redirect:
            console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

        console.print(f"  [cyan]Testing PKCE bypass...[/cyan]")
        pkce = await _test_pkce_bypass(session, auth_url, token_url)
        all_findings.extend(pkce)

        console.print(f"  [cyan]Testing implicit flow leakage...[/cyan]")
        implicit = await _test_token_leakage(session, auth_url)
        all_findings.extend(implicit)

    if 'openid_config' in endpoints:
        config = endpoints['openid_config']
        if isinstance(config, dict):
            grants = config.get('grant_types_supported', [])
            if 'implicit' in grants:
                all_findings.append({
                    'type': 'Implicit Grant Supported (Deprecated)',
                    'severity': 'Medium',
                })
            if 'password' in grants or 'client_credentials' in grants:
                all_findings.append({
                    'type': f'Risky Grant Types: {[g for g in grants if g in ("password","client_credentials")]}',
                    'severity': 'Medium',
                })

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} OAuth2 vulnerabilities![/bold red]")
    else:
        console.print(f"\n  [green]✓ OAuth2 configuration looks secure[/green]")

    return {'endpoints': {k: v for k, v in endpoints.items() if k != 'openid_config'}, 'findings': all_findings}
