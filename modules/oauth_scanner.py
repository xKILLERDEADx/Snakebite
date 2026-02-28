"""OAuth/SAML Flaw Scanner — detect OAuth redirect, token leakage, SAML flaws."""

import aiohttp
import asyncio
import re
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from modules.core import console

OAUTH_ENDPOINTS = [
    '/oauth/authorize', '/oauth2/authorize', '/auth/authorize',
    '/oauth/token', '/oauth2/token', '/auth/token',
    '/oauth/callback', '/oauth2/callback', '/auth/callback',
    '/login/oauth', '/.well-known/openid-configuration',
    '/connect/authorize', '/api/oauth', '/sso/login',
]

SAML_ENDPOINTS = [
    '/saml/login', '/saml/acs', '/saml/metadata',
    '/saml2/login', '/saml2/acs', '/auth/saml',
    '/sso/saml', '/adfs/ls', '/simplesaml/',
]

REDIRECT_BYPASS_PAYLOADS = [
    'https://evil.com', 'https://evil.com%40target.com', '//evil.com',
    'https://target.com.evil.com', '/.evil.com', '/\\evil.com',
    'https://evil.com#@target.com', 'https://evil.com?.target.com',
    '///evil.com', 'https:evil.com', '\\\\evil.com',
    'https://evil.com/%2f%2f', 'https://evil.com@target.com',
    'data:text/html,<script>alert(1)</script>',
    'javascript:alert(1)', 'https://evil.com/target.com',
]


async def _find_oauth_endpoints(session, url):
    """Discover OAuth/OIDC endpoints."""
    found = []
    for endpoint in OAUTH_ENDPOINTS:
        test_url = urljoin(url, endpoint)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status in [200, 302, 301, 400, 401]:
                    found.append({
                        'url': test_url,
                        'status': resp.status,
                        'type': 'OAuth',
                        'location': resp.headers.get('Location', ''),
                    })
        except Exception:
            pass
    return found


async def _find_saml_endpoints(session, url):
    """Discover SAML/SSO endpoints."""
    found = []
    for endpoint in SAML_ENDPOINTS:
        test_url = urljoin(url, endpoint)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status in [200, 302, 301, 400]:
                    body = await resp.text()
                    if any(kw in body.lower() for kw in ['saml', 'assertion', 'sso', 'entityid']):
                        found.append({
                            'url': test_url,
                            'status': resp.status,
                            'type': 'SAML',
                        })
        except Exception:
            pass
    return found


async def _test_redirect_bypass(session, endpoint_url):
    """Test OAuth redirect_uri bypass techniques."""
    findings = []
    for payload in REDIRECT_BYPASS_PAYLOADS:
        try:
            params = {'redirect_uri': payload, 'response_type': 'code', 'client_id': 'test'}
            async with session.get(endpoint_url, params=params,
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=False) as resp:
                location = resp.headers.get('Location', '')
                if payload.replace('https://', '').replace('http://', '').split('/')[0] in location:
                    findings.append({
                        'type': 'OAuth Redirect Bypass',
                        'payload': payload,
                        'redirect': location[:120],
                        'severity': 'Critical',
                    })
                if resp.status == 200:
                    body = await resp.text()
                    if 'code=' in body or 'token=' in body:
                        findings.append({
                            'type': 'OAuth Token Leakage',
                            'payload': payload,
                            'severity': 'Critical',
                        })
        except Exception:
            pass
    return findings


async def _test_token_exposure(session, url):
    """Check for token exposure in URLs, referrer, etc."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            body = await resp.text()
            final_url = str(resp.url)
            if 'access_token=' in final_url or 'token=' in final_url:
                findings.append({
                    'type': 'Token in URL',
                    'url': final_url[:120],
                    'severity': 'High',
                })
            token_patterns = [
                r'access_token["\s]*[:=]\s*["\']([^"\']+)',
                r'id_token["\s]*[:=]\s*["\']([^"\']+)',
                r'refresh_token["\s]*[:=]\s*["\']([^"\']+)',
            ]
            for pattern in token_patterns:
                matches = re.findall(pattern, body)
                if matches:
                    findings.append({
                        'type': 'Token Exposed in Page',
                        'pattern': pattern[:40],
                        'severity': 'High',
                    })
    except Exception:
        pass
    return findings


async def scan_oauth_saml(session, url):
    """Scan for OAuth and SAML vulnerabilities."""
    console.print(f"\n[bold cyan]--- OAuth/SAML Flaw Scanner ---[/bold cyan]")

    results = {'oauth_endpoints': [], 'saml_endpoints': [], 'vulnerabilities': []}

    console.print(f"  [cyan]Scanning {len(OAUTH_ENDPOINTS)} OAuth endpoints...[/cyan]")
    oauth_eps = await _find_oauth_endpoints(session, url)
    results['oauth_endpoints'] = oauth_eps

    for ep in oauth_eps:
        console.print(f"  [green]OAuth: {ep['url']} ({ep['status']})[/green]")

    console.print(f"  [cyan]Scanning {len(SAML_ENDPOINTS)} SAML endpoints...[/cyan]")
    saml_eps = await _find_saml_endpoints(session, url)
    results['saml_endpoints'] = saml_eps

    for ep in saml_eps:
        console.print(f"  [green]SAML: {ep['url']} ({ep['status']})[/green]")

    if oauth_eps:
        console.print(f"\n  [yellow]Testing redirect_uri bypass ({len(REDIRECT_BYPASS_PAYLOADS)} payloads)...[/yellow]")
        for ep in oauth_eps:
            if 'authorize' in ep['url']:
                bypasses = await _test_redirect_bypass(session, ep['url'])
                results['vulnerabilities'].extend(bypasses)
                for v in bypasses:
                    console.print(f"  [bold red]⚠ {v['type']}: {v['payload'][:60]}[/bold red]")

    console.print(f"  [cyan]Checking token exposure...[/cyan]")
    exposure = await _test_token_exposure(session, url)
    results['vulnerabilities'].extend(exposure)
    for v in exposure:
        console.print(f"  [red]⚠ {v['type']}[/red]")

    if not results['vulnerabilities']:
        console.print(f"\n  [green]✓ No OAuth/SAML vulnerabilities found[/green]")
    else:
        console.print(f"\n  [bold red]{len(results['vulnerabilities'])} auth flaws found![/bold red]")

    return results
