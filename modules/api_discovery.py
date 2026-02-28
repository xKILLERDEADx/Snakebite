"""Smart API Endpoint Discoverer — find hidden API routes and test them."""

import aiohttp
import asyncio
import json
import re
from urllib.parse import urljoin, urlparse
from modules.core import console

API_PATHS = [
    '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4',
    '/rest', '/rest/v1', '/rest/v2',
    '/graphql', '/gql', '/graphiql',
    '/swagger.json', '/openapi.json', '/api-docs',
    '/swagger-ui.html', '/swagger-ui/', '/redoc',
    '/api/docs', '/api/schema', '/api/spec',
    '/api/health', '/api/status', '/api/info', '/api/version',
    '/api/config', '/api/settings', '/api/env',
    '/api/users', '/api/user', '/api/account', '/api/accounts',
    '/api/admin', '/api/auth', '/api/login', '/api/register',
    '/api/upload', '/api/files', '/api/download',
    '/api/search', '/api/query', '/api/data',
    '/api/export', '/api/import', '/api/backup',
    '/api/webhooks', '/api/hooks', '/api/events',
    '/api/keys', '/api/tokens', '/api/sessions',
    '/api/logs', '/api/audit', '/api/debug',
    '/api/internal', '/api/private', '/api/hidden',
    '/_api', '/v1', '/v2', '/v3',
    '/jsonapi', '/json-api', '/api.php', '/api.json',
    '/wp-json/', '/wp-json/wp/v2/users',
    '/api/graphql', '/api/rest',
]

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

SENSITIVE_PATTERNS = [
    r'"(?:password|secret|token|key|api_key|apikey|auth)"',
    r'"(?:email|phone|ssn|card|credit)"',
    r'"(?:admin|root|superuser)"',
    r'"(?:internal|private|debug|config)"',
    r'(?:BEGIN|PRIVATE|RSA)\s+KEY',
]


async def _probe_endpoint(session, url, path):
    """Probe a single API endpoint."""
    test_url = urljoin(url, path)
    try:
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=False) as resp:
            body = await resp.text()
            content_type = resp.headers.get('Content-Type', '')

            is_api = (
                'json' in content_type or
                'xml' in content_type or
                body.strip().startswith('{') or
                body.strip().startswith('[') or
                body.strip().startswith('<?xml')
            )

            if resp.status == 200 and (is_api or len(body) > 10):
                sensitive = []
                for pattern in SENSITIVE_PATTERNS:
                    if re.search(pattern, body, re.I):
                        sensitive.append(pattern[:30])

                return {
                    'url': test_url,
                    'status': resp.status,
                    'content_type': content_type[:50],
                    'size': len(body),
                    'is_json': is_api,
                    'sensitive': sensitive,
                    'severity': 'Critical' if sensitive else 'Medium' if is_api else 'Low',
                    'path': path,
                }
            elif resp.status in [401, 403]:
                return {
                    'url': test_url,
                    'status': resp.status,
                    'content_type': content_type[:50],
                    'size': len(body),
                    'is_json': is_api,
                    'sensitive': [],
                    'severity': 'Low',
                    'path': path,
                    'auth_required': True,
                }
    except Exception:
        pass
    return None


async def _test_methods(session, endpoint_url):
    """Test which HTTP methods an endpoint accepts."""
    methods = []
    for method in HTTP_METHODS:
        try:
            async with session.request(method, endpoint_url,
                                       timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False, allow_redirects=False) as resp:
                if resp.status not in [404, 405, 501]:
                    methods.append({'method': method, 'status': resp.status})
        except Exception:
            pass
    return methods


async def _extract_from_js(session, url):
    """Extract API endpoints from JS files."""
    endpoints = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            js_files = re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body)

            for js_file in js_files[:10]:
                js_url = urljoin(url, js_file)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=8),
                                           ssl=False) as js_resp:
                        js_body = await js_resp.text()
                        api_patterns = [
                            r'["\'](/api/[a-zA-Z0-9/_-]+)["\']',
                            r'["\'](/v[1-3]/[a-zA-Z0-9/_-]+)["\']',
                            r'["\'](/rest/[a-zA-Z0-9/_-]+)["\']',
                            r'fetch\(["\']([^"\']+)["\']',
                            r'axios\.\w+\(["\']([^"\']+)["\']',
                            r'\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
                        ]
                        for pattern in api_patterns:
                            matches = re.findall(pattern, js_body)
                            for match in matches:
                                if match.startswith('/'):
                                    endpoints.add(match)
                except Exception:
                    pass
    except Exception:
        pass

    return endpoints


async def scan_api_discovery(session, url):
    """Discover and test API endpoints."""
    console.print(f"\n[bold cyan]--- Smart API Endpoint Discovery ---[/bold cyan]")

    results = {'endpoints': [], 'sensitive': [], 'js_extracted': []}

    console.print(f"  [cyan]Probing {len(API_PATHS)} common API paths...[/cyan]")
    tasks = [_probe_endpoint(session, url, path) for path in API_PATHS]
    found = await asyncio.gather(*tasks)

    for result in found:
        if result:
            results['endpoints'].append(result)
            sev_color = 'red' if result['severity'] == 'Critical' else 'yellow' if result['severity'] == 'Medium' else 'dim'
            auth_tag = ' [AUTH]' if result.get('auth_required') else ''
            console.print(f"  [{sev_color}]{result['path']} ({result['status']}) [{result['content_type'][:20]}]{auth_tag}[/{sev_color}]")
            if result.get('sensitive'):
                console.print(f"    [bold red]⚠ Sensitive data detected![/bold red]")
                results['sensitive'].append(result)

    console.print(f"\n  [cyan]Extracting API routes from JavaScript...[/cyan]")
    js_endpoints = await _extract_from_js(session, url)

    for ep in sorted(js_endpoints):
        if not any(e['path'] == ep for e in results['endpoints']):
            probe = await _probe_endpoint(session, url, ep)
            if probe:
                results['endpoints'].append(probe)
                results['js_extracted'].append(ep)
                console.print(f"  [green]JS-discovered: {ep} ({probe['status']})[/green]")

    if results['endpoints']:
        console.print(f"\n  [bold]{len(results['endpoints'])} API endpoints found[/bold]")
        if results['sensitive']:
            console.print(f"  [bold red]{len(results['sensitive'])} with sensitive data exposure![/bold red]")
    else:
        console.print(f"\n  [green]✓ No exposed API endpoints found[/green]")

    return results
