"""API Schema Reconstructor — auto-discover undocumented API endpoints, build OpenAPI spec."""

import aiohttp
import asyncio
import re
import json
from urllib.parse import urljoin, urlparse
from modules.core import console

API_PREFIXES = ['/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/rest', '/ajax']

COMMON_ENDPOINTS = [
    'users', 'user', 'auth', 'login', 'register', 'logout', 'token', 'refresh',
    'profile', 'account', 'settings', 'config', 'admin', 'dashboard',
    'posts', 'comments', 'messages', 'notifications', 'search', 'upload',
    'files', 'images', 'media', 'products', 'orders', 'cart', 'checkout',
    'payments', 'invoices', 'categories', 'tags', 'roles', 'permissions',
    'logs', 'events', 'analytics', 'reports', 'export', 'import',
    'health', 'status', 'info', 'version', 'docs', 'swagger', 'openapi',
    'graphql', 'webhooks', 'callbacks', 'cron', 'jobs', 'queue',
    'sessions', 'tokens', 'keys', 'secrets', 'certs', 'debug', 'test',
]

METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']


async def _discover_from_page(session, url):
    """Extract API endpoints from HTML/JS sources."""
    endpoints = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            api_patterns = [
                r'["\'](/api/[^"\'\s<>]+)["\']',
                r'["\'](/v\d+/[^"\'\s<>]+)["\']',
                r'["\'](/rest/[^"\'\s<>]+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
                r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
                r'XMLHttpRequest[^;]*open\s*\([^,]*,\s*["\']([^"\']+)["\']',
            ]
            for pattern in api_patterns:
                matches = re.findall(pattern, body)
                for match in matches:
                    if match.startswith('/') or match.startswith('http'):
                        endpoints.add(match)

            script_sources = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
            for src in script_sources[:10]:
                js_url = urljoin(url, src)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as js_resp:
                        if js_resp.status == 200:
                            js_body = await js_resp.text()
                            for pattern in api_patterns:
                                for match in re.findall(pattern, js_body):
                                    if match.startswith('/') or 'api' in match.lower():
                                        endpoints.add(match)
                except Exception:
                    pass
    except Exception:
        pass
    return endpoints


async def _brute_endpoints(session, url):
    """Brute force common API endpoints."""
    discovered = []
    for prefix in API_PREFIXES:
        for endpoint in COMMON_ENDPOINTS:
            test_url = urljoin(url, f'{prefix}/{endpoint}')
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=4), ssl=False) as resp:
                    if resp.status not in (404, 403, 405, 500, 502, 503):
                        ct = resp.headers.get('Content-Type', '')
                        body = await resp.text()
                        if 'json' in ct or body.startswith('{') or body.startswith('['):
                            discovered.append({
                                'path': f'{prefix}/{endpoint}',
                                'status': resp.status, 'content_type': ct,
                                'response_size': len(body),
                            })
                        elif resp.status == 200 and len(body) > 10:
                            discovered.append({
                                'path': f'{prefix}/{endpoint}',
                                'status': resp.status, 'content_type': ct,
                                'response_size': len(body),
                            })
            except Exception:
                pass
    return discovered


async def _test_methods(session, url, endpoints):
    """Test HTTP methods on discovered endpoints."""
    method_map = {}
    for ep in endpoints[:20]:
        path = ep if isinstance(ep, str) else ep.get('path', '')
        test_url = urljoin(url, path)
        allowed = []
        for method in METHODS:
            try:
                async with session.request(method, test_url, timeout=aiohttp.ClientTimeout(total=4),
                                           ssl=False) as resp:
                    if resp.status not in (404, 405):
                        allowed.append(method)
            except Exception:
                pass
        if allowed:
            method_map[path] = allowed
    return method_map


async def _check_docs(session, url):
    """Check for exposed API documentation."""
    findings = []
    doc_paths = ['/swagger.json', '/openapi.json', '/api-docs', '/swagger-ui.html',
                 '/swagger-ui/', '/api/swagger.json', '/v1/swagger.json',
                 '/docs', '/api/docs', '/redoc', '/api-docs.json', '/swagger.yaml',
                 '/.well-known/openapi.json', '/api/openapi.json']
    for path in doc_paths:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if any(k in body for k in ['swagger', 'openapi', 'paths', 'definitions', 'schemas']):
                        findings.append({'type': f'API Docs Exposed: {path}', 'severity': 'High',
                                         'detail': f'OpenAPI/Swagger spec accessible ({len(body)} bytes)'})
        except Exception:
            pass
    return findings


async def scan_api_reconstruct(session, url):
    console.print(f"\n[bold cyan]--- API Schema Reconstructor ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Extracting API refs from HTML/JS...[/cyan]")
    page_eps = await _discover_from_page(session, url)
    console.print(f"  [dim]Found {len(page_eps)} API references in page[/dim]")

    console.print(f"  [cyan]Brute-forcing {len(API_PREFIXES)}×{len(COMMON_ENDPOINTS)} endpoints...[/cyan]")
    brute_eps = await _brute_endpoints(session, url)
    console.print(f"  [green]{len(brute_eps)} live API endpoints discovered[/green]")

    for ep in brute_eps:
        all_findings.append({'type': f'API Endpoint: {ep["path"]}', 'severity': 'Medium',
                             'status': ep['status'], 'size': ep['response_size']})

    console.print(f"  [cyan]Testing HTTP methods on endpoints...[/cyan]")
    methods = await _test_methods(session, url, brute_eps)
    for path, allowed in methods.items():
        if 'DELETE' in allowed or 'PUT' in allowed:
            all_findings.append({'type': f'Write Methods on {path}: {allowed}', 'severity': 'High'})

    console.print(f"  [cyan]Checking API documentation exposure...[/cyan]")
    docs = await _check_docs(session, url)
    all_findings.extend(docs)
    for f in docs:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

    if all_findings:
        console.print(f"\n  [bold]{len(all_findings)} API findings[/bold]")
    else:
        console.print(f"\n  [green]✓ No undocumented APIs found[/green]")

    return {'page_refs': list(page_eps), 'live_endpoints': brute_eps,
            'methods': methods, 'findings': all_findings}
