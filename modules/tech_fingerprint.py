"""Deep Technology Fingerprinter — detect exact framework versions and hidden tech."""

import aiohttp
import asyncio
import re
import hashlib
from urllib.parse import urlparse, urljoin
from modules.core import console

FRAMEWORK_SIGNATURES = {
    'React': {
        'paths': ['/static/js/main.', '/static/js/bundle.'],
        'headers': {},
        'body': ['_reactRootContainer', 'data-reactroot', '__NEXT_DATA__', 'react-app'],
        'meta': ['react'],
    },
    'Next.js': {
        'paths': ['/_next/static/', '/_next/data/'],
        'headers': {'x-powered-by': 'Next.js'},
        'body': ['__NEXT_DATA__', '_next/static', 'next/head'],
    },
    'Vue.js': {
        'paths': ['/js/app.', '/js/chunk-'],
        'body': ['__vue__', 'v-cloak', 'data-v-', 'vue-router', 'Vue.component'],
    },
    'Angular': {
        'paths': ['/main.', '/polyfills.', '/runtime.'],
        'body': ['ng-version', 'ng-app', 'angular.min.js', 'ng-controller'],
    },
    'Laravel': {
        'headers': {'set-cookie': 'laravel_session'},
        'body': ['laravel', 'csrf-token'],
        'paths': ['/vendor/laravel/', '/_ignition/'],
    },
    'Django': {
        'headers': {'set-cookie': 'csrftoken'},
        'body': ['csrfmiddlewaretoken', '__admin__', 'django'],
        'paths': ['/admin/login/', '/static/admin/'],
    },
    'Flask': {
        'headers': {'server': 'Werkzeug'},
        'body': ['flask', 'werkzeug'],
    },
    'Express.js': {
        'headers': {'x-powered-by': 'Express'},
    },
    'Ruby on Rails': {
        'headers': {'x-powered-by': 'Phusion Passenger', 'set-cookie': '_session_id'},
        'body': ['rails', 'csrf-param', 'authenticity_token'],
        'meta': ['csrf-param'],
    },
    'ASP.NET': {
        'headers': {'x-powered-by': 'ASP.NET', 'x-aspnet-version': ''},
        'body': ['__VIEWSTATE', '__EVENTVALIDATION', 'aspnet'],
    },
    'Spring Boot': {
        'paths': ['/actuator', '/actuator/health', '/actuator/info'],
        'headers': {},
        'body': ['whitelabel error', 'spring'],
    },
    'Nuxt.js': {
        'body': ['__NUXT__', 'nuxt', '_nuxt'],
        'paths': ['/_nuxt/'],
    },
    'Gatsby': {
        'body': ['gatsby', '___gatsby'],
        'paths': ['/page-data/', '/static/'],
    },
    'Svelte': {
        'body': ['svelte', '__svelte'],
    },
    'jQuery': {
        'body': ['jquery', 'jQuery'],
    },
    'Bootstrap': {
        'body': ['bootstrap.min', 'bootstrap.css', 'btn btn-'],
    },
    'Tailwind CSS': {
        'body': ['tailwindcss', 'tw-'],
    },
}

SERVER_SIGNATURES = {
    'Nginx': r'nginx/?(\d+\.[\d.]+)?',
    'Apache': r'Apache/?(\d+\.[\d.]+)?',
    'IIS': r'Microsoft-IIS/?(\d+\.[\d.]+)?',
    'LiteSpeed': r'LiteSpeed/?(\d+\.[\d.]+)?',
    'Caddy': r'Caddy/?(\d+\.[\d.]+)?',
    'Gunicorn': r'gunicorn/?(\d+\.[\d.]+)?',
    'Tomcat': r'tomcat/?(\d+\.[\d.]+)?',
}


async def scan_tech_fingerprint(session, url):
    """Deep technology fingerprinting with version detection."""
    console.print(f"\n[bold cyan]--- Deep Technology Fingerprinter ---[/bold cyan]")

    results = {
        'frameworks': [],
        'server': {},
        'technologies': [],
        'versions': {},
    }

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            body = await resp.text()
            headers = {k.lower(): v for k, v in resp.headers.items()}

            server = headers.get('server', '')
            if server:
                results['server']['raw'] = server
                for name, pattern in SERVER_SIGNATURES.items():
                    match = re.search(pattern, server, re.I)
                    if match:
                        results['server']['name'] = name
                        results['server']['version'] = match.group(1) if match.group(1) else 'unknown'
                        console.print(f"  [green]Server: {name} {match.group(1) or ''}[/green]")

            xpb = headers.get('x-powered-by', '')
            if xpb:
                results['technologies'].append({'name': 'X-Powered-By', 'value': xpb})
                console.print(f"  [green]Powered By: {xpb}[/green]")

            for fw_name, sigs in FRAMEWORK_SIGNATURES.items():
                detected = False
                for header_key, header_val in sigs.get('headers', {}).items():
                    if header_key in headers:
                        if not header_val or header_val.lower() in headers[header_key].lower():
                            detected = True

                if not detected:
                    for keyword in sigs.get('body', []):
                        if keyword.lower() in body.lower():
                            detected = True
                            break

                if detected:
                    results['frameworks'].append(fw_name)
                    console.print(f"  [cyan]Framework: {fw_name}[/cyan]")

            version_patterns = {
                'jQuery': r'jquery[/\-\s]v?(\d+\.\d+(?:\.\d+)?)',
                'Bootstrap': r'bootstrap[/\-\s]v?(\d+\.\d+(?:\.\d+)?)',
                'React': r'react[/\-\s]v?(\d+\.\d+(?:\.\d+)?)',
                'Angular': r'angular[/\-\s]v?(\d+\.\d+(?:\.\d+)?)',
                'Vue.js': r'vue[/\-\s]v?(\d+\.\d+(?:\.\d+)?)',
                'WordPress': r'WordPress\s+(\d+\.\d+(?:\.\d+)?)',
                'PHP': r'PHP/(\d+\.\d+(?:\.\d+)?)',
            }
            for tech, pattern in version_patterns.items():
                match = re.search(pattern, body + ' ' + str(headers), re.I)
                if match:
                    results['versions'][tech] = match.group(1)
                    console.print(f"  [yellow]Version: {tech} {match.group(1)}[/yellow]")

    except Exception as e:
        console.print(f"  [red]Error: {e}[/red]")

    for path_fw, sigs in FRAMEWORK_SIGNATURES.items():
        if path_fw in results['frameworks']:
            continue
        for path in sigs.get('paths', []):
            try:
                test_url = urljoin(url, path)
                async with session.head(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                        ssl=False) as resp:
                    if resp.status == 200:
                        results['frameworks'].append(path_fw)
                        console.print(f"  [cyan]Framework (path): {path_fw}[/cyan]")
                        break
            except Exception:
                pass

    console.print(f"\n  [bold]Summary: {len(results['frameworks'])} frameworks, {len(results['versions'])} versions detected[/bold]")

    return results
