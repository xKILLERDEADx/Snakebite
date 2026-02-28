"""Attack Surface Mapper — full automatic attack surface mapping with priority."""

import aiohttp
import asyncio
import re
import socket
from urllib.parse import urlparse, urljoin
from modules.core import console

ATTACK_VECTORS = {
    'Entry Points': {
        'forms': [],
        'api_endpoints': [],
        'upload_points': [],
        'authentication': [],
        'websockets': [],
    },
    'Information Disclosure': {
        'exposed_data': [],
        'error_pages': [],
        'version_info': [],
    },
    'Infrastructure': {
        'open_ports': [],
        'services': [],
        'technologies': [],
    },
}


async def _map_forms(session, url):
    """Discover HTML forms as entry points."""
    forms = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()

            form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>'
            matches = re.findall(form_pattern, body, re.DOTALL | re.I)

            for action, content in matches:
                inputs = re.findall(r'<input[^>]*name=["\']?([^"\'>\s]*)["\']?[^>]*>', content, re.I)
                method_match = re.search(r'method=["\']?(GET|POST)["\']?', content, re.I)
                method = method_match.group(1).upper() if method_match else 'GET'
                form_type = 'Login' if any(t in content.lower() for t in ['password', 'login', 'signin']) else \
                            'Upload' if 'type="file"' in content.lower() else \
                            'Search' if any(t in content.lower() for t in ['search', 'query']) else 'Generic'

                forms.append({
                    'action': action or url,
                    'method': method,
                    'inputs': inputs[:10],
                    'type': form_type,
                    'priority': 'High' if form_type in ('Login', 'Upload') else 'Medium',
                })
    except Exception:
        pass
    return forms


async def _map_api(session, url):
    """Discover API endpoints from JavaScript."""
    endpoints = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()

            js_files = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body)

            for js_file in js_files[:8]:
                js_url = urljoin(url, js_file)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=8),
                                           ssl=False) as js_resp:
                        js_body = await js_resp.text()

                        api_patterns = [
                            r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']',
                            r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-]+)["\']',
                            r'fetch\s*\(["\']([^"\']+)["\']',
                            r'\.(?:get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']',
                        ]
                        for pattern in api_patterns:
                            matches = re.findall(pattern, js_body)
                            endpoints.update(matches)
                except Exception:
                    pass
    except Exception:
        pass
    return list(endpoints)[:30]


async def _map_technologies(session, url):
    """Detect technologies in use."""
    techs = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()
            headers = {k.lower(): v for k, v in resp.headers.items()}

            tech_signatures = {
                'React': [r'__NEXT_DATA__', r'react', r'_reactRootContainer'],
                'Vue.js': [r'__vue__', r'Vue\.', r'v-bind', r'v-if'],
                'Angular': [r'ng-app', r'ng-controller', r'angular'],
                'jQuery': [r'jquery', r'jQuery'],
                'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
                'Laravel': [r'laravel', r'XSRF-TOKEN'],
                'Django': [r'csrfmiddlewaretoken', r'django'],
                'Express': [r'X-Powered-By.*Express'],
                'Rails': [r'X-Runtime', r'rails'],
                'Spring': [r'actuator', r'spring'],
                'ASP.NET': [r'__VIEWSTATE', r'ASP.NET', r'aspnet'],
                'PHP': [r'PHPSESSID', r'X-Powered-By.*PHP'],
                'Nginx': [r'nginx'],
                'Apache': [r'Apache'],
                'Cloudflare': [r'cf-ray', r'cloudflare'],
            }

            all_text = body + str(headers)
            for tech, patterns in tech_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, all_text, re.I):
                        techs.append(tech)
                        break
    except Exception:
        pass
    return list(set(techs))


async def _calculate_risk_map(forms, apis, techs, url):
    """Calculate attack surface risk scores."""
    risk_areas = []

    for form in forms:
        risk_score = 90 if form['type'] == 'Upload' else 80 if form['type'] == 'Login' else 40
        risk_areas.append({
            'area': f"Form: {form['type']} ({form['method']} {form['action'][:30]})",
            'risk_score': risk_score,
            'priority': 'Critical' if risk_score > 70 else 'High' if risk_score > 50 else 'Medium',
            'inputs': form['inputs'],
        })

    for api in apis:
        is_sensitive = any(kw in api.lower() for kw in ['admin', 'user', 'auth', 'token', 'password', 'payment'])
        risk_score = 85 if is_sensitive else 50
        risk_areas.append({
            'area': f"API: {api[:40]}",
            'risk_score': risk_score,
            'priority': 'Critical' if is_sensitive else 'Medium',
        })

    risk_areas.sort(key=lambda x: x['risk_score'], reverse=True)
    return risk_areas


async def scan_attack_surface(session, url):
    """Full automatic attack surface mapping."""
    console.print(f"\n[bold cyan]--- Attack Surface Mapper ---[/bold cyan]")

    console.print(f"  [cyan]Mapping HTML forms...[/cyan]")
    forms = await _map_forms(session, url)
    if forms:
        console.print(f"  [green]{len(forms)} forms found[/green]")
        for f in forms:
            console.print(f"    [dim]{f['type']}: {f['method']} {f['action'][:40]} ({len(f['inputs'])} inputs)[/dim]")

    console.print(f"  [cyan]Discovering API endpoints...[/cyan]")
    apis = await _map_api(session, url)
    if apis:
        console.print(f"  [green]{len(apis)} API endpoints discovered[/green]")

    console.print(f"  [cyan]Fingerprinting technologies...[/cyan]")
    techs = await _map_technologies(session, url)
    if techs:
        console.print(f"  [green]Technologies: {', '.join(techs)}[/green]")

    console.print(f"  [cyan]Calculating risk map...[/cyan]")
    risk_map = await _calculate_risk_map(forms, apis, techs, url)

    console.print(f"\n  [bold]Attack Surface Summary:[/bold]")
    console.print(f"  Forms: {len(forms)} | APIs: {len(apis)} | Technologies: {len(techs)}")

    if risk_map:
        console.print(f"\n  [bold]Top Priority Targets:[/bold]")
        for area in risk_map[:10]:
            color = 'red' if area['priority'] == 'Critical' else 'yellow' if area['priority'] == 'High' else 'dim'
            console.print(f"  [{color}][{area['risk_score']}] {area['area']}[/{color}]")

    return {
        'forms': forms,
        'api_endpoints': apis,
        'technologies': techs,
        'risk_map': risk_map[:20],
        'total_surface': len(forms) + len(apis),
    }
