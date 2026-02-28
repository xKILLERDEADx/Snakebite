"""Client-Side Attack Engine — DOM clobbering, postMessage, service worker hijack."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin
from modules.core import console

async def _analyze_dom_clobbering(session, url):
    """Check for DOM clobbering attack vectors."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()

            clobber_patterns = [
                (r'document\.getElementById\(["\'](\w+)["\']\)\.(?:href|src|action|innerHTML)',
                 'DOM element used in sensitive context'),
                (r'(?:window|document)\[(["\'][^"\']+["\'])\]',
                 'Dynamic property access from DOM'),
                (r'(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?:document|window)',
                 'Code execution from DOM element'),
                (r'\.innerHTML\s*=\s*(?:document|window|location)',
                 'innerHTML from DOM input'),
                (r'document\.forms\[\d+\]\.action',
                 'Form action from DOM'),
            ]

            for pattern, desc in clobber_patterns:
                matches = re.findall(pattern, body)
                if matches:
                    findings.append({
                        'type': 'DOM Clobbering Vector',
                        'detail': desc,
                        'matches': len(matches),
                        'severity': 'High',
                    })

            id_elements = re.findall(r'id=["\']([^"\']+)["\']', body)
            name_elements = re.findall(r'name=["\']([^"\']+)["\']', body)
            dangerous_names = ['config', 'settings', 'options', 'data', 'user',
                             'auth', 'token', 'admin', 'form', 'submit']
            for name in dangerous_names:
                if name not in id_elements and name not in name_elements:
                    if f'document.getElementById("{name}")' in body or f"document.getElementById('{name}')" in body:
                        findings.append({
                            'type': f'Clobberable ID: {name}',
                            'severity': 'Medium',
                            'detail': 'Script uses element ID not defined in DOM',
                        })

    except Exception:
        pass

    return findings


async def _analyze_postmessage(session, url):
    """Check for insecure postMessage handling."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()

            pm_patterns = [
                (r'addEventListener\s*\(\s*["\']message["\']', 'postMessage listener found'),
                (r'window\.onmessage\s*=', 'window.onmessage handler'),
            ]

            has_listener = False
            for pattern, desc in pm_patterns:
                if re.search(pattern, body):
                    has_listener = True

            if has_listener:
                if not re.search(r'event\.origin\s*[!=]==?\s*["\']', body) and \
                   not re.search(r'\.origin\s*[!=]==?\s*["\']', body):
                    findings.append({
                        'type': 'postMessage No Origin Check',
                        'severity': 'Critical',
                        'detail': 'Message listener without origin validation',
                    })

                if re.search(r'\.data.*(?:eval|innerHTML|document\.write|\.src\s*=)', body):
                    findings.append({
                        'type': 'postMessage Data Used Unsafely',
                        'severity': 'Critical',
                        'detail': 'Message data flows to dangerous sink',
                    })

                if not re.search(r'event\.origin|e\.origin|msg\.origin', body):
                    findings.append({
                        'type': 'postMessage Origin Not Checked',
                        'severity': 'High',
                        'detail': 'No origin variable found near message handler',
                    })

    except Exception:
        pass

    return findings


async def _check_service_worker(session, url):
    """Check for service worker security issues."""
    findings = []

    sw_paths = ['/sw.js', '/service-worker.js', '/serviceworker.js',
                '/worker.js', '/sw-main.js', '/firebase-messaging-sw.js',
                '/ngsw-worker.js', '/precache-manifest.js']

    for path in sw_paths:
        test_url = urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if 'addEventListener' in body or 'self.' in body or 'caches' in body:
                        findings.append({
                            'type': f'Service Worker Found: {path}',
                            'severity': 'Medium',
                        })

                        if re.search(r'importScripts\s*\(', body):
                            scripts = re.findall(r'importScripts\s*\(["\']([^"\']+)', body)
                            for script in scripts:
                                if 'http' in script and not script.startswith(url):
                                    findings.append({
                                        'type': 'SW Imports External Script',
                                        'detail': script[:60],
                                        'severity': 'Critical',
                                    })

                        if 'cache' in body.lower() and 'token' in body.lower():
                            findings.append({
                                'type': 'SW Caches Tokens',
                                'severity': 'High',
                            })
        except Exception:
            pass

    return findings


async def _check_csp_bypass(session, url):
    """Analyze CSP header for bypass opportunities."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            csp = resp.headers.get('Content-Security-Policy', '')

            if not csp:
                findings.append({
                    'type': 'No CSP Header',
                    'severity': 'High',
                    'detail': 'Content-Security-Policy completely missing',
                })
                return findings

            bypass_checks = {
                "'unsafe-inline'": ('CSP unsafe-inline', 'Allows inline script execution', 'High'),
                "'unsafe-eval'": ('CSP unsafe-eval', 'Allows eval() execution', 'High'),
                "data:": ('CSP data: URI', 'Allows data: URI attacks', 'Medium'),
                "blob:": ('CSP blob: URI', 'Allows blob: URI attacks', 'Medium'),
                "*.googleapis.com": ('CSP Wildcard googleapis', 'JSONP callback bypass possible', 'High'),
                "*.cloudflare.com": ('CSP Wildcard Cloudflare', 'CDN bypass possible', 'Medium'),
                "*.google.com": ('CSP Wildcard Google', 'Multiple bypass vectors', 'Medium'),
                "*": ('CSP Wildcard *', 'Allows any source', 'Critical'),
            }

            for pattern, (name, detail, severity) in bypass_checks.items():
                if pattern in csp:
                    findings.append({
                        'type': name,
                        'detail': detail,
                        'severity': severity,
                    })

            if 'script-src' not in csp and 'default-src' not in csp:
                findings.append({
                    'type': 'CSP No script-src',
                    'severity': 'High',
                    'detail': 'No script source restriction',
                })

    except Exception:
        pass

    return findings


async def _check_js_prototype(session, url):
    """Check for client-side prototype pollution indicators."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()

            risky_patterns = [
                (r'Object\.assign\s*\(\s*\{\}', 'Object.assign merge (pollution risk)'),
                (r'_\.merge\s*\(', 'lodash merge (CVE possible)'),
                (r'jQuery\.extend\s*\(', 'jQuery.extend (deep merge risk)'),
                (r'\$\.extend\s*\(\s*true', 'jQuery deep extend (pollution)'),
                (r'JSON\.parse\s*\(.*location\.|query|param', 'JSON.parse from user input'),
                (r'(?:config|options|settings)\s*=\s*\{[^}]*\.\.\.\s*(?:req|params|query)', 'Spread from user input'),
            ]

            for pattern, desc in risky_patterns:
                if re.search(pattern, body):
                    findings.append({
                        'type': f'Client Prototype Pollution: {desc}',
                        'severity': 'Medium',
                    })

    except Exception:
        pass

    return findings


async def scan_client_attack(session, url):
    """Client-side attack surface scanner."""
    console.print(f"\n[bold cyan]--- Client-Side Attack Engine ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Analyzing DOM clobbering vectors...[/cyan]")
    dom = await _analyze_dom_clobbering(session, url)
    all_findings.extend(dom)

    console.print(f"  [cyan]Checking postMessage security...[/cyan]")
    pm = await _analyze_postmessage(session, url)
    all_findings.extend(pm)
    for f in pm:
        console.print(f"  [red]⚠ {f['type']}[/red]")

    console.print(f"  [cyan]Scanning service workers (8 paths)...[/cyan]")
    sw = await _check_service_worker(session, url)
    all_findings.extend(sw)

    console.print(f"  [cyan]Analyzing CSP bypass vectors...[/cyan]")
    csp = await _check_csp_bypass(session, url)
    all_findings.extend(csp)

    console.print(f"  [cyan]Checking client prototype pollution...[/cyan]")
    proto = await _check_js_prototype(session, url)
    all_findings.extend(proto)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} client-side attack vectors![/bold red]")
    else:
        console.print(f"\n  [green]✓ Client-side looks secure[/green]")

    return {'findings': all_findings}
