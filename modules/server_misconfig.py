"""Server Misconfiguration Scanner — comprehensive server security checks."""

import aiohttp
import asyncio
from urllib.parse import urljoin
from modules.core import console

DANGEROUS_METHODS = ['TRACE', 'TRACK', 'DEBUG', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']

MISCONFIG_CHECKS = {
    'Directory Listing': {
        'paths': ['/images/', '/uploads/', '/static/', '/assets/', '/files/', '/media/',
                  '/css/', '/js/', '/backup/', '/logs/', '/tmp/', '/data/'],
        'indicators': ['Index of', 'Directory listing', 'Parent Directory', '[To Parent Directory]'],
    },
    'Debug Mode': {
        'paths': ['/debug/', '/_debug/', '/debug/default/view', '/elmah.axd',
                  '/__debug__/', '/trace.axd', '/actuator/env',
                  '/api/debug', '/_profiler/', '/silk/'],
        'indicators': ['debug', 'stack trace', 'traceback', 'exception'],
    },
    'Default Pages': {
        'paths': ['/readme.html', '/readme.txt', '/README.md',
                  '/INSTALL.txt', '/CHANGELOG.txt', '/LICENSE.txt',
                  '/web.config.bak', '/wp-config.php.bak',
                  '/info.php', '/phpinfo.php', '/test.php',
                  '/i.php', '/pi.php'],
        'indicators': ['phpinfo', 'PHP Version', 'Apache', 'WordPress'],
    },
}


async def _check_methods(session, url):
    """Test for dangerous HTTP methods."""
    findings = []

    try:
        async with session.options(url, timeout=aiohttp.ClientTimeout(total=6),
                                   ssl=False) as resp:
            allow = resp.headers.get('Allow', '')
            if allow:
                for method in DANGEROUS_METHODS:
                    if method in allow.upper():
                        findings.append({
                            'type': f'Dangerous Method: {method}',
                            'severity': 'High' if method in ('TRACE', 'DEBUG') else 'Medium',
                            'detail': f'Allowed via OPTIONS: {allow}',
                        })
    except Exception:
        pass

    for method in ['TRACE', 'TRACK', 'DEBUG']:
        try:
            async with session.request(method, url,
                                       timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if method.upper() in body or 'TRACE' in body:
                        findings.append({
                            'type': f'{method} Method Enabled',
                            'severity': 'High',
                            'detail': 'Method reflects request — XST possible',
                        })
        except Exception:
            pass

    return findings


async def _check_misconfigs(session, url):
    """Check for common misconfigurations."""
    findings = []

    for check_name, config in MISCONFIG_CHECKS.items():
        for path in config['paths']:
            try:
                test_url = urljoin(url, path)
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        for indicator in config['indicators']:
                            if indicator.lower() in body.lower():
                                findings.append({
                                    'type': check_name,
                                    'path': path,
                                    'indicator': indicator,
                                    'severity': 'High' if check_name == 'Debug Mode' else 'Medium',
                                })
                                break
            except Exception:
                pass

    return findings


async def _check_version_disclosure(session, url):
    """Check for server version disclosure."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=6),
                               ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            version_headers = ['server', 'x-powered-by', 'x-aspnet-version',
                               'x-aspnetmvc-version', 'x-generator']
            for h in version_headers:
                val = headers.get(h, '')
                if val and any(c.isdigit() for c in val):
                    findings.append({
                        'type': f'Version Disclosure: {h}',
                        'value': val,
                        'severity': 'Low',
                    })
    except Exception:
        pass
    return findings


async def _check_cors_misconfig(session, url):
    """Check for CORS wildcard misconfiguration."""
    findings = []
    try:
        headers = {'Origin': 'https://evil.com'}
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=5),
                               ssl=False) as resp:
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                findings.append({
                    'type': 'CORS Wildcard',
                    'severity': 'Medium',
                })
            elif 'evil.com' in acao:
                sev = 'Critical' if acac.lower() == 'true' else 'High'
                findings.append({
                    'type': 'CORS Origin Reflection',
                    'severity': sev,
                    'detail': f'ACAO: {acao}, ACAC: {acac}',
                })
    except Exception:
        pass
    return findings


async def scan_server_misconfig(session, url):
    """Comprehensive server misconfiguration scan."""
    console.print(f"\n[bold cyan]--- Server Misconfiguration Scanner ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Testing dangerous HTTP methods...[/cyan]")
    method_findings = await _check_methods(session, url)
    all_findings.extend(method_findings)
    for f in method_findings:
        console.print(f"  [red]{f['type']}[/red]")

    console.print(f"  [cyan]Checking directory listing, debug, defaults...[/cyan]")
    misconfig_findings = await _check_misconfigs(session, url)
    all_findings.extend(misconfig_findings)
    for f in misconfig_findings:
        console.print(f"  [yellow]{f['type']}: {f['path']}[/yellow]")

    console.print(f"  [cyan]Checking version disclosure...[/cyan]")
    version_findings = await _check_version_disclosure(session, url)
    all_findings.extend(version_findings)
    for f in version_findings:
        console.print(f"  [dim]{f['type']}: {f['value']}[/dim]")

    console.print(f"  [cyan]Checking CORS configuration...[/cyan]")
    cors_findings = await _check_cors_misconfig(session, url)
    all_findings.extend(cors_findings)
    for f in cors_findings:
        console.print(f"  [{'red' if f['severity'] in ('Critical','High') else 'yellow'}]{f['type']}[/{'red' if f['severity'] in ('Critical','High') else 'yellow'}]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} misconfigurations found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No server misconfigurations detected[/green]")

    return {'findings': all_findings}
