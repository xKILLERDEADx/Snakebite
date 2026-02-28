"""Supply Chain Auditor — SRI integrity, CDN compromise, version vuln detection."""

import aiohttp
import asyncio
import re
import hashlib
import base64
from urllib.parse import urlparse
from modules.core import console

KNOWN_VULN_LIBS = {
    'jquery': {
        'vulnerable': ['1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '1.12',
                       '2.0', '2.1', '2.2', '3.0', '3.1', '3.2', '3.3', '3.4'],
        'cve': 'CVE-2020-11022/CVE-2020-11023 (XSS via HTML)',
        'safe': '3.5.0+',
    },
    'lodash': {
        'vulnerable': ['4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7',
                       '4.8', '4.9', '4.10', '4.11', '4.12', '4.13', '4.14',
                       '4.15', '4.16', '4.17.0', '4.17.1', '4.17.2', '4.17.3',
                       '4.17.4', '4.17.5', '4.17.6', '4.17.7', '4.17.8',
                       '4.17.9', '4.17.10', '4.17.11', '4.17.12', '4.17.13',
                       '4.17.14', '4.17.15', '4.17.16', '4.17.17', '4.17.18',
                       '4.17.19', '4.17.20'],
        'cve': 'CVE-2021-23337 (Command Injection)',
        'safe': '4.17.21+',
    },
    'angular': {
        'vulnerable': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8'],
        'cve': 'Multiple XSS (Sandbox escape)',
        'safe': '1.8.1+ or Angular 2+',
    },
    'moment': {
        'vulnerable': ['2.0', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7',
                       '2.8', '2.9', '2.10', '2.11', '2.12', '2.13', '2.14',
                       '2.15', '2.16', '2.17', '2.18', '2.19', '2.20',
                       '2.21', '2.22', '2.23', '2.24', '2.25', '2.26',
                       '2.27', '2.28', '2.29.0', '2.29.1', '2.29.2', '2.29.3'],
        'cve': 'CVE-2022-31129 (ReDoS)',
        'safe': '2.29.4+',
    },
    'bootstrap': {
        'vulnerable': ['3.0', '3.1', '3.2', '3.3', '3.4.0'],
        'cve': 'CVE-2019-8331 (XSS)',
        'safe': '3.4.1+ or 4.x+',
    },
}


async def _extract_resources(session, url):
    """Extract all JS/CSS resources from page."""
    resources = {'scripts': [], 'styles': [], 'integrity_stats': {'total': 0, 'with_sri': 0}}

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()

            script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*(?:integrity=["\']([^"\']*)["\'])?[^>]*>'
            for match in re.finditer(script_pattern, body, re.I):
                src = match.group(1)
                integrity = match.group(2) or None
                parsed = urlparse(src)
                is_external = bool(parsed.netloc) and parsed.netloc not in urlparse(url).netloc

                resources['scripts'].append({
                    'src': src,
                    'integrity': integrity,
                    'external': is_external,
                })
                resources['integrity_stats']['total'] += 1
                if integrity:
                    resources['integrity_stats']['with_sri'] += 1

            style_pattern = r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\'][^>]*(?:integrity=["\']([^"\']*)["\'])?[^>]*>'
            for match in re.finditer(style_pattern, body, re.I):
                href = match.group(1)
                integrity = match.group(2) or None
                parsed = urlparse(href)
                is_external = bool(parsed.netloc) and parsed.netloc not in urlparse(url).netloc

                resources['styles'].append({
                    'href': href,
                    'integrity': integrity,
                    'external': is_external,
                })
                resources['integrity_stats']['total'] += 1
                if integrity:
                    resources['integrity_stats']['with_sri'] += 1

    except Exception:
        pass

    return resources


async def _check_vulnerable_libs(session, url, resources):
    """Check loaded libraries against known vulnerabilities."""
    findings = []

    for script in resources['scripts']:
        src = script['src'].lower()
        for lib_name, info in KNOWN_VULN_LIBS.items():
            if lib_name in src:
                version_match = re.search(rf'{lib_name}[/._-]v?(\d+\.\d+(?:\.\d+)?)', src)
                if version_match:
                    version = version_match.group(1)
                    major_minor = '.'.join(version.split('.')[:2])
                    if major_minor in info['vulnerable'] or version in info['vulnerable']:
                        findings.append({
                            'type': f'Vulnerable Library: {lib_name} v{version}',
                            'cve': info['cve'],
                            'safe_version': info['safe'],
                            'src': script['src'][:80],
                            'severity': 'High',
                        })

    return findings


async def _verify_sri(session, resources):
    """Verify SRI integrity hashes for external resources."""
    findings = []

    external_no_sri = [s for s in resources['scripts'] if s['external'] and not s['integrity']]
    external_no_sri += [s for s in resources['styles'] if s['external'] and not s.get('integrity')]

    for resource in external_no_sri[:10]:
        src = resource.get('src') or resource.get('href', '')
        findings.append({
            'type': 'External Resource Without SRI',
            'src': src[:80],
            'severity': 'Medium',
            'detail': 'No integrity hash — CDN compromise would be undetected',
        })

    for script in resources['scripts']:
        if script['integrity'] and script['external']:
            try:
                async with session.get(script['src'],
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        algo = script['integrity'].split('-')[0]
                        if algo == 'sha256':
                            computed = 'sha256-' + base64.b64encode(hashlib.sha256(content).digest()).decode()
                        elif algo == 'sha384':
                            computed = 'sha384-' + base64.b64encode(hashlib.sha384(content).digest()).decode()
                        elif algo == 'sha512':
                            computed = 'sha512-' + base64.b64encode(hashlib.sha512(content).digest()).decode()
                        else:
                            continue

                        if computed != script['integrity']:
                            findings.append({
                                'type': 'SRI Hash Mismatch!',
                                'src': script['src'][:80],
                                'severity': 'Critical',
                                'detail': 'Content does not match integrity hash — possible tampering',
                            })
            except Exception:
                pass

    return findings


async def _check_cdn_security(resources):
    """Check CDN usage patterns for security."""
    findings = []
    cdn_domains = set()

    for s in resources['scripts'] + resources['styles']:
        src = s.get('src') or s.get('href', '')
        parsed = urlparse(src)
        if parsed.netloc and s.get('external'):
            cdn_domains.add(parsed.netloc)

    insecure = [s for s in resources['scripts'] if s['external'] and s['src'].startswith('http://')]
    if insecure:
        findings.append({
            'type': f'HTTP CDN Resources ({len(insecure)})',
            'severity': 'High',
            'detail': 'External scripts loaded over HTTP (MITM risk)',
            'urls': [s['src'][:60] for s in insecure[:3]],
        })

    if len(cdn_domains) > 5:
        findings.append({
            'type': f'Too Many CDN Domains ({len(cdn_domains)})',
            'severity': 'Low',
            'detail': 'Increases attack surface and supply chain risk',
        })

    return findings


async def scan_supply_chain(session, url):
    """Supply chain security auditor."""
    console.print(f"\n[bold cyan]--- Supply Chain Auditor ---[/bold cyan]")

    console.print(f"  [cyan]Extracting JS/CSS resources...[/cyan]")
    resources = await _extract_resources(session, url)

    total_scripts = len(resources['scripts'])
    total_styles = len(resources['styles'])
    external_scripts = len([s for s in resources['scripts'] if s['external']])
    external_styles = len([s for s in resources['styles'] if s['external']])

    console.print(f"  [dim]Scripts: {total_scripts} ({external_scripts} external) | Styles: {total_styles} ({external_styles} external)[/dim]")

    sri = resources['integrity_stats']
    if sri['total'] > 0:
        pct = round(sri['with_sri'] / sri['total'] * 100)
        console.print(f"  [dim]SRI Coverage: {sri['with_sri']}/{sri['total']} ({pct}%)[/dim]")

    all_findings = []

    console.print(f"  [cyan]Checking against known vulnerable libraries...[/cyan]")
    vuln_libs = await _check_vulnerable_libs(session, url, resources)
    all_findings.extend(vuln_libs)
    for f in vuln_libs:
        console.print(f"  [bold red]⚠ {f['type']} — {f['cve']}[/bold red]")

    console.print(f"  [cyan]Verifying SRI integrity hashes...[/cyan]")
    sri_issues = await _verify_sri(session, resources)
    all_findings.extend(sri_issues)

    console.print(f"  [cyan]Analyzing CDN security...[/cyan]")
    cdn = await _check_cdn_security(resources)
    all_findings.extend(cdn)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} supply chain issues![/bold red]")
    else:
        console.print(f"\n  [green]✓ Supply chain looks secure[/green]")

    return {
        'resources': {'scripts': total_scripts, 'styles': total_styles,
                      'external_scripts': external_scripts, 'external_styles': external_styles},
        'sri_coverage': sri,
        'findings': all_findings,
    }
