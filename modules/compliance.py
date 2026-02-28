"""Compliance Scanner — PCI DSS, HIPAA, SOC2, GDPR security compliance checks."""

import aiohttp
import asyncio
from modules.core import console

PCI_DSS_CHECKS = {
    'Requirement 2: No defaults': {
        'checks': ['default_passwords', 'default_pages'],
        'severity': 'Critical',
    },
    'Requirement 4: Encrypt transmission': {
        'checks': ['tls_version', 'hsts_enabled'],
        'severity': 'High',
    },
    'Requirement 6: Secure systems': {
        'checks': ['security_headers', 'xss_protection', 'csp_policy'],
        'severity': 'High',
    },
    'Requirement 8: Identify users': {
        'checks': ['authentication', 'session_management'],
        'severity': 'High',
    },
    'Requirement 10: Track access': {
        'checks': ['logging', 'audit_trail'],
        'severity': 'Medium',
    },
}

GDPR_CHECKS = {
    'Privacy Policy': {
        'paths': ['/privacy', '/privacy-policy', '/privacy.html', '/gdpr'],
        'required': True,
    },
    'Cookie Consent': {
        'indicators': ['cookie-consent', 'cookie-notice', 'cookieconsent',
                        'gdpr-cookie', 'cookie-law', 'cookie-banner'],
    },
    'Data Processing': {
        'indicators': ['data-protection', 'data-processing', 'dpo', 'dpa'],
    },
}


async def _check_tls(session, url):
    """Check TLS/SSL compliance."""
    findings = []
    if url.startswith('http://'):
        findings.append({
            'check': 'HTTPS Not Enforced',
            'standard': 'PCI DSS Req 4',
            'status': 'FAIL',
            'severity': 'Critical',
        })

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            if 'strict-transport-security' not in headers:
                findings.append({
                    'check': 'HSTS Missing',
                    'standard': 'PCI DSS Req 4',
                    'status': 'FAIL',
                    'severity': 'High',
                })
            else:
                hsts = headers['strict-transport-security']
                if 'max-age' in hsts:
                    import re
                    age = re.search(r'max-age=(\d+)', hsts)
                    if age and int(age.group(1)) < 31536000:
                        findings.append({
                            'check': 'HSTS Max-Age Too Short',
                            'standard': 'PCI DSS Req 4',
                            'status': 'WARN',
                            'severity': 'Medium',
                        })
    except Exception:
        pass

    return findings


async def _check_security_headers(session, url):
    """Check required security headers for compliance."""
    required_headers = {
        'Content-Security-Policy': {'standard': 'PCI DSS Req 6, SOC2', 'severity': 'High'},
        'X-Content-Type-Options': {'standard': 'PCI DSS Req 6', 'severity': 'Medium'},
        'X-Frame-Options': {'standard': 'PCI DSS Req 6, SOC2', 'severity': 'Medium'},
        'Referrer-Policy': {'standard': 'GDPR, SOC2', 'severity': 'Medium'},
        'Permissions-Policy': {'standard': 'SOC2', 'severity': 'Low'},
    }

    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, info in required_headers.items():
                if header.lower() not in headers:
                    findings.append({
                        'check': f'Missing: {header}',
                        'standard': info['standard'],
                        'status': 'FAIL',
                        'severity': info['severity'],
                    })
                else:
                    findings.append({
                        'check': f'Present: {header}',
                        'standard': info['standard'],
                        'status': 'PASS',
                        'severity': 'Info',
                    })
    except Exception:
        pass
    return findings


async def _check_gdpr(session, url):
    """Check GDPR compliance indicators."""
    findings = []

    for check_name, config in GDPR_CHECKS.items():
        found = False

        if 'paths' in config:
            from urllib.parse import urljoin
            for path in config['paths']:
                try:
                    test_url = urljoin(url, path)
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                           ssl=False, allow_redirects=True) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if len(body) > 200:
                                found = True
                                break
                except Exception:
                    pass

        if 'indicators' in config and not found:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                       ssl=False) as resp:
                    body = await resp.text()
                    for indicator in config['indicators']:
                        if indicator.lower() in body.lower():
                            found = True
                            break
            except Exception:
                pass

        findings.append({
            'check': check_name,
            'standard': 'GDPR',
            'status': 'PASS' if found else 'FAIL',
            'severity': 'High' if config.get('required') and not found else 'Medium',
        })

    return findings


async def _check_cookie_security(session, url):
    """Check cookie security flags."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            cookies = resp.headers.getall('Set-Cookie', [])
            for cookie in cookies:
                cookie_lower = cookie.lower()
                name = cookie.split('=')[0].strip()

                if 'secure' not in cookie_lower:
                    findings.append({
                        'check': f'Cookie "{name}" Missing Secure Flag',
                        'standard': 'PCI DSS Req 6, SOC2',
                        'status': 'FAIL',
                        'severity': 'Medium',
                    })
                if 'httponly' not in cookie_lower:
                    findings.append({
                        'check': f'Cookie "{name}" Missing HttpOnly',
                        'standard': 'PCI DSS Req 6',
                        'status': 'FAIL',
                        'severity': 'Medium',
                    })
                if 'samesite' not in cookie_lower:
                    findings.append({
                        'check': f'Cookie "{name}" Missing SameSite',
                        'standard': 'SOC2',
                        'status': 'FAIL',
                        'severity': 'Low',
                    })
    except Exception:
        pass
    return findings


async def scan_compliance(session, url):
    """Run comprehensive compliance scan."""
    console.print(f"\n[bold cyan]--- Compliance Scanner (PCI DSS / GDPR / SOC2 / HIPAA) ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Checking TLS/HTTPS compliance...[/cyan]")
    tls_findings = await _check_tls(session, url)
    all_findings.extend(tls_findings)

    console.print(f"  [cyan]Checking security headers...[/cyan]")
    header_findings = await _check_security_headers(session, url)
    all_findings.extend(header_findings)

    console.print(f"  [cyan]Checking GDPR compliance...[/cyan]")
    gdpr_findings = await _check_gdpr(session, url)
    all_findings.extend(gdpr_findings)

    console.print(f"  [cyan]Checking cookie security...[/cyan]")
    cookie_findings = await _check_cookie_security(session, url)
    all_findings.extend(cookie_findings)

    passed = sum(1 for f in all_findings if f['status'] == 'PASS')
    failed = sum(1 for f in all_findings if f['status'] == 'FAIL')
    warnings = sum(1 for f in all_findings if f['status'] == 'WARN')
    total = len(all_findings)

    score = int((passed / max(total, 1)) * 100)
    grade = 'A' if score >= 90 else 'B' if score >= 75 else 'C' if score >= 60 else 'D' if score >= 40 else 'F'

    console.print(f"\n  [bold]Compliance Results:[/bold]")
    for f in all_findings:
        if f['status'] == 'FAIL':
            console.print(f"  [red]✗ {f['check']} [{f['standard']}][/red]")
        elif f['status'] == 'WARN':
            console.print(f"  [yellow]⚠ {f['check']} [{f['standard']}][/yellow]")

    grade_color = 'green' if score >= 75 else 'yellow' if score >= 50 else 'red'
    console.print(f"\n  [bold {grade_color}]Compliance Grade: {grade} ({score}%)[/bold {grade_color}]")
    console.print(f"  [green]Passed: {passed}[/green] | [red]Failed: {failed}[/red] | [yellow]Warnings: {warnings}[/yellow]")

    return {
        'score': score,
        'grade': grade,
        'passed': passed,
        'failed': failed,
        'findings': all_findings,
    }
