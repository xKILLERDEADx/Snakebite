"""OWASP Top 10 Compliance Checker — maps scan findings to OWASP categories + risk score."""

from modules.core import console


OWASP_TOP_10 = {
    'A01': {
        'name': 'Broken Access Control',
        'keywords': ['idor', 'bypass_403', 'admin', 'privilege', 'authorization',
                     'access control', 'forced browsing', 'directory traversal', 'lfi'],
        'description': 'Restrictions on authenticated users are not properly enforced',
    },
    'A02': {
        'name': 'Cryptographic Failures',
        'keywords': ['ssl', 'tls', 'certificate', 'encryption', 'crypto', 'cleartext',
                     'http', 'weak cipher', 'expired cert', 'self-signed'],
        'description': 'Failures related to cryptography leading to exposure of sensitive data',
    },
    'A03': {
        'name': 'Injection',
        'keywords': ['sqli', 'xss', 'ssti', 'nosql', 'ldap', 'xpath', 'xxe', 'command',
                     'rce', 'code injection', 'template injection', 'sql injection',
                     'blind_sqli', 'blind_rce', 'log4shell', 'ognl'],
        'description': 'Untrusted data sent to an interpreter as part of a command or query',
    },
    'A04': {
        'name': 'Insecure Design',
        'keywords': ['race', 'logic flaw', 'design', 'business logic', 'workflow',
                     'rate limit', 'brute force'],
        'description': 'Missing or ineffective control design, different from implementation bugs',
    },
    'A05': {
        'name': 'Security Misconfiguration',
        'keywords': ['cors', 'clickjacking', 'header', 'csp', 'hsts', 'x-frame',
                     'debug', 'default', 'unnecessary', 'directory listing', 'error',
                     'stack trace', 'misconfiguration', 'exposed', 'open redirect',
                     'redirect', 'crlf', 'host header', 'swagger', 'phpinfo'],
        'description': 'Missing appropriate security hardening across any part of the stack',
    },
    'A06': {
        'name': 'Vulnerable & Outdated Components',
        'keywords': ['cve', 'outdated', 'version', 'component', 'library', 'framework',
                     'dependency', 'spring4shell', 'struts', 'drupalgeddon', 'wp plugin',
                     'wordpress', 'jquery', 'angular', 'bootstrap'],
        'description': 'Using components with known vulnerabilities',
    },
    'A07': {
        'name': 'Identification & Authentication Failures',
        'keywords': ['session', 'token', 'jwt', 'auth', 'login', 'password', 'credential',
                     'brute', 'weak password', 'session fixation', 'cookie'],
        'description': 'Authentication and session management weaknesses',
    },
    'A08': {
        'name': 'Software & Data Integrity Failures',
        'keywords': ['deserialization', 'pickle', 'php_obj', 'prototype', 'supply chain',
                     'ci/cd', 'integrity', 'unsigned', 'unverified'],
        'description': 'Code and infrastructure without integrity verification',
    },
    'A09': {
        'name': 'Security Logging & Monitoring Failures',
        'keywords': ['logging', 'monitoring', 'audit', 'detection', 'alerting',
                     'incident response'],
        'description': 'Insufficient logging, detection, monitoring, and active response',
    },
    'A10': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'keywords': ['ssrf', 'server-side request', 'internal', 'metadata',
                     'cloud metadata', 'ssrf_port', 'url fetch'],
        'description': 'Web application fetching a remote resource without validating user-supplied URL',
    },
}

RISK_LEVELS = {
    'A+': (0, 'Excellent — No significant vulnerabilities detected'),
    'A': (1, 'Very Good — Minor informational findings only'),
    'B': (2, 'Good — Low-risk issues found, mostly secure'),
    'C': (3, 'Fair — Some medium-risk findings need attention'),
    'D': (4, 'Poor — Multiple high-risk vulnerabilities found'),
    'F': (5, 'Critical — Critical vulnerabilities require immediate action'),
}


def _classify_finding(finding):
    """Map a finding to OWASP categories."""
    categories = []
    finding_type = str(finding.get('type', finding.get('vulnerability', finding.get('module', '')))).lower()
    finding_module = str(finding.get('module', '')).lower()
    finding_url = str(finding.get('url', '')).lower()
    combined = f"{finding_type} {finding_module} {finding_url}"

    for owasp_id, owasp_data in OWASP_TOP_10.items():
        for keyword in owasp_data['keywords']:
            if keyword in combined:
                categories.append(owasp_id)
                break

    return categories if categories else ['A05']

def assess_owasp_compliance(all_findings, recon_data=None, ssl_data=None, session_data=None):
    """Run OWASP Top 10 compliance assessment on scan findings."""
    console.print(f"\n[bold cyan]--- OWASP Top 10 Compliance Assessment ---[/bold cyan]")

    category_findings = {cat: [] for cat in OWASP_TOP_10}
    severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1}

    for finding in all_findings:
        categories = _classify_finding(finding)
        for cat in categories:
            if cat in category_findings:
                category_findings[cat].append(finding)

    if ssl_data and isinstance(ssl_data, dict):
        if not ssl_data.get('valid', True):
            category_findings['A02'].append({
                'type': 'SSL/TLS Issue', 'severity': 'Medium',
                'url': ssl_data.get('url', ''),
            })

    if session_data and isinstance(session_data, dict):
        cookies = session_data.get('cookies', [])
        for cookie in cookies:
            if cookie.get('risk_score', 0) >= 8:
                category_findings['A07'].append({
                    'type': f"Weak Session: {cookie.get('name', 'unknown')}",
                    'severity': 'High',
                    'url': '',
                })

    total_score = 0
    max_severity_seen = 'Info'
    sev_order = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}

    console.print()
    for owasp_id in sorted(OWASP_TOP_10.keys()):
        owasp = OWASP_TOP_10[owasp_id]
        findings = category_findings[owasp_id]

        if findings:
            severities = [f.get('severity', 'Medium') for f in findings]
            max_sev = max(severities, key=lambda s: sev_order.get(s, 0))
            cat_score = sum(severity_weights.get(s, 0) for s in severities)
            total_score += cat_score

            if sev_order.get(max_sev, 0) > sev_order.get(max_severity_seen, 0):
                max_severity_seen = max_sev

            sev_color = {'Critical': 'red', 'High': 'red', 'Medium': 'yellow', 'Low': 'blue', 'Info': 'dim'}.get(max_sev, 'white')
            status = f"[{sev_color}]FAIL ({len(findings)} findings, max={max_sev})[/{sev_color}]"
        else:
            status = "[green]PASS ✓[/green]"

        console.print(f"  [{owasp_id}] {owasp['name']:45s} {status}")

    if total_score == 0:
        grade, grade_desc = 'A+', RISK_LEVELS['A+'][1]
    elif total_score <= 5:
        grade, grade_desc = 'A', RISK_LEVELS['A'][1]
    elif total_score <= 15:
        grade, grade_desc = 'B', RISK_LEVELS['B'][1]
    elif total_score <= 40:
        grade, grade_desc = 'C', RISK_LEVELS['C'][1]
    elif total_score <= 80:
        grade, grade_desc = 'D', RISK_LEVELS['D'][1]
    else:
        grade, grade_desc = 'F', RISK_LEVELS['F'][1]

    grade_color = {'A+': 'green', 'A': 'green', 'B': 'cyan', 'C': 'yellow', 'D': 'red', 'F': 'bold red'}.get(grade, 'white')

    console.print(f"\n  [bold]Overall Risk Score:[/bold] {total_score}")
    console.print(f"  [bold]Security Grade:[/bold] [{grade_color}]{grade}[/{grade_color}]")
    console.print(f"  [dim]{grade_desc}[/dim]")

    failed = sum(1 for cat in category_findings if category_findings[cat])
    passed = 10 - failed
    console.print(f"\n  [green]Passed: {passed}/10[/green] | [red]Failed: {failed}/10[/red]")

    return {
        'grade': grade,
        'score': total_score,
        'passed': passed,
        'failed': failed,
        'categories': {k: len(v) for k, v in category_findings.items()},
        'max_severity': max_severity_seen,
        'description': grade_desc,
    }
