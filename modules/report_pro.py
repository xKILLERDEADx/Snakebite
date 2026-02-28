"""Full Report Generator Pro — executive summary, risk matrix, OWASP/PCI-DSS mapping."""

import json
import os
from datetime import datetime
from modules.core import console

OWASP_MAP = {
    'sql': 'A03:2021 Injection', 'xss': 'A03:2021 Injection', 'ssti': 'A03:2021 Injection',
    'ssrf': 'A10:2021 SSRF', 'auth': 'A07:2021 Auth Failures', 'session': 'A07:2021 Auth Failures',
    'header': 'A05:2021 Security Misconfiguration', 'cors': 'A05:2021 Security Misconfiguration',
    'csp': 'A05:2021 Security Misconfiguration', 'crypto': 'A02:2021 Crypto Failures',
    'ssl': 'A02:2021 Crypto Failures', 'access': 'A01:2021 Broken Access Control',
    'idor': 'A01:2021 Broken Access Control', 'deserialization': 'A08:2021 Integrity Failures',
    'log': 'A09:2021 Logging Failures', 'component': 'A06:2021 Vulnerable Components',
    'supply': 'A06:2021 Vulnerable Components', 'default': 'A05:2021 Security Misconfiguration',
}

PCI_MAP = {
    'sql': 'Req 6.5.1 - Injection Flaws', 'xss': 'Req 6.5.7 - XSS',
    'auth': 'Req 8 - Identify and Authenticate', 'crypto': 'Req 4 - Encrypt Transmission',
    'access': 'Req 7 - Restrict Access', 'log': 'Req 10 - Track and Monitor',
    'header': 'Req 6.5.10 - Broken Auth', 'default': 'Req 6.5 - Secure Coding',
}


def _classify(finding_type):
    ft = finding_type.lower()
    for key in OWASP_MAP:
        if key in ft:
            return key
    return 'default'


def _generate_executive_summary(stats, target):
    risk = 'CRITICAL' if stats['critical'] > 0 else 'HIGH' if stats['high'] > 0 else 'MEDIUM' if stats['medium'] > 0 else 'LOW'
    return {
        'target': target,
        'overall_risk': risk,
        'total_findings': stats['total'],
        'critical': stats['critical'],
        'high': stats['high'],
        'medium': stats['medium'],
        'low': stats['low'],
        'recommendation': 'Immediate remediation required' if risk == 'CRITICAL' else
                          'Address high-priority findings within 30 days' if risk == 'HIGH' else
                          'Schedule remediation in next sprint' if risk == 'MEDIUM' else
                          'Monitor and maintain security posture',
    }


def _build_risk_matrix(findings):
    matrix = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
    for f in findings:
        sev = f.get('severity', 'Medium')
        if sev in matrix:
            matrix[sev].append(f.get('type', 'Unknown'))
    return matrix


async def scan_report_pro(session, url, full_report=None):
    console.print(f"\n[bold cyan]--- Full Report Generator Pro ---[/bold cyan]")
    if not full_report:
        console.print(f"  [dim]No data for report[/dim]")
        return {}

    all_findings = []
    for key, value in full_report.items():
        if isinstance(value, dict):
            findings = value.get('findings', [])
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict):
                        all_findings.append(f)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and 'type' in item:
                    all_findings.append(item)

    stats = {
        'total': len(all_findings),
        'critical': len([f for f in all_findings if f.get('severity') == 'Critical']),
        'high': len([f for f in all_findings if f.get('severity') == 'High']),
        'medium': len([f for f in all_findings if f.get('severity') == 'Medium']),
        'low': len([f for f in all_findings if f.get('severity') == 'Low']),
    }

    executive = _generate_executive_summary(stats, url)
    risk_matrix = _build_risk_matrix(all_findings)

    compliance = {'owasp': {}, 'pci_dss': {}}
    for f in all_findings:
        cat = _classify(f.get('type', ''))
        owasp = OWASP_MAP.get(cat, OWASP_MAP['default'])
        pci = PCI_MAP.get(cat, PCI_MAP['default'])
        compliance['owasp'].setdefault(owasp, []).append(f.get('type', ''))
        compliance['pci_dss'].setdefault(pci, []).append(f.get('type', ''))

    console.print(f"\n  [bold]Executive Summary:[/bold]")
    console.print(f"  Overall Risk: [bold {'red' if executive['overall_risk'] == 'CRITICAL' else 'yellow'}]{executive['overall_risk']}[/bold {'red' if executive['overall_risk'] == 'CRITICAL' else 'yellow'}]")
    console.print(f"  Total: {stats['total']} | Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}")
    console.print(f"  [dim]{executive['recommendation']}[/dim]")

    console.print(f"\n  [bold]OWASP Top 10 Mapping:[/bold]")
    for owasp, items in compliance['owasp'].items():
        console.print(f"  [dim]{owasp}: {len(items)} finding(s)[/dim]")

    return {
        'executive_summary': executive,
        'stats': stats,
        'risk_matrix': risk_matrix,
        'compliance': compliance,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
