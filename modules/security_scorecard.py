"""Security Scorecard — comprehensive security grade with detailed breakdown."""

from collections import Counter
from modules.core import console

CATEGORY_WEIGHTS = {
    'Critical Vulnerabilities': {'weight': 25, 'penalty_per': 10},
    'High Vulnerabilities': {'weight': 20, 'penalty_per': 5},
    'Medium Vulnerabilities': {'weight': 15, 'penalty_per': 2},
    'HTTPS/TLS': {'weight': 10, 'base': 10},
    'Security Headers': {'weight': 10, 'base': 10},
    'Authentication': {'weight': 10, 'base': 10},
    'Information Disclosure': {'weight': 5, 'penalty_per': 3},
    'OWASP Compliance': {'weight': 5, 'base': 5},
}

SECURITY_HEADERS_LIST = [
    'Strict-Transport-Security', 'Content-Security-Policy',
    'X-Content-Type-Options', 'X-Frame-Options',
    'X-XSS-Protection', 'Referrer-Policy',
    'Permissions-Policy', 'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
]


def _calculate_vuln_score(findings):
    """Calculate vulnerability deduction score."""
    sev_counts = Counter()
    for f in findings:
        sev = f.get('severity', f.get('risk', 'Info'))
        sev_counts[sev] += 1

    deductions = {
        'Critical': min(sev_counts.get('Critical', 0) * 10, 25),
        'High': min(sev_counts.get('High', 0) * 5, 20),
        'Medium': min(sev_counts.get('Medium', 0) * 2, 15),
        'Low': min(sev_counts.get('Low', 0) * 1, 5),
    }
    return deductions, sev_counts


def _calculate_header_score(recon_data):
    """Calculate security header score."""
    headers = recon_data.get('headers', {})
    if not headers:
        return 0, []

    present = []
    missing = []
    for h in SECURITY_HEADERS_LIST:
        if any(h.lower() == k.lower() for k in headers.keys()):
            present.append(h)
        else:
            missing.append(h)

    score = int((len(present) / len(SECURITY_HEADERS_LIST)) * 10)
    return score, missing


def _calculate_ssl_score(ssl_data):
    """Calculate SSL/TLS score."""
    if not ssl_data:
        return 0

    score = 5
    if ssl_data.get('valid'):
        score += 2
    if ssl_data.get('days_remaining', 0) > 30:
        score += 1
    if 'TLSv1.3' in str(ssl_data.get('protocol', '')):
        score += 2
    elif 'TLSv1.2' in str(ssl_data.get('protocol', '')):
        score += 1

    return min(score, 10)


def _get_grade(score):
    """Convert numeric score to letter grade."""
    if score >= 95: return 'A+'
    if score >= 90: return 'A'
    if score >= 85: return 'A-'
    if score >= 80: return 'B+'
    if score >= 75: return 'B'
    if score >= 70: return 'B-'
    if score >= 65: return 'C+'
    if score >= 60: return 'C'
    if score >= 55: return 'C-'
    if score >= 50: return 'D'
    if score >= 40: return 'D-'
    return 'F'


def generate_scorecard(full_report):
    """Generate comprehensive security scorecard."""
    console.print(f"\n[bold cyan]--- Security Scorecard ---[/bold cyan]")

    total_score = 100
    breakdown = {}

    findings = full_report.get('findings', [])
    deductions, sev_counts = _calculate_vuln_score(findings)

    for sev, deduction in deductions.items():
        total_score -= deduction
        if deduction > 0:
            breakdown[f'{sev} Vulns (-{deduction})'] = sev_counts.get(sev, 0)

    recon = full_report.get('recon', {})
    header_score, missing_headers = _calculate_header_score(recon)
    header_deduction = 10 - header_score
    total_score -= header_deduction
    breakdown['Security Headers'] = f'{header_score}/10'

    ssl_data = full_report.get('ssl', {})
    ssl_score = _calculate_ssl_score(ssl_data)
    ssl_deduction = 10 - ssl_score
    total_score -= ssl_deduction
    breakdown['SSL/TLS'] = f'{ssl_score}/10'

    owasp = full_report.get('owasp', {})
    owasp_grade = owasp.get('grade', 'F')
    owasp_score = {'A+': 5, 'A': 5, 'B': 4, 'C': 3, 'D': 2, 'F': 0}.get(owasp_grade, 0)
    total_score -= (5 - owasp_score)
    breakdown['OWASP'] = owasp_grade

    total_score = max(0, min(100, total_score))
    grade = _get_grade(total_score)

    grade_color = 'green' if total_score >= 80 else 'yellow' if total_score >= 60 else 'red'

    console.print(f"\n  [bold {grade_color}]╔══════════════════════════╗[/bold {grade_color}]")
    console.print(f"  [bold {grade_color}]║  SECURITY GRADE: {grade:>4}    ║[/bold {grade_color}]")
    console.print(f"  [bold {grade_color}]║  SCORE: {total_score:>3}/100           ║[/bold {grade_color}]")
    console.print(f"  [bold {grade_color}]╚══════════════════════════╝[/bold {grade_color}]")

    console.print(f"\n  [bold]Breakdown:[/bold]")
    for category, value in breakdown.items():
        console.print(f"    [dim]{category}: {value}[/dim]")

    if missing_headers:
        console.print(f"\n  [yellow]Missing Headers ({len(missing_headers)}):[/yellow]")
        for h in missing_headers[:5]:
            console.print(f"    [dim]• {h}[/dim]")

    sev_total = sum(sev_counts.values())
    console.print(f"\n  [bold]Vulnerabilities: {sev_total}[/bold]")
    console.print(f"    [red]Critical: {sev_counts.get('Critical', 0)}[/red]")
    console.print(f"    [red]High: {sev_counts.get('High', 0)}[/red]")
    console.print(f"    [yellow]Medium: {sev_counts.get('Medium', 0)}[/yellow]")
    console.print(f"    [dim]Low: {sev_counts.get('Low', 0)}[/dim]")

    return {
        'score': total_score,
        'grade': grade,
        'breakdown': breakdown,
        'sev_counts': dict(sev_counts),
        'missing_headers': missing_headers,
    }
