"""AI Vulnerability Classifier — pattern-based intelligent vulnerability prioritization."""

import re
from collections import Counter
from modules.core import console

VULN_PRIORITY_RULES = {
    'Critical': {
        'patterns': [
            r'(?i)remote.?code.?execution', r'(?i)rce', r'(?i)command.?injection',
            r'(?i)sql.?injection.*auth', r'(?i)deserialization',
            r'(?i)ssrf.*metadata', r'(?i)cloud.?metadata',
            r'(?i)credentials?.?exposed', r'(?i)admin.?bypass',
            r'(?i)authentication.?bypass', r'(?i)privilege.?escalation',
        ],
        'keywords': ['rce', 'remote code', 'command injection', 'deserializ',
                      'admin bypass', 'auth bypass', 'credential', 'private key'],
        'weight': 10,
    },
    'High': {
        'patterns': [
            r'(?i)sql.?injection', r'(?i)sqli', r'(?i)xss.*stored',
            r'(?i)ssrf', r'(?i)xxe', r'(?i)lfi.*passwd',
            r'(?i)token.?leak', r'(?i)api.?key.*valid',
            r'(?i)jwt.*weak', r'(?i)idor',
        ],
        'keywords': ['sqli', 'sql injection', 'stored xss', 'ssrf', 'xxe',
                      'file inclusion', 'token leak', 'api key', 'idor'],
        'weight': 5,
    },
    'Medium': {
        'patterns': [
            r'(?i)xss.*reflected', r'(?i)cors', r'(?i)csrf',
            r'(?i)open.?redirect', r'(?i)info.?disclosure',
            r'(?i)directory.?listing', r'(?i)session.*fixation',
        ],
        'keywords': ['reflected xss', 'cors', 'csrf', 'redirect', 'disclosure',
                      'directory listing', 'session', 'clickjacking'],
        'weight': 2,
    },
    'Low': {
        'patterns': [
            r'(?i)missing.?header', r'(?i)cookie.*flag',
            r'(?i)information.*banner', r'(?i)version.?disclosure',
        ],
        'keywords': ['missing header', 'cookie flag', 'banner', 'version'],
        'weight': 1,
    },
}

EXPLOIT_PROBABILITY = {
    'rce': 0.95, 'command injection': 0.95, 'deserialization': 0.90,
    'sql injection': 0.85, 'sqli': 0.85, 'authentication bypass': 0.90,
    'ssrf': 0.80, 'lfi': 0.75, 'xxe': 0.70,
    'stored xss': 0.65, 'idor': 0.70,
    'reflected xss': 0.50, 'open redirect': 0.40,
    'cors': 0.35, 'csrf': 0.30,
    'clickjacking': 0.20, 'missing header': 0.10,
}


def _calculate_exploitability(finding):
    """Calculate exploitability score based on finding type."""
    vuln_type = str(finding.get('type', finding.get('vulnerability', ''))).lower()
    for key, prob in EXPLOIT_PROBABILITY.items():
        if key in vuln_type:
            return prob
    return 0.3


def _calculate_impact(finding):
    """Calculate business impact score."""
    impact = 0.5
    vuln_type = str(finding.get('type', '')).lower()

    if any(kw in vuln_type for kw in ['admin', 'credential', 'database', 'rce', 'auth']):
        impact = 1.0
    elif any(kw in vuln_type for kw in ['sql', 'ssrf', 'xxe', 'deserial', 'lfi']):
        impact = 0.8
    elif any(kw in vuln_type for kw in ['xss', 'idor', 'token']):
        impact = 0.6
    elif any(kw in vuln_type for kw in ['redirect', 'cors', 'csrf']):
        impact = 0.4

    url = str(finding.get('url', '')).lower()
    if any(kw in url for kw in ['/admin', '/api', '/auth', '/login', '/payment']):
        impact = min(impact + 0.2, 1.0)

    return impact


def classify_vulnerability(finding):
    """Classify a single vulnerability with AI-style scoring."""
    vuln_type = str(finding.get('type', finding.get('vulnerability', ''))).lower()
    classified_severity = 'Info'
    matched_rule = None

    for severity, rule in VULN_PRIORITY_RULES.items():
        for pattern in rule['patterns']:
            if re.search(pattern, vuln_type):
                classified_severity = severity
                matched_rule = severity
                break
        if matched_rule:
            break

        for keyword in rule['keywords']:
            if keyword in vuln_type:
                classified_severity = severity
                matched_rule = severity
                break
        if matched_rule:
            break

    exploitability = _calculate_exploitability(finding)
    impact = _calculate_impact(finding)
    risk_score = round((exploitability * 0.6 + impact * 0.4) * 100)

    return {
        'original': finding,
        'classified_severity': classified_severity,
        'exploitability': round(exploitability, 2),
        'impact': round(impact, 2),
        'risk_score': risk_score,
        'priority': 'Immediate' if risk_score >= 80 else 'High' if risk_score >= 60 else 'Medium' if risk_score >= 40 else 'Low',
    }


def classify_all_findings(findings):
    """Classify and prioritize all findings."""
    console.print(f"\n[bold cyan]--- AI Vulnerability Classifier ---[/bold cyan]")

    if not findings:
        console.print(f"  [dim]No findings to classify[/dim]")
        return {'classified': [], 'summary': {}}

    classified = []
    for finding in findings:
        result = classify_vulnerability(finding)
        classified.append(result)

    classified.sort(key=lambda x: x['risk_score'], reverse=True)

    priority_counts = Counter(c['priority'] for c in classified)
    severity_counts = Counter(c['classified_severity'] for c in classified)

    console.print(f"\n  [bold]Classification Results:[/bold]")
    console.print(f"  [red]Immediate Action: {priority_counts.get('Immediate', 0)}[/red]")
    console.print(f"  [yellow]High Priority: {priority_counts.get('High', 0)}[/yellow]")
    console.print(f"  [cyan]Medium Priority: {priority_counts.get('Medium', 0)}[/cyan]")
    console.print(f"  [dim]Low Priority: {priority_counts.get('Low', 0)}[/dim]")

    console.print(f"\n  [bold]Top 5 Critical Findings:[/bold]")
    for item in classified[:5]:
        f = item['original']
        vuln_type = f.get('type', f.get('vulnerability', 'Unknown'))
        console.print(f"  [{'red' if item['risk_score'] >= 80 else 'yellow'}]"
                       f"Score: {item['risk_score']}/100 | {item['priority']} | {vuln_type}[/{'red' if item['risk_score'] >= 80 else 'yellow'}]")
        console.print(f"    [dim]Exploit: {item['exploitability']*100:.0f}% | Impact: {item['impact']*100:.0f}%[/dim]")

    avg_score = sum(c['risk_score'] for c in classified) / len(classified) if classified else 0
    overall_risk = 'Critical' if avg_score >= 70 else 'High' if avg_score >= 50 else 'Medium' if avg_score >= 30 else 'Low'

    console.print(f"\n  [bold {'red' if overall_risk in ('Critical','High') else 'yellow'}]"
                   f"Overall Risk: {overall_risk} (avg score: {avg_score:.0f}/100)[/bold {'red' if overall_risk in ('Critical','High') else 'yellow'}]")

    return {
        'classified': classified,
        'summary': {
            'total': len(classified),
            'priority_counts': dict(priority_counts),
            'severity_counts': dict(severity_counts),
            'avg_risk_score': round(avg_score),
            'overall_risk': overall_risk,
        },
    }
