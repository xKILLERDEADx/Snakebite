"""AI Vulnerability Predictor — ML-style pattern analysis to predict vulns."""

import aiohttp
import asyncio
import re
import time
import hashlib
import statistics
from urllib.parse import urljoin
from modules.core import console

VULN_SIGNATURES = {
    'sql_injection': {
        'weight': 0.95,
        'indicators': [
            (r'(?:mysql|mariadb|postgresql|sqlite|oracle|mssql)', 0.3),
            (r'(?:error|warning|notice).*sql', 0.8),
            (r'(?:select|union|insert|update|delete)\s+', 0.2),
            (r'database\s+error', 0.9),
            (r'syntax\s+error.+query', 0.95),
        ],
    },
    'xss': {
        'weight': 0.85,
        'indicators': [
            (r'<script', 0.4),
            (r'onerror\s*=', 0.7),
            (r'javascript:', 0.6),
            (r'innerHTML', 0.3),
            (r'document\.(cookie|write|location)', 0.5),
        ],
    },
    'ssti': {
        'weight': 0.90,
        'indicators': [
            (r'\b49\b', 0.6),
            (r'\{\{.*\}\}', 0.3),
            (r'<%.*%>', 0.3),
            (r'config', 0.2),
            (r'class.*subclasses', 0.9),
        ],
    },
    'path_traversal': {
        'weight': 0.80,
        'indicators': [
            (r'root:.*:0:0', 0.95),
            (r'\[boot\s+loader\]', 0.95),
            (r'(?:/etc/|C:\\Windows\\)', 0.85),
            (r'No such file or directory', 0.3),
            (r'failed to open stream', 0.5),
        ],
    },
    'ssrf': {
        'weight': 0.88,
        'indicators': [
            (r'169\.254\.169\.254', 0.95),
            (r'ami-[a-z0-9]+', 0.9),
            (r'localhost|127\.0\.0\.1', 0.4),
            (r'internal\s+server', 0.3),
            (r'connection\s+refused', 0.2),
        ],
    },
    'auth_bypass': {
        'weight': 0.92,
        'indicators': [
            (r'admin|administrator', 0.3),
            (r'dashboard|control\s*panel', 0.5),
            (r'(?:logout|sign\s*out)', 0.6),
            (r'user.*role.*admin', 0.8),
            (r'welcome.*admin', 0.9),
        ],
    },
    'info_disclosure': {
        'weight': 0.70,
        'indicators': [
            (r'stack\s*trace', 0.8),
            (r'debug\s*=\s*true', 0.7),
            (r'(?:PHP|ASP|JSP)\s+(?:Warning|Notice|Error)', 0.6),
            (r'<!--.*(?:TODO|FIXME|HACK|password)', 0.5),
            (r'(?:api[_-]?key|secret[_-]?key)\s*[:=]', 0.9),
        ],
    },
}


async def _analyze_response(session, url, payload_type, payload, param='q'):
    """Inject payload and analyze response for vuln indicators."""
    try:
        start = time.time()
        async with session.get(url, params={param: payload},
                               timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            elapsed = time.time() - start
            body = await resp.text()
            status = resp.status
            size = len(body)
            headers = dict(resp.headers)

            return {
                'status': status, 'size': size, 'time': elapsed,
                'body': body[:5000], 'headers': headers,
            }
    except Exception:
        return None


async def _predict_vulnerabilities(session, url):
    """Run predictive analysis on target."""
    predictions = []

    test_payloads = {
        'sql_injection': ["' OR '1'='1", "1 UNION SELECT NULL--", "1' AND SLEEP(0)--"],
        'xss': ["<img src=x>", "javascript:void(0)", "{{7*7}}"],
        'ssti': ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        'path_traversal': ["../etc/passwd", "....//....//etc/passwd", "..\\windows\\win.ini"],
        'ssrf': ["http://127.0.0.1", "http://169.254.169.254/"],
        'info_disclosure': ["%00", "' --", "{}"],
    }

    baseline = await _analyze_response(session, url, 'baseline', 'normal_value')
    if not baseline:
        return predictions

    for vuln_type, payloads in test_payloads.items():
        scores = []
        for payload in payloads:
            result = await _analyze_response(session, url, vuln_type, payload)
            if not result:
                continue

            score = 0.0
            vuln_config = VULN_SIGNATURES.get(vuln_type, {})

            for pattern, indicator_weight in vuln_config.get('indicators', []):
                if re.search(pattern, result['body'], re.I):
                    if not re.search(pattern, baseline['body'], re.I):
                        score += indicator_weight * 0.5
                    else:
                        score += indicator_weight * 0.1

            if result['status'] == 500 and baseline['status'] != 500:
                score += 0.3
            if result['status'] == 200 and baseline['status'] != 200:
                score += 0.2

            size_diff = abs(result['size'] - baseline['size'])
            if size_diff > baseline['size'] * 2:
                score += 0.2

            if result['time'] > baseline['time'] * 3 and result['time'] > 2:
                score += 0.4

            scores.append(min(score, 1.0))

        if scores:
            avg_score = statistics.mean(scores)
            max_score = max(scores)
            confidence = avg_score * vuln_config.get('weight', 0.5) * 100

            if confidence > 15:
                predictions.append({
                    'vulnerability': vuln_type,
                    'confidence': round(confidence, 1),
                    'max_signal': round(max_score * 100, 1),
                    'severity': 'Critical' if confidence > 70 else 'High' if confidence > 40 else 'Medium' if confidence > 20 else 'Low',
                    'samples': len(scores),
                })

    predictions.sort(key=lambda x: x['confidence'], reverse=True)
    return predictions


async def scan_ai_predict(session, url):
    """AI-style vulnerability prediction engine."""
    console.print(f"\n[bold cyan]--- AI Vulnerability Predictor ---[/bold cyan]")
    console.print(f"  [cyan]Running predictive analysis with {len(VULN_SIGNATURES)} models...[/cyan]")

    predictions = await _predict_vulnerabilities(session, url)

    if predictions:
        console.print(f"\n  [bold]Vulnerability Predictions:[/bold]")
        for p in predictions:
            color = 'red' if p['severity'] in ('Critical', 'High') else 'yellow'
            console.print(f"  [{color}]{p['vulnerability']}: {p['confidence']}% confidence [{p['severity']}][/{color}]")

        high_risk = [p for p in predictions if p['confidence'] > 40]
        if high_risk:
            console.print(f"\n  [bold red]{len(high_risk)} high-confidence predictions![/bold red]")
    else:
        console.print(f"\n  [green]✓ No significant vulnerability signals[/green]")

    return {'predictions': predictions}
