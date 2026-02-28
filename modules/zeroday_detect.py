"""Zero-Day Pattern Detector — heuristic anomaly analysis for unknown vulnerabilities."""

import aiohttp
import asyncio
import re
import time
import hashlib
import statistics
from urllib.parse import urljoin, urlparse, quote
from modules.core import console

ANOMALY_TESTS = {
    'buffer_overflow': {
        'payloads': ['A' * 1000, 'A' * 5000, 'A' * 10000, '%n' * 100, '%s' * 100],
        'indicators': ['segfault', 'core dump', 'buffer overflow', 'stack smash',
                       'memory', 'abort', 'violation', 'SIGSEGV'],
    },
    'format_string': {
        'payloads': ['%x' * 50, '%n%n%n%n', '%s%s%s%s', '%p%p%p%p',
                     '${jndi:ldap://x}', '%08x.' * 20],
        'indicators': ['0x', '(nil)', 'AAAA', 'segfault', 'core dump'],
    },
    'integer_overflow': {
        'payloads': ['2147483647', '2147483648', '-2147483649', '99999999999999999',
                     '0', '-1', '-0', '0x7FFFFFFF'],
        'indicators': ['overflow', 'out of range', 'numeric', 'integer', 'conversion'],
    },
    'type_juggling': {
        'payloads': ['0', 'null', 'undefined', 'NaN', 'Infinity', '[]', '{}',
                     'true', 'false', '0e1', '0x0', '00', "''"],
        'indicators': ['type', 'cast', 'convert', 'unexpected', 'mismatch'],
    },
    'unicode_abuse': {
        'payloads': ['\u0000', '\uFFFF', '\u202E', '\uFEFF', '\u200B',
                     'A\u0300' * 50, '\uD800', '%C0%AE%C0%AE'],
        'indicators': ['encoding', 'unicode', 'character', 'invalid', 'malformed'],
    },
}

FUZZ_PARAMS = ['id', 'q', 'search', 'page', 'user', 'name', 'file',
               'data', 'input', 'value', 'cmd', 'action', 'type']


async def _get_baseline(session, url):
    """Establish normal response baseline."""
    baselines = []
    for _ in range(3):
        try:
            start = time.time()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False) as resp:
                body = await resp.text()
                elapsed = time.time() - start
                baselines.append({
                    'status': resp.status,
                    'size': len(body),
                    'time': elapsed,
                    'headers': dict(resp.headers),
                    'hash': hashlib.md5(body.encode()).hexdigest(),
                })
        except Exception:
            pass
    if not baselines:
        return None
    return {
        'status': baselines[0]['status'],
        'avg_size': statistics.mean([b['size'] for b in baselines]),
        'avg_time': statistics.mean([b['time'] for b in baselines]),
        'size_std': statistics.stdev([b['size'] for b in baselines]) if len(baselines) > 1 else 0,
        'time_std': statistics.stdev([b['time'] for b in baselines]) if len(baselines) > 1 else 0,
        'headers': baselines[0]['headers'],
    }


async def _detect_anomalies(session, url, baseline):
    """Run anomaly detection across all test categories."""
    findings = []

    for category, config in ANOMALY_TESTS.items():
        category_scores = []

        for payload in config['payloads']:
            for param in FUZZ_PARAMS[:5]:
                try:
                    start = time.time()
                    async with session.get(url, params={param: payload},
                                           timeout=aiohttp.ClientTimeout(total=12),
                                           ssl=False) as resp:
                        body = await resp.text()
                        elapsed = time.time() - start
                        score = 0.0

                        if resp.status == 500 and baseline['status'] != 500:
                            score += 0.4
                        elif resp.status >= 500:
                            score += 0.2

                        for indicator in config['indicators']:
                            if indicator.lower() in body.lower():
                                score += 0.3

                        size_diff = abs(len(body) - baseline['avg_size'])
                        if baseline['avg_size'] > 0:
                            size_ratio = size_diff / baseline['avg_size']
                            if size_ratio > 2:
                                score += 0.3
                            elif size_ratio > 0.5:
                                score += 0.1

                        if elapsed > baseline['avg_time'] * 3:
                            score += 0.3
                        elif elapsed > baseline['avg_time'] * 2:
                            score += 0.15

                        error_patterns = [
                            r'(?:fatal|critical)\s+error', r'exception\s+in\s+thread',
                            r'stack\s*trace', r'at\s+\w+\.\w+\(', r'traceback',
                            r'internal\s+server\s+error', r'debug\s*mode',
                            r'undefined\s+(?:variable|index|method)',
                        ]
                        for pattern in error_patterns:
                            if re.search(pattern, body, re.I):
                                score += 0.2
                                break

                        if score > 0:
                            category_scores.append({
                                'param': param, 'payload': payload[:30],
                                'score': min(score, 1.0),
                                'status': resp.status, 'time': round(elapsed, 2),
                            })
                except asyncio.TimeoutError:
                    category_scores.append({
                        'param': param, 'payload': payload[:30],
                        'score': 0.8, 'status': 0, 'time': 12,
                    })
                except Exception:
                    pass

        if category_scores:
            max_entry = max(category_scores, key=lambda x: x['score'])
            avg_score = statistics.mean([s['score'] for s in category_scores])
            if max_entry['score'] > 0.3:
                severity = 'Critical' if max_entry['score'] > 0.7 else 'High' if max_entry['score'] > 0.4 else 'Medium'
                findings.append({
                    'type': f'Zero-Day Signal: {category}',
                    'severity': severity,
                    'max_score': round(max_entry['score'] * 100, 1),
                    'avg_score': round(avg_score * 100, 1),
                    'best_param': max_entry['param'],
                    'best_payload': max_entry['payload'],
                    'samples': len(category_scores),
                })

    return findings


async def _detect_error_disclosure(session, url):
    """Check for detailed error messages that reveal internals."""
    findings = []
    error_triggers = [
        ("'", 'Single Quote'), ('\\', 'Backslash'), ('\x00', 'Null Byte'),
        ('<', 'Less Than'), ('${', 'Expression'), ('{{', 'Template'),
    ]
    for trigger, desc in error_triggers:
        for param in ['id', 'q', 'page']:
            try:
                async with session.get(url, params={param: trigger},
                                       timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                    body = await resp.text()
                    disclosures = []
                    if re.search(r'(?:\/\w+)+\.(?:py|php|java|js|rb):\d+', body):
                        disclosures.append('File path + line number')
                    if re.search(r'(?:SELECT|INSERT|UPDATE|DELETE)\s+', body, re.I):
                        disclosures.append('SQL query exposed')
                    if re.search(r'at\s+\w+\.\w+\.\w+\(', body):
                        disclosures.append('Stack trace')
                    if re.search(r'(?:DB_|DATABASE_|MYSQL_|POSTGRES_)\w+', body):
                        disclosures.append('DB config variable')
                    if disclosures:
                        findings.append({
                            'type': f'Error Disclosure ({desc}→?{param})',
                            'severity': 'High',
                            'disclosures': disclosures,
                        })
            except Exception:
                pass
    return findings


async def scan_zeroday_detect(session, url):
    """Zero-day pattern detection through heuristic analysis."""
    console.print(f"\n[bold cyan]--- Zero-Day Pattern Detector ---[/bold cyan]")

    console.print(f"  [cyan]Establishing baseline (3 samples)...[/cyan]")
    baseline = await _get_baseline(session, url)
    if not baseline:
        console.print(f"  [red]Could not establish baseline[/red]")
        return {'findings': []}

    console.print(f"  [dim]Baseline: {baseline['status']} | ~{int(baseline['avg_size'])} bytes | ~{baseline['avg_time']:.2f}s[/dim]")

    console.print(f"  [cyan]Running {len(ANOMALY_TESTS)} anomaly categories × {len(FUZZ_PARAMS[:5])} params...[/cyan]")
    anomalies = await _detect_anomalies(session, url, baseline)

    console.print(f"  [cyan]Checking error disclosure patterns...[/cyan]")
    errors = await _detect_error_disclosure(session, url)

    all_findings = anomalies + errors
    for f in all_findings:
        color = 'red' if f['severity'] in ('Critical', 'High') else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']} ({f.get('max_score', '?')}%)[/{color}]")

    if not all_findings:
        console.print(f"\n  [green]✓ No anomalous patterns detected[/green]")
    return {'baseline': baseline, 'findings': all_findings}
