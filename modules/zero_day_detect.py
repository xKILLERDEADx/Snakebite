"""Zero-Day Pattern Detector — heuristic anomaly detection for unknown vulns."""

import aiohttp
import asyncio
import time
import re
import hashlib
from modules.core import console

ANOMALY_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{constructor.constructor('return 1')()}}",
    "${{<%[%'\"}}%\\.",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "%00", "%0d%0a", "%25%30%30",
    "' OR ''='",
    "../" * 10,
    "A" * 10000,
    "\x00\x01\x02\x03\x04\x05",
    "{{config}}", "{{self}}", "{{request}}",
    "<foo>", "<!--", "]]>", "<?xml?>",
]

ERROR_SIGNATURES = {
    'stack_trace': [r'at\s+[\w.]+\([\w.]+:\d+\)', r'File\s+"[^"]+",\s+line\s+\d+'],
    'sql_error': [r'SQL\s+syntax', r'mysql_', r'pg_query', r'ORA-\d{5}', r'SQLITE_ERROR'],
    'template_eval': [r'\b49\b', r'7\s*\*\s*7\s*=?\s*49'],
    'path_disclosure': [r'[A-Z]:\\[\w\\]+', r'/(?:home|var|usr|opt)/[\w/]+'],
    'debug_info': [r'DEBUG\s*=\s*True', r'DJANGO_SETTINGS', r'laravel', r'stack\s*trace'],
    'internal_ip': [r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}'],
    'exception': [r'(?:Exception|Error|Warning|Fatal|Traceback)', r'Unhandled\s+Exception'],
}


async def _detect_anomalies(session, url, payload):
    """Inject payload and detect anomalous behavior."""
    findings = []
    params = ['q', 'search', 'input', 'name', 'id']

    for param in params:
        try:
            baseline_start = time.time()
            async with session.get(url, params={param: 'normal_value'},
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                baseline_body = await resp.text()
                baseline_status = resp.status
                baseline_size = len(baseline_body)
            baseline_time = time.time() - baseline_start

            inject_start = time.time()
            async with session.get(url, params={param: payload},
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                inject_body = await resp.text()
                inject_status = resp.status
                inject_size = len(inject_body)
            inject_time = time.time() - inject_start

            if inject_status == 500 and baseline_status != 500:
                findings.append({
                    'type': 'Server Error Triggered',
                    'param': param,
                    'payload': repr(payload[:30]),
                    'severity': 'High',
                    'detail': f'Status changed: {baseline_status} → {inject_status}',
                })

            for sig_name, patterns in ERROR_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, inject_body, re.I) and not re.search(pattern, baseline_body, re.I):
                        findings.append({
                            'type': f'Anomaly: {sig_name}',
                            'param': param,
                            'payload': repr(payload[:30]),
                            'severity': 'High' if sig_name in ('template_eval', 'sql_error') else 'Medium',
                            'detail': f'Pattern "{pattern[:30]}" appeared in response',
                        })
                        break

            size_diff = abs(inject_size - baseline_size)
            if size_diff > baseline_size * 5 and size_diff > 5000:
                findings.append({
                    'type': 'Response Size Anomaly',
                    'param': param,
                    'payload': repr(payload[:30]),
                    'severity': 'Medium',
                    'detail': f'Size: {baseline_size}B → {inject_size}B',
                })

            if inject_time > baseline_time * 3 and inject_time > 3:
                findings.append({
                    'type': 'Timing Anomaly',
                    'param': param,
                    'payload': repr(payload[:30]),
                    'severity': 'Medium',
                    'detail': f'Time: {baseline_time:.2f}s → {inject_time:.2f}s',
                })

        except Exception:
            pass

    return findings


async def scan_zero_day(session, url):
    """Heuristic anomaly detection for unknown vulnerabilities."""
    console.print(f"\n[bold cyan]--- Zero-Day Pattern Detector ---[/bold cyan]")
    console.print(f"  [cyan]Testing {len(ANOMALY_PAYLOADS)} anomaly payloads...[/cyan]")

    all_findings = []

    for payload in ANOMALY_PAYLOADS:
        findings = await _detect_anomalies(session, url, payload)
        all_findings.extend(findings)
        for f in findings:
            sev_color = 'red' if f['severity'] == 'High' else 'yellow'
            console.print(f"  [{sev_color}]⚠ {f['type']}: param={f['param']} [{f['detail']}][/{sev_color}]")
        await asyncio.sleep(0.1)

    unique = {}
    for f in all_findings:
        key = f"{f['type']}:{f['param']}"
        if key not in unique:
            unique[key] = f

    deduped = list(unique.values())

    if deduped:
        console.print(f"\n  [bold red]{len(deduped)} anomalies detected (potential zero-days)![/bold red]")
    else:
        console.print(f"\n  [green]✓ No anomalous behavior detected[/green]")

    return {'findings': deduped}
