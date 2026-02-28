"""ReDoS Scanner — test for Regular Expression Denial of Service."""

import aiohttp
import asyncio
import time
from modules.core import console

REDOS_PAYLOADS = [
    ('a' * 50) + '!',
    ('a' * 100) + '!',
    'a' * 30 + '@' + 'a' * 30 + '.com',
    ('0' * 50) + 'x',
    ('<' + 'a' * 50 + '>'),
    ('{' + '"a":' * 30 + '"x"' + '}' * 30),
    ('(' + ')(' * 25 + ')' * 25),
    ('\t' * 50 + 'x'),
    ('\\' * 50),
    ('%' + 'a' * 50),
    'aaaaaaaaaaaaaaaaaaaaaaaaa' + chr(0) + 'b',
    '.' * 50 + '@' + '.' * 50,
]

INJECTION_PARAMS = [
    'email', 'username', 'name', 'search', 'q', 'query',
    'pattern', 'regex', 'filter', 'input', 'url', 'path',
    'value', 'text', 'data', 'comment',
]


async def _test_redos_param(session, url, param, payload, baseline_time):
    """Test a parameter for ReDoS by measuring response time."""
    try:
        start = time.time()
        async with session.get(url, params={param: payload},
                               timeout=aiohttp.ClientTimeout(total=15),
                               ssl=False) as resp:
            await resp.text()
        elapsed = time.time() - start

        if elapsed > baseline_time * 3 and elapsed > 2:
            return {
                'type': 'ReDoS (Potential)',
                'param': param,
                'payload': repr(payload[:40]),
                'response_time': round(elapsed, 2),
                'baseline': round(baseline_time, 2),
                'multiplier': round(elapsed / max(baseline_time, 0.01), 1),
                'severity': 'High' if elapsed > 5 else 'Medium',
            }
    except asyncio.TimeoutError:
        return {
            'type': 'ReDoS (Timeout)',
            'param': param,
            'payload': repr(payload[:40]),
            'response_time': 15,
            'severity': 'Critical',
        }
    except Exception:
        pass
    return None


async def _test_redos_post(session, url, param, payload, baseline_time):
    """Test POST body for ReDoS."""
    try:
        start = time.time()
        async with session.post(url, data={param: payload},
                                timeout=aiohttp.ClientTimeout(total=15),
                                ssl=False) as resp:
            await resp.text()
        elapsed = time.time() - start

        if elapsed > baseline_time * 3 and elapsed > 2:
            return {
                'type': 'ReDoS POST (Potential)',
                'param': param,
                'payload': repr(payload[:40]),
                'response_time': round(elapsed, 2),
                'severity': 'High' if elapsed > 5 else 'Medium',
            }
    except asyncio.TimeoutError:
        return {
            'type': 'ReDoS POST (Timeout)',
            'param': param,
            'severity': 'Critical',
        }
    except Exception:
        pass
    return None


async def scan_redos(session, url):
    """Scan for Regular Expression Denial of Service vulnerabilities."""
    console.print(f"\n[bold cyan]--- ReDoS Scanner ---[/bold cyan]")
    console.print(f"  [cyan]Testing {len(REDOS_PAYLOADS)} payloads x {len(INJECTION_PARAMS)} params...[/cyan]")

    start = time.time()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            await resp.text()
    except Exception:
        pass
    baseline = time.time() - start

    console.print(f"  [dim]Baseline response: {baseline:.2f}s[/dim]")

    all_findings = []
    for param in INJECTION_PARAMS:
        for payload in REDOS_PAYLOADS:
            result = await _test_redos_param(session, url, param, payload, baseline)
            if result:
                all_findings.append(result)
                sev_color = 'red' if result['severity'] == 'Critical' else 'yellow'
                console.print(f"  [{sev_color}]⚠ {result['type']}: {param} ({result['response_time']}s vs {baseline:.2f}s)[/{sev_color}]")

            result_post = await _test_redos_post(session, url, param, payload, baseline)
            if result_post:
                all_findings.append(result_post)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} ReDoS vectors found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No ReDoS vulnerabilities detected[/green]")

    return {'findings': all_findings, 'baseline': round(baseline, 2)}
