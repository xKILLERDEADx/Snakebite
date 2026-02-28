"""Race Condition Deep Scanner — multi-threaded TOCTOU and double-spend detection."""

import aiohttp
import asyncio
import time
from urllib.parse import urljoin
from modules.core import console

RACE_ENDPOINTS = [
    '/api/transfer', '/api/withdraw', '/api/payment', '/api/checkout',
    '/api/redeem', '/api/coupon', '/api/vote', '/api/like',
    '/api/follow', '/api/purchase', '/api/order', '/api/book',
    '/api/claim', '/api/register', '/api/signup',
    '/api/v1/transfer', '/api/v1/payment', '/api/v1/order',
]

RACE_PAYLOADS = [
    {'amount': 1, 'to': 'test_user'},
    {'coupon': 'DISCOUNT50', 'apply': True},
    {'action': 'claim', 'id': 1},
    {'quantity': 1, 'item_id': 1},
    {'vote': 1, 'option': 'a'},
]


async def _send_concurrent(session, url, data, concurrency=20):
    """Send many concurrent requests to trigger race condition."""
    results = {'responses': [], 'timings': []}

    async def single_request(i):
        start = time.time()
        try:
            async with session.post(url, json=data,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    ssl=False) as resp:
                body = await resp.text()
                elapsed = time.time() - start
                return {
                    'index': i,
                    'status': resp.status,
                    'size': len(body),
                    'time': round(elapsed, 4),
                    'body_preview': body[:100],
                }
        except Exception as e:
            return {'index': i, 'error': str(e)[:50]}

    tasks = [single_request(i) for i in range(concurrency)]
    responses = await asyncio.gather(*tasks)

    success = [r for r in responses if r.get('status') in (200, 201, 204)]
    errors = [r for r in responses if 'error' in r]

    return {
        'total_sent': concurrency,
        'success_count': len(success),
        'error_count': len(errors),
        'responses': responses,
    }


async def _test_toctou(session, url):
    """Test Time-of-Check to Time-of-Use race condition."""
    findings = []

    check_paths = ['/api/balance', '/api/account', '/api/credits', '/api/stock']
    action_paths = ['/api/transfer', '/api/withdraw', '/api/purchase', '/api/order']

    for check, action in zip(check_paths, action_paths):
        check_url = urljoin(url, check)
        action_url = urljoin(url, action)

        try:
            async with session.get(check_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status == 200:
                    pre_data = await resp.text()

                    concurrent = await _send_concurrent(session, action_url,
                                                         {'amount': 1}, concurrency=10)

                    if concurrent['success_count'] > 1:
                        async with session.get(check_url,
                                               timeout=aiohttp.ClientTimeout(total=5),
                                               ssl=False) as resp2:
                            post_data = await resp2.text()

                            if pre_data != post_data:
                                findings.append({
                                    'type': 'TOCTOU Race Condition',
                                    'check_endpoint': check,
                                    'action_endpoint': action,
                                    'concurrent_success': concurrent['success_count'],
                                    'severity': 'Critical',
                                    'detail': 'State changed after concurrent requests',
                                })
        except Exception:
            pass

    return findings


async def _test_double_spend(session, url):
    """Test for double-spend / double-submit vulnerabilities."""
    findings = []

    for endpoint in RACE_ENDPOINTS:
        test_url = urljoin(url, endpoint)

        try:
            async with session.options(test_url, timeout=aiohttp.ClientTimeout(total=3),
                                       ssl=False) as resp:
                if resp.status in (404, 500):
                    continue
        except Exception:
            continue

        for payload in RACE_PAYLOADS[:2]:
            result = await _send_concurrent(session, test_url, payload, concurrency=15)

            if result['success_count'] > 1:
                statuses = [r.get('status') for r in result['responses'] if r.get('status')]
                unique_statuses = set(statuses)

                if len(unique_statuses) == 1 and 200 in unique_statuses:
                    findings.append({
                        'type': 'Double-Spend (Potential)',
                        'endpoint': endpoint,
                        'concurrent_success': result['success_count'],
                        'severity': 'High',
                        'detail': f'All {result["success_count"]} concurrent requests succeeded',
                    })

    return findings


async def scan_race_condition(session, url):
    """Deep scan for race condition vulnerabilities."""
    console.print(f"\n[bold cyan]--- Race Condition Deep Scanner ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Testing TOCTOU (Time-of-Check-Time-of-Use)...[/cyan]")
    toctou = await _test_toctou(session, url)
    all_findings.extend(toctou)
    for f in toctou:
        console.print(f"  [bold red]⚠ {f['type']}: {f['action_endpoint']}[/bold red]")

    console.print(f"  [cyan]Testing double-spend across {len(RACE_ENDPOINTS)} endpoints...[/cyan]")
    double_spend = await _test_double_spend(session, url)
    all_findings.extend(double_spend)
    for f in double_spend:
        console.print(f"  [red]{f['type']}: {f['endpoint']} ({f['concurrent_success']} success)[/red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} race conditions found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No race conditions detected[/green]")

    return {'findings': all_findings}
