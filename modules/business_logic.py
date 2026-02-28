"""Business Logic Fuzzer — smart price manipulation, coupon abuse, cart logic."""

import aiohttp
import asyncio
import json
from urllib.parse import urljoin
from modules.core import console

PRICE_MANIPULATION = [
    {'price': 0}, {'price': -1}, {'price': 0.01}, {'price': 0.001},
    {'amount': 0}, {'amount': -100}, {'total': 0}, {'total': -1},
    {'discount': 100}, {'discount': 999}, {'discount': -1},
    {'quantity': -1}, {'quantity': 0}, {'quantity': 99999},
    {'tax': 0}, {'shipping': 0}, {'fee': -10},
]

COUPON_ABUSE = [
    {'code': 'DISCOUNT100', 'apply': True},
    {'code': 'FREE', 'apply': True},
    {'code': 'ADMIN', 'apply': True},
    {'code': 'TEST', 'apply': True},
    {'code': '0', 'apply': True},
    {'code': 'null', 'apply': True},
    {'code': "' OR '1'='1", 'apply': True},
]

LOGIC_ENDPOINTS = {
    'cart': ['/api/cart', '/api/cart/update', '/cart', '/api/v1/cart'],
    'checkout': ['/api/checkout', '/checkout', '/api/v1/checkout', '/api/order'],
    'coupon': ['/api/coupon', '/api/coupon/apply', '/api/discount', '/api/promo'],
    'payment': ['/api/payment', '/api/pay', '/api/v1/payment'],
    'transfer': ['/api/transfer', '/api/send', '/api/v1/transfer'],
}


async def _test_price_manipulation(session, url, endpoint):
    """Test price/amount manipulation."""
    findings = []
    test_url = urljoin(url, endpoint)

    for payload in PRICE_MANIPULATION:
        try:
            async with session.post(test_url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=8),
                                    ssl=False) as resp:
                if resp.status in (200, 201):
                    body = await resp.text()
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            total = data.get('total', data.get('amount', data.get('price', None)))
                            if total is not None and (total <= 0 or total == 0.01):
                                findings.append({
                                    'type': 'Price Manipulation',
                                    'endpoint': endpoint,
                                    'payload': str(payload)[:50],
                                    'result_total': total,
                                    'severity': 'Critical',
                                })
                    except Exception:
                        pass
        except Exception:
            pass

    return findings


async def _test_coupon_abuse(session, url, endpoints):
    """Test coupon/discount code abuse."""
    findings = []

    for endpoint in endpoints:
        test_url = urljoin(url, endpoint)
        for payload in COUPON_ABUSE:
            try:
                async with session.post(test_url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        success_indicators = ['success', 'applied', 'valid', 'discount', 'accepted']
                        if any(ind in body.lower() for ind in success_indicators):
                            findings.append({
                                'type': 'Coupon Code Accepted',
                                'endpoint': endpoint,
                                'code': payload['code'],
                                'severity': 'High' if payload['code'] in ('FREE', 'ADMIN', "' OR '1'='1") else 'Medium',
                            })
            except Exception:
                pass

        try:
            test_url_apply = urljoin(url, endpoint)
            payload = {'code': 'DISCOUNT50', 'apply': True}
            for _ in range(3):
                async with session.post(test_url_apply, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=5),
                                        ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
        except Exception:
            pass

    return findings


async def _test_negative_quantity(session, url, endpoints):
    """Test negative quantity / reverse transaction attacks."""
    findings = []

    negative_payloads = [
        {'quantity': -1, 'item_id': 1},
        {'amount': -100, 'to': 'attacker'},
        {'items': [{'id': 1, 'qty': -5}]},
    ]

    for endpoint in endpoints:
        test_url = urljoin(url, endpoint)
        for payload in negative_payloads:
            try:
                async with session.post(test_url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as resp:
                    if resp.status in (200, 201):
                        body = await resp.text()
                        if 'success' in body.lower() or 'total' in body.lower():
                            findings.append({
                                'type': 'Negative Value Accepted',
                                'endpoint': endpoint,
                                'payload': str(payload)[:60],
                                'severity': 'Critical',
                            })
            except Exception:
                pass

    return findings


async def scan_business_logic(session, url):
    """Smart business logic vulnerability fuzzer."""
    console.print(f"\n[bold cyan]--- Business Logic Fuzzer ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Testing price manipulation...[/cyan]")
    for endpoints in [LOGIC_ENDPOINTS['cart'], LOGIC_ENDPOINTS['checkout'], LOGIC_ENDPOINTS['payment']]:
        for ep in endpoints:
            findings = await _test_price_manipulation(session, url, ep)
            all_findings.extend(findings)
            for f in findings:
                console.print(f"  [bold red]⚠ {f['type']}: {f['endpoint']} (total={f['result_total']})[/bold red]")

    console.print(f"  [cyan]Testing coupon abuse...[/cyan]")
    coupon_findings = await _test_coupon_abuse(session, url, LOGIC_ENDPOINTS['coupon'])
    all_findings.extend(coupon_findings)
    for f in coupon_findings:
        console.print(f"  [red]{f['type']}: {f['code']}[/red]")

    console.print(f"  [cyan]Testing negative values...[/cyan]")
    neg_findings = await _test_negative_quantity(session, url,
                                                  LOGIC_ENDPOINTS['cart'] + LOGIC_ENDPOINTS['transfer'])
    all_findings.extend(neg_findings)
    for f in neg_findings:
        console.print(f"  [bold red]{f['type']}: {f['endpoint']}[/bold red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} business logic flaws![/bold red]")
    else:
        console.print(f"\n  [green]✓ No business logic vulnerabilities detected[/green]")

    return {'findings': all_findings}
