"""Rate Limit Detection — detect and adapt to target rate limiting."""

import aiohttp
import asyncio
import time
from modules.core import console

async def detect_rate_limit(session, url):
    """Detect rate limiting by sending burst requests and monitoring responses."""
    console.print(f"\n[bold cyan]--- Rate Limit Detection ---[/bold cyan]")

    results = {
        'rate_limited': False,
        'limit_type': 'none',
        'threshold': 0,
        'response_pattern': [],
        'headers_found': {},
        'recommended_delay': 0.0,
    }

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            headers = dict(resp.headers)
            rl_headers = {}

            rate_header_names = [
                'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
                'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset',
                'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset',
                'retry-after', 'x-retry-after',
                'x-ratelimit-requests-limit', 'x-ratelimit-requests-remaining',
            ]

            for h_name in rate_header_names:
                for actual_name, actual_value in headers.items():
                    if actual_name.lower() == h_name:
                        rl_headers[h_name] = actual_value

            results['headers_found'] = rl_headers

            if rl_headers:
                console.print(f"  [yellow]Rate limit headers found:[/yellow]")
                for h, v in rl_headers.items():
                    console.print(f"    [dim]{h}: {v}[/dim]")

                limit = rl_headers.get('x-ratelimit-limit', rl_headers.get('ratelimit-limit', ''))
                if limit:
                    try:
                        results['threshold'] = int(limit)
                    except ValueError:
                        pass
    except Exception as e:
        console.print(f"  [red]Error: {e}[/red]")
        return results

    console.print(f"  [cyan]Running burst test (20 rapid requests)...[/cyan]")
    responses = []
    start_time = time.time()

    for i in range(20):
        try:
            req_start = time.time()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                req_time = time.time() - req_start
                responses.append({
                    'request_num': i + 1,
                    'status': resp.status,
                    'time': round(req_time, 3),
                    'length': int(resp.headers.get('content-length', 0)),
                })

                if resp.status == 429:
                    results['rate_limited'] = True
                    results['limit_type'] = 'HTTP 429'
                    results['threshold'] = i + 1
                    retry_after = resp.headers.get('Retry-After', '')
                    if retry_after:
                        try:
                            results['recommended_delay'] = float(retry_after)
                        except ValueError:
                            results['recommended_delay'] = 1.0
                    else:
                        results['recommended_delay'] = 1.0
                    break
                elif resp.status == 503 and i > 5:
                    results['rate_limited'] = True
                    results['limit_type'] = 'HTTP 503 (Service Unavailable)'
                    results['threshold'] = i + 1
                    results['recommended_delay'] = 0.5
                    break
        except aiohttp.ClientError:
            if i > 3:
                results['rate_limited'] = True
                results['limit_type'] = 'Connection Reset'
                results['threshold'] = i + 1
                results['recommended_delay'] = 2.0
                break
        except Exception:
            pass

    elapsed = time.time() - start_time
    results['response_pattern'] = responses

    if not results['rate_limited'] and len(responses) >= 10:
        early_times = [r['time'] for r in responses[:5]]
        late_times = [r['time'] for r in responses[-5:]]
        avg_early = sum(early_times) / len(early_times) if early_times else 0
        avg_late = sum(late_times) / len(late_times) if late_times else 0

        if avg_late > avg_early * 3 and avg_late > 1.0:
            results['rate_limited'] = True
            results['limit_type'] = 'Soft Rate Limit (Response Throttling)'
            results['recommended_delay'] = avg_late

    if results['rate_limited']:
        console.print(f"\n  [bold red]⚠ Rate Limiting Detected![/bold red]")
        console.print(f"    [red]Type:[/red] {results['limit_type']}")
        console.print(f"    [red]Threshold:[/red] ~{results['threshold']} requests before blocking")
        console.print(f"    [yellow]Recommended delay:[/yellow] {results['recommended_delay']}s between requests")
    else:
        console.print(f"\n  [green]✓ No rate limiting detected in {len(responses)} requests ({elapsed:.1f}s)[/green]")

    if rl_headers:
        console.print(f"\n  [bold yellow]Rate Limit Headers:[/bold yellow]")
        for h, v in rl_headers.items():
            console.print(f"    {h}: {v}")

    return results
