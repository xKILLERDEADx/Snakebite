"""Smart Parameter Discovery & Fuzzing — discover hidden parameters via real requests."""

import aiohttp
import asyncio
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from modules.core import console

COMMON_PARAMS = [
    'id', 'page', 'user', 'username', 'name', 'email', 'password', 'pass',
    'search', 'q', 'query', 'filter', 'sort', 'order', 'limit', 'offset',
    'token', 'key', 'api_key', 'apikey', 'auth', 'session', 'sid',
    'debug', 'test', 'admin', 'action', 'cmd', 'command', 'exec',
    'file', 'path', 'dir', 'folder', 'url', 'redirect', 'next', 'return',
    'callback', 'cb', 'ref', 'source', 'utm_source', 'from',
    'lang', 'language', 'locale', 'format', 'type', 'mode', 'view',
    'category', 'cat', 'tag', 'status', 'state', 'role',
    'config', 'setting', 'option', 'param', 'data', 'value', 'input',
    'output', 'result', 'response', 'request', 'method', 'version', 'v',
    'include', 'require', 'import', 'load', 'template', 'theme',
    'width', 'height', 'size', 'color', 'bg', 'style', 'css',
    'json', 'xml', 'csv', 'raw', 'download', 'export', 'print',
    'year', 'month', 'day', 'date', 'time', 'start', 'end', 'from', 'to',
    'count', 'num', 'max', 'min', 'step', 'index', 'pos', 'cursor',
    'table', 'column', 'field', 'db', 'database', 'schema',
    'host', 'port', 'server', 'proxy', 'ip', 'address',
    'access', 'grant', 'scope', 'permission', 'level', 'group',
    'secret', 'private', 'public', 'internal', 'hidden', 'show',
    'enable', 'disable', 'on', 'off', 'true', 'false', 'yes', 'no',
    'continue', 'submit', 'confirm', 'cancel', 'delete', 'remove',
    'upload', 'attach', 'media', 'image', 'photo', 'video', 'document',
    'message', 'msg', 'text', 'content', 'body', 'title', 'subject',
    'comment', 'note', 'description', 'info', 'detail', 'summary',
    'price', 'amount', 'total', 'qty', 'quantity', 'discount', 'coupon',
    'product', 'item', 'sku', 'code', 'number', 'ref',
    'wp_nonce', '_wpnonce', 'csrf_token', '_token', 'authenticity_token',
]

async def _get_baseline_response(session, url):
    """Get baseline response for comparison."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False, allow_redirects=True) as resp:
            body = await resp.text()
            return {
                'status': resp.status,
                'length': len(body),
                'headers': dict(resp.headers),
                'body_hash': hash(body[:5000]),
            }
    except Exception:
        return None


async def _test_param(session, url, param_name, baseline):
    """Test if a parameter is reflected or causes different behavior."""
    canary = 'snkbt3st'
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)
    existing_params[param_name] = [canary]
    new_query = urlencode(existing_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    try:
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=True) as resp:
            body = await resp.text()
            response_length = len(body)

            result = {
                'param': param_name,
                'status': resp.status,
                'length': response_length,
                'reflected': canary in body,
                'length_diff': abs(response_length - baseline['length']),
                'status_diff': resp.status != baseline['status'],
            }

            is_interesting = (
                result['reflected'] or
                result['status_diff'] or
                result['length_diff'] > 50
            )

            if is_interesting:
                return result

    except Exception:
        pass
    return None


async def scan_param_fuzzer(session, url):
    """Discover hidden parameters via real request fuzzing."""
    console.print(f"\n[bold cyan]--- Smart Parameter Discovery ---[/bold cyan]")
    console.print(f"  [dim]Testing {len(COMMON_PARAMS)} common parameters...[/dim]")

    baseline = await _get_baseline_response(session, url)
    if not baseline:
        console.print(f"  [red]Could not get baseline response[/red]")
        return []

    console.print(f"  [dim]Baseline: status={baseline['status']}, length={baseline['length']}[/dim]")

    results = []
    batch_size = 15
    for i in range(0, len(COMMON_PARAMS), batch_size):
        batch = COMMON_PARAMS[i:i + batch_size]
        tasks = [_test_param(session, url, param, baseline) for param in batch]
        batch_results = await asyncio.gather(*tasks)

        for r in batch_results:
            if r:
                results.append(r)
                indicators = []
                if r['reflected']:
                    indicators.append('[red]REFLECTED[/red]')
                if r['status_diff']:
                    indicators.append(f'[yellow]Status→{r["status"]}[/yellow]')
                if r['length_diff'] > 50:
                    indicators.append(f'[cyan]ΔLen={r["length_diff"]}[/cyan]')

                console.print(f"    [bold green]✓ ?{r['param']}=[/bold green] {' | '.join(indicators)}")

        await asyncio.sleep(0.1)

    if results:
        console.print(f"\n  [bold green]Found {len(results)} active parameters![/bold green]")
        reflected = [r for r in results if r['reflected']]
        if reflected:
            console.print(f"  [bold red]⚠ {len(reflected)} reflected params (potential XSS)[/bold red]")
    else:
        console.print(f"\n  [dim]No hidden parameters discovered[/dim]")

    return results
