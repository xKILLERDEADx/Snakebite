"""HTTP Parameter Pollution Scanner — server-side HPP, parser differential, array injection."""

import aiohttp
import asyncio
from modules.core import console

HPP_PARAMS = ['id', 'user', 'page', 'search', 'action', 'type', 'role', 'admin',
              'redirect', 'url', 'email', 'callback', 'token', 'file']

async def _test_duplicate_params(session, url):
    findings = []
    for param in HPP_PARAMS[:8]:
        try:
            test_url = f"{url}?{param}=value1&{param}=value2"
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                body = await resp.text()
                if 'value1' in body and 'value2' in body:
                    findings.append({'type': f'HPP Both Values: ?{param}', 'severity': 'Medium',
                                     'detail': 'Server processes both duplicate params'})
                elif 'value2' in body and 'value1' not in body:
                    findings.append({'type': f'HPP Last Wins: ?{param}', 'severity': 'Medium',
                                     'detail': 'Last param value overrides first'})
        except Exception:
            pass
    return findings

async def _test_array_injection(session, url):
    findings = []
    for param in HPP_PARAMS[:6]:
        array_formats = [
            (f'{param}[]=val1&{param}[]=val2', 'PHP array'),
            (f'{param}=val1,val2', 'Comma separated'),
            (f'{param}[0]=val1&{param}[1]=val2', 'Indexed array'),
        ]
        for payload, desc in array_formats:
            try:
                async with session.get(f'{url}?{payload}', timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                    body = await resp.text()
                    if 'val1' in body or 'val2' in body:
                        findings.append({'type': f'Array Injection ({desc}): ?{param}', 'severity': 'Medium'})
                        break
            except Exception:
                pass
    return findings

async def _test_parser_differential(session, url):
    findings = []
    differentials = [
        ('id=1&id=2%00', 'Null byte differential'),
        ('id=1&id=2%0d%0a', 'CRLF differential'),
        ('id=1&ID=2', 'Case differential'),
        ('id=1&id[]=2', 'Type confusion'),
        ('id=admin&id=user', 'Auth parameter override'),
    ]
    for payload, desc in differentials:
        try:
            async with session.get(f'{url}?{payload}', timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                body = await resp.text()
                if resp.status not in (400, 404) and len(body) > 10:
                    normal = None
                    async with session.get(f'{url}?id=1', timeout=aiohttp.ClientTimeout(total=5), ssl=False) as nr:
                        normal = await nr.text()
                    if normal and body != normal:
                        findings.append({'type': f'Parser Diff: {desc}', 'severity': 'High'})
        except Exception:
            pass
    return findings

async def scan_hpp(session, url):
    console.print(f"\n[bold cyan]--- HTTP Parameter Pollution ---[/bold cyan]")
    all_f = []
    console.print(f"  [cyan]Testing duplicate params...[/cyan]")
    all_f.extend(await _test_duplicate_params(session, url))
    console.print(f"  [cyan]Testing array injection...[/cyan]")
    all_f.extend(await _test_array_injection(session, url))
    console.print(f"  [cyan]Testing parser differentials...[/cyan]")
    all_f.extend(await _test_parser_differential(session, url))
    for f in all_f:
        console.print(f"  [red]⚠ {f['type']}[/red]")
    if not all_f:
        console.print(f"\n  [green]✓ No HPP issues[/green]")
    return {'findings': all_f}
