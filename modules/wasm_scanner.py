"""WebAssembly Scanner — analyze WASM binaries for secrets and vulnerabilities."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin
from modules.core import console

WASM_PATHS = [
    '/main.wasm', '/app.wasm', '/module.wasm', '/game.wasm',
    '/static/wasm/', '/assets/wasm/', '/build/',
    '/wasm/', '/pkg/', '/out/', '/dist/',
]

SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', 'API Key'),
    (r'(?:password|passwd|pwd)["\s:=]+["\']?([^\s"\']{6,})', 'Password'),
    (r'(?:secret|token)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})', 'Secret/Token'),
    (r'(?:aws_access|aws_secret)["\s:=]+["\']?([A-Z0-9]{16,})', 'AWS Key'),
    (r'(?:mysql|postgres|mongodb)://[^\s"\']+', 'Database URL'),
    (r'(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)', 'Private Key'),
    (r'https?://[^\s"\']+(?:admin|internal|private)[^\s"\']*', 'Internal URL'),
]

VULN_PATTERNS = [
    (r'eval\s*\(', 'Eval Usage'),
    (r'dangerouslySetInnerHTML', 'Dangerous HTML Injection'),
    (r'document\.write', 'Document Write'),
    (r'innerHTML\s*=', 'InnerHTML Assignment'),
    (r'\.exec\s*\(', 'Exec Call'),
    (r'child_process', 'Child Process'),
    (r'__proto__', 'Prototype Access'),
]


async def _find_wasm_files(session, url):
    """Discover WASM files on the target."""
    found = []

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            body = await resp.text()
            wasm_refs = re.findall(r'["\']([^"\']*\.wasm(?:\?[^"\']*)?)["\']', body)
            for ref in wasm_refs:
                wasm_url = urljoin(url, ref)
                found.append(wasm_url)

            js_files = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body)
            for js_file in js_files[:10]:
                js_url = urljoin(url, js_file)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=8),
                                           ssl=False) as js_resp:
                        js_body = await js_resp.text()
                        wasm_in_js = re.findall(r'["\']([^"\']*\.wasm(?:\?[^"\']*)?)["\']', js_body)
                        for ref in wasm_in_js:
                            wasm_url = urljoin(url, ref)
                            if wasm_url not in found:
                                found.append(wasm_url)
                except Exception:
                    pass
    except Exception:
        pass

    for path in WASM_PATHS:
        test_url = urljoin(url, path)
        try:
            async with session.head(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                    ssl=False) as resp:
                content_type = resp.headers.get('Content-Type', '')
                if resp.status == 200 and ('wasm' in content_type or 'octet' in content_type):
                    if test_url not in found:
                        found.append(test_url)
        except Exception:
            pass

    return found


async def _analyze_wasm(session, wasm_url):
    """Download and analyze WASM binary for strings."""
    findings = []
    try:
        async with session.get(wasm_url, timeout=aiohttp.ClientTimeout(total=30),
                               ssl=False) as resp:
            if resp.status != 200:
                return findings

            data = await resp.read()
            size = len(data)

            if data[:4] != b'\x00asm':
                return findings

            strings = []
            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= 6:
                        strings.append(''.join(current))
                    current = []

            all_strings = '\n'.join(strings)

            for pattern, name in SECRET_PATTERNS:
                matches = re.findall(pattern, all_strings, re.I)
                for match in matches[:3]:
                    findings.append({
                        'type': f'WASM Secret: {name}',
                        'wasm_file': wasm_url.split('/')[-1],
                        'value': match[:40] + '...' if len(match) > 40 else match,
                        'severity': 'Critical',
                    })

            for pattern, name in VULN_PATTERNS:
                if re.search(pattern, all_strings, re.I):
                    findings.append({
                        'type': f'WASM Vuln Pattern: {name}',
                        'wasm_file': wasm_url.split('/')[-1],
                        'severity': 'Medium',
                    })

            urls = re.findall(r'https?://[^\s\x00-\x1f]{10,}', all_strings)
            for url_found in set(urls[:10]):
                findings.append({
                    'type': 'WASM Embedded URL',
                    'url': url_found[:80],
                    'severity': 'Info',
                })

            findings.append({
                'type': 'WASM File Analyzed',
                'wasm_file': wasm_url.split('/')[-1],
                'size': size,
                'strings_found': len(strings),
                'severity': 'Info',
            })

    except Exception:
        pass

    return findings


async def scan_wasm(session, url):
    """Scan for WebAssembly files and analyze them."""
    console.print(f"\n[bold cyan]--- WebAssembly Scanner ---[/bold cyan]")

    console.print(f"  [cyan]Discovering WASM files...[/cyan]")
    wasm_files = await _find_wasm_files(session, url)

    if not wasm_files:
        console.print(f"  [dim]No WASM files found[/dim]")
        return {'wasm_files': [], 'findings': []}

    console.print(f"  [green]Found {len(wasm_files)} WASM file(s)[/green]")

    all_findings = []
    for wasm_url in wasm_files[:5]:
        console.print(f"  [cyan]Analyzing: {wasm_url.split('/')[-1]}[/cyan]")
        findings = await _analyze_wasm(session, wasm_url)
        all_findings.extend(findings)

        for f in findings:
            if f['severity'] == 'Critical':
                console.print(f"  [bold red]⚠ {f['type']}: {f.get('value', '')}[/bold red]")
            elif f['severity'] == 'Medium':
                console.print(f"  [yellow]{f['type']}[/yellow]")

    secrets = [f for f in all_findings if 'Secret' in f['type']]
    if secrets:
        console.print(f"\n  [bold red]{len(secrets)} secrets found in WASM![/bold red]")

    return {'wasm_files': wasm_files, 'findings': all_findings}
