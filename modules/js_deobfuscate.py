"""JavaScript Deobfuscator — detect obfuscated JS, extract hidden endpoints/secrets."""

import aiohttp
import asyncio
import re
import base64
from urllib.parse import urljoin
from modules.core import console

OBFUSCATION_INDICATORS = [
    (r'\\x[0-9a-fA-F]{2}', 'Hex encoding'),
    (r'\\u[0-9a-fA-F]{4}', 'Unicode escapes'),
    (r'eval\s*\(', 'eval() usage'),
    (r'Function\s*\(', 'Function constructor'),
    (r'atob\s*\(', 'Base64 decode'),
    (r'String\.fromCharCode', 'CharCode strings'),
    (r'decodeURI(?:Component)?\s*\(', 'URI decoding'),
    (r'\[(?:"\\x[0-9a-f]{2}"[,\s]*){5,}\]', 'Hex array'),
    (r'_0x[a-f0-9]{4,}', 'Obfuscator.io pattern'),
    (r'var\s+_\w+\s*=\s*\[', 'Array-based obfuscation'),
]

async def _extract_js_files(session, url):
    scripts = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            inline = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S)
            for i, code in enumerate(inline):
                if len(code.strip()) > 50:
                    scripts.append({'type': 'inline', 'name': f'inline_{i}', 'code': code})
            srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.I)
            for src in srcs[:15]:
                js_url = urljoin(url, src)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as jr:
                        if jr.status == 200:
                            scripts.append({'type': 'external', 'name': src.split('/')[-1][:30],
                                            'code': await jr.text(), 'url': js_url})
                except Exception:
                    pass
    except Exception:
        pass
    return scripts

def _detect_obfuscation(code):
    indicators = []
    for pattern, desc in OBFUSCATION_INDICATORS:
        matches = re.findall(pattern, code)
        if len(matches) > 3:
            indicators.append({'type': desc, 'count': len(matches)})
    entropy = len(set(code)) / max(len(code), 1) * 100
    if entropy < 15:
        indicators.append({'type': 'Low entropy (packed)', 'count': round(entropy, 1)})
    avg_line = sum(len(l) for l in code.split('\n')) / max(len(code.split('\n')), 1)
    if avg_line > 500:
        indicators.append({'type': 'Very long lines (minified/packed)', 'count': round(avg_line)})
    return indicators

def _extract_hidden_data(code):
    found = []
    base64_strings = re.findall(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']', code)
    for b64 in base64_strings[:10]:
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='replace')
            if any(c.isalpha() for c in decoded) and len(decoded) > 5:
                if any(k in decoded.lower() for k in ['http', 'api', 'key', 'secret', 'password', 'token',
                                                       'admin', 'config', 'database', 'mysql', 'redis']):
                    found.append({'type': 'Base64 Secret', 'decoded': decoded[:60], 'severity': 'High'})
                else:
                    found.append({'type': 'Base64 String', 'decoded': decoded[:40], 'severity': 'Low'})
        except Exception:
            pass

    hex_strings = re.findall(r'(?:\\x[0-9a-fA-F]{2}){5,}', code)
    for h in hex_strings[:5]:
        try:
            decoded = bytes.fromhex(h.replace('\\x', '')).decode('utf-8', errors='replace')
            if len(decoded) > 3:
                found.append({'type': 'Hex String', 'decoded': decoded[:40], 'severity': 'Medium'})
        except Exception:
            pass

    charcode = re.findall(r'String\.fromCharCode\(([0-9,\s]+)\)', code)
    for cc in charcode[:5]:
        try:
            chars = [int(c.strip()) for c in cc.split(',') if c.strip().isdigit()]
            decoded = ''.join(chr(c) for c in chars if 0 < c < 128)
            if len(decoded) > 3:
                found.append({'type': 'CharCode String', 'decoded': decoded[:40], 'severity': 'Medium'})
        except Exception:
            pass

    api_urls = re.findall(r'["\']((https?://[^"\']+/api[^"\']*|/api/[^"\']+))["\']', code)
    for url_match in api_urls:
        found.append({'type': 'Hidden API URL', 'decoded': url_match[0][:60], 'severity': 'Medium'})

    return found

async def scan_js_deobfuscate(session, url):
    console.print(f"\n[bold cyan]--- JavaScript Deobfuscator ---[/bold cyan]")
    console.print(f"  [cyan]Extracting JS files...[/cyan]")
    scripts = await _extract_js_files(session, url)
    console.print(f"  [dim]{len(scripts)} JS blocks found[/dim]")

    all_findings = []
    for script in scripts:
        indicators = _detect_obfuscation(script['code'])
        if indicators:
            all_findings.append({
                'type': f'Obfuscated JS: {script["name"]}',
                'severity': 'Medium',
                'indicators': [i['type'] for i in indicators],
            })
            console.print(f"  [yellow]⚠ Obfuscated: {script['name']} ({', '.join(i['type'] for i in indicators[:3])})[/yellow]")

        hidden = _extract_hidden_data(script['code'])
        for h in hidden:
            h['source'] = script['name']
            all_findings.append(h)
            if h['severity'] in ('High', 'Critical'):
                console.print(f"  [red]⚠ {h['type']}: {h['decoded'][:30]}[/red]")

    if not all_findings:
        console.print(f"\n  [green]✓ No obfuscated secrets found[/green]")
    return {'scripts': len(scripts), 'findings': all_findings}
