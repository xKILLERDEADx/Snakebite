"""C2 Beacon Detector — detect Command & Control communication, beaconing, exfil."""

import aiohttp, asyncio, re, time
from urllib.parse import urljoin, urlparse
from modules.core import console

C2_INDICATORS = [
    (r'setInterval\s*\(\s*function.*?(?:XMLHttpRequest|fetch|ajax).*?\d{3,}', 'JS Beaconing (setInterval + HTTP)'),
    (r'WebSocket.*?ws[s]?://(?!.*(?:googleapis|cloudflare|pusher|socket\.io))', 'Suspicious WebSocket C2'),
    (r'navigator\.sendBeacon\s*\(\s*["\']https?://(?!.*(?:google|facebook|analytics))', 'sendBeacon exfil'),
    (r'new\s+Image\(\)\.src\s*=.*?\+.*?(?:document\.cookie|localStorage)', 'Image beacon data exfil'),
    (r'fetch\s*\(\s*["\']https?://[^"\']+["\'].*?(?:cookie|token|session|password)', 'Fetch credential exfil'),
    (r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']https?://(?!.*{domain})', 'AJAX to external C2'),
]

EXFIL_PATTERNS = [
    (r'document\.cookie', 'Cookie access (potential exfil)'),
    (r'localStorage\.getItem', 'LocalStorage access'),
    (r'sessionStorage\.getItem', 'SessionStorage access'),
    (r'navigator\.credentials', 'Credential API access'),
    (r'document\.querySelectorAll\s*\(\s*["\']input\[type.*password', 'Password field scraping'),
    (r'new\s+FormData\s*\(\s*document\.forms', 'Full form data capture'),
]

DNS_EXFIL_DOMAINS = ['.oast.pro', '.interact.sh', '.burpcollaborator.net',
                     '.canarytokens.com', '.requestbin.net', '.pipedream.net']


async def _analyze_js_beaconing(session, url):
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            domain = urlparse(url).hostname

            for pattern, desc in C2_INDICATORS:
                p = pattern.replace('{domain}', re.escape(domain))
                if re.search(p, body, re.I | re.S):
                    findings.append({'type': f'C2 Signal: {desc}', 'severity': 'Critical'})

            for pattern, desc in EXFIL_PATTERNS:
                matches = re.findall(pattern, body, re.I)
                if matches:
                    findings.append({'type': f'Data Access: {desc} ({len(matches)}x)', 'severity': 'High'})

            scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.I)
            for src in scripts[:10]:
                js_url = urljoin(url, src)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False) as jr:
                        if jr.status == 200:
                            js = await jr.text()
                            for pattern, desc in C2_INDICATORS:
                                p = pattern.replace('{domain}', re.escape(domain))
                                if re.search(p, js, re.I | re.S):
                                    findings.append({'type': f'C2 in JS ({src.split("/")[-1][:20]}): {desc}',
                                                     'severity': 'Critical'})
                except Exception:
                    pass
    except Exception:
        pass
    return findings


async def _check_timing_beacons(session, url):
    findings = []
    timings = []
    for _ in range(5):
        try:
            start = time.time()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                body = await resp.text()
                elapsed = time.time() - start
                timings.append({'time': elapsed, 'size': len(body)})
        except Exception:
            pass
        await asyncio.sleep(0.5)

    if len(timings) >= 3:
        sizes = [t['size'] for t in timings]
        if len(set(sizes)) > 1:
            min_s, max_s = min(sizes), max(sizes)
            if max_s > min_s * 1.3:
                findings.append({
                    'type': f'Dynamic Content Variance ({min_s}-{max_s} bytes)',
                    'severity': 'Medium',
                    'detail': 'Page content changes between requests (possible C2 payload injection)',
                })
    return findings


async def _check_dns_exfil_refs(session, url):
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            body = await resp.text()
            for domain in DNS_EXFIL_DOMAINS:
                if domain in body:
                    findings.append({'type': f'DNS Exfil Tool Reference: {domain}', 'severity': 'Critical'})
    except Exception:
        pass
    return findings


async def scan_c2_detect(session, url):
    console.print(f"\n[bold cyan]--- C2 Beacon Detector ---[/bold cyan]")
    all_f = []
    console.print(f"  [cyan]Analyzing JS for C2 patterns...[/cyan]")
    all_f.extend(await _analyze_js_beaconing(session, url))
    console.print(f"  [cyan]Timing beacon analysis (5 samples)...[/cyan]")
    all_f.extend(await _check_timing_beacons(session, url))
    console.print(f"  [cyan]DNS exfil tool references...[/cyan]")
    all_f.extend(await _check_dns_exfil_refs(session, url))
    for f in all_f:
        color = 'red' if f['severity'] == 'Critical' else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not all_f:
        console.print(f"\n  [green]✓ No C2 beaconing detected[/green]")
    return {'findings': all_f}
