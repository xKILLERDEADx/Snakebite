"""Defacement Monitor — detect website defacement, content integrity, visual changes."""

import aiohttp, asyncio, re, hashlib
from urllib.parse import urljoin
from modules.core import console

DEFACEMENT_SIGS = [
    'hacked by', 'defaced by', 'owned by', 'pwned by', 'greetz',
    '0wn3d', 'h4ck3d', 'rooted by', 'shell uploaded', 'cyber army',
    'we are legion', 'anonymous', 'team poison', 'script kiddie',
    'zone-h', 'mirror-h', 'exploit-db', 'your site has been',
    'this website is hacked', 'all your data belongs to us',
]

DEFACE_INDICATORS = [
    (r'<title>[^<]*(?:hacked|defaced|owned|pwned)[^<]*</title>', 'Defaced title tag'),
    (r'<body[^>]*background\s*=\s*["\'][^"\']*(?:skull|hack|dark)', 'Hacker background image'),
    (r'<marquee[^>]*>[^<]*(?:hack|deface|own)', 'Marquee defacement text'),
    (r'<audio[^>]*src\s*=\s*["\'][^"\']*(?:hack|anon)', 'Hacker audio playing'),
    (r'<h1[^>]*>[^<]*(?:hacked|defaced|greetz)', 'Defacement heading'),
]

INTEGRITY_PAGES = ['/', '/index.php', '/index.html', '/wp-login.php', '/wp-admin/']


async def _check_defacement(session, url):
    findings = []
    for page in INTEGRITY_PAGES:
        try:
            async with session.get(urljoin(url, page), timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    body_lower = body.lower()
                    for sig in DEFACEMENT_SIGS:
                        if sig in body_lower:
                            findings.append({'type': f'Defacement: "{sig}" on {page}', 'severity': 'Critical'})
                            break
                    for pattern, desc in DEFACE_INDICATORS:
                        if re.search(pattern, body, re.I):
                            findings.append({'type': f'{desc} on {page}', 'severity': 'Critical'})
                            break

                    if '<title>' in body:
                        title = re.search(r'<title>([^<]+)</title>', body, re.I)
                        if title:
                            t = title.group(1).lower()
                            if any(k in t for k in ['hacked', 'defaced', 'pwned', 'owned', '404', 'error']):
                                findings.append({'type': f'Suspicious Title: {title.group(1)[:40]}', 'severity': 'High'})
        except Exception:
            pass
    return findings


async def _content_baseline(session, url):
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            body = await resp.text()
            page_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
            word_count = len(body.split())
            has_css = bool(re.search(r'<link[^>]*\.css', body, re.I))
            has_images = bool(re.search(r'<img[^>]*src', body, re.I))

            if word_count < 10 and not has_css and not has_images:
                findings.append({'type': 'Suspicious: Minimal Content (Possible Wipe)', 'severity': 'High',
                                 'detail': f'Only {word_count} words, no CSS/images'})
            findings.append({'type': f'Content Hash: {page_hash}', 'severity': 'Info',
                             'words': word_count, 'hash': page_hash})
    except Exception:
        pass
    return findings


async def _check_status_codes(session, url):
    findings = []
    for page in INTEGRITY_PAGES:
        try:
            async with session.get(urljoin(url, page), timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status in (500, 502, 503):
                    findings.append({'type': f'Server Error on {page}: {resp.status}', 'severity': 'High'})
                elif resp.status == 301 or resp.status == 302:
                    loc = resp.headers.get('Location', '')
                    if loc and not loc.startswith(url[:20]):
                        findings.append({'type': f'Suspicious Redirect from {page}: {loc[:50]}', 'severity': 'High'})
        except Exception:
            pass
    return findings


async def scan_defacement(session, url):
    console.print(f"\n[bold cyan]--- Defacement Monitor ---[/bold cyan]")
    all_f = []
    console.print(f"  [cyan]Checking defacement signatures...[/cyan]")
    all_f.extend(await _check_defacement(session, url))
    console.print(f"  [cyan]Content integrity baseline...[/cyan]")
    all_f.extend(await _content_baseline(session, url))
    console.print(f"  [cyan]Status code analysis...[/cyan]")
    all_f.extend(await _check_status_codes(session, url))
    for f in all_f:
        if f['severity'] != 'Info':
            color = 'red' if f['severity'] == 'Critical' else 'yellow'
            console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not [f for f in all_f if f['severity'] in ('Critical', 'High')]:
        console.print(f"\n  [green]✓ No defacement detected[/green]")
    return {'findings': all_f}
