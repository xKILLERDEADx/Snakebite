"""Backdoor Finder — deep scan for hidden backdoors in web applications."""

import aiohttp
import asyncio
import re
import hashlib
from urllib.parse import urljoin
from modules.core import console

BACKDOOR_PATHS = [
    '.htaccess', '.htpasswd', 'wp-config.php.bak', 'wp-config.php.old',
    'wp-config.php.save', 'wp-config.php~', 'wp-config.txt',
    '.wp-config.php.swp', 'wp-config.php.orig', 'db.php', 'database.php',
    'wp-load.php', 'wp-blog-header.php', 'wp-settings.php',
    'wp-includes/version.php', 'wp-includes/class-wp-post.php',
    'wp-content/debug.log', 'debug.log', 'error_log', 'error.log',
    '.git/HEAD', '.git/config', '.svn/entries', '.env', '.env.bak',
    'robots.txt', 'sitemap.xml', 'readme.html', 'license.txt',
    'xmlrpc.php', 'wp-cron.php', 'wp-trackback.php',
]

HTACCESS_MALWARE = [
    (r'RewriteRule\s+.*\.(php|asp|jsp)\s+', 'Suspicious rewrite to script'),
    (r'Header\s+set\s+.*base64', 'Base64 in header'),
    (r'ErrorDocument\s+\d+\s+.*\.php', 'Error page pointing to PHP'),
    (r'php_value\s+auto_prepend_file', 'Auto prepend file (backdoor loader)'),
    (r'php_value\s+auto_append_file', 'Auto append file (backdoor injector)'),
    (r'SetHandler\s+.*php', 'Non-PHP extension handled as PHP'),
    (r'AddType\s+.*php.*\.(jpg|png|gif|ico)', 'Image extension as PHP'),
    (r'RewriteCond.*HTTP_REFERER.*google|yahoo|bing', 'SEO spam redirect'),
]

INJECTED_CODE_PATTERNS = [
    (r'<script[^>]*src=["\']https?://[^/]*(?:evil|hack|malw|trojan)[^"\']*["\']', 'Malicious external script'),
    (r'document\.write\s*\(\s*unescape\s*\(', 'Obfuscated document.write'),
    (r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e', 'Dean Edwards packer (often malware)'),
    (r'<iframe\s+[^>]*style\s*=\s*["\'][^"\']*display\s*:\s*none', 'Hidden iframe'),
    (r'<iframe\s+[^>]*width\s*=\s*["\']?[01]["\']?\s+height\s*=\s*["\']?[01]', 'Zero-size iframe'),
    (r'window\.location\s*=\s*["\']https?://(?!.*(?:' + re.escape('example') + r'))', 'Suspicious redirect'),
    (r'String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){10,}', 'Long CharCode (likely malware)'),
    (r'var\s+\w+\s*=\s*\[\s*"\\x', 'Hex-encoded variable array'),
]

WP_CORE_CRITICAL = [
    'wp-includes/version.php',
    'wp-includes/class-wp.php',
    'wp-includes/pluggable.php',
    'wp-includes/functions.php',
    'wp-login.php',
    'index.php',
    'wp-blog-header.php',
]


async def _scan_backdoor_paths(session, url):
    findings = []
    for path in BACKDOOR_PATHS:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    ct = resp.headers.get('Content-Type', '')

                    if path == '.htaccess':
                        for pattern, desc in HTACCESS_MALWARE:
                            if re.search(pattern, body, re.I):
                                findings.append({'type': f'.htaccess Backdoor: {desc}', 'severity': 'Critical'})

                    elif path.endswith(('.bak', '.old', '.save', '~', '.swp', '.orig', '.txt')):
                        if 'DB_PASSWORD' in body or 'DB_NAME' in body:
                            findings.append({'type': f'Config Backup Exposed: {path}', 'severity': 'Critical',
                                             'detail': 'Database credentials may be visible'})

                    elif path == '.env' or path == '.env.bak':
                        if any(k in body for k in ['PASSWORD', 'SECRET', 'KEY', 'DB_']):
                            findings.append({'type': f'Env File Exposed: {path}', 'severity': 'Critical'})

                    elif path == 'wp-content/debug.log' or 'log' in path:
                        if len(body) > 100:
                            findings.append({'type': f'Debug Log Exposed: {path}', 'severity': 'High',
                                             'size': len(body)})

                    elif path.startswith('.git') or path.startswith('.svn'):
                        findings.append({'type': f'Source Control Exposed: {path}', 'severity': 'Critical'})
        except Exception:
            pass
    return findings


async def _scan_injected_code(session, url):
    findings = []
    pages = [url, urljoin(url, '/?p=1'), urljoin(url, '/wp-login.php'),
             urljoin(url, '/wp-admin/')]

    for page in pages:
        try:
            async with session.get(page, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    for pattern, desc in INJECTED_CODE_PATTERNS:
                        if re.search(pattern, body, re.I):
                            findings.append({
                                'type': f'Injected Code: {desc}',
                                'url': page,
                                'severity': 'Critical',
                            })

                    external_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.I)
                    for src in external_scripts:
                        suspicious_tlds = ['.xyz', '.tk', '.top', '.pw', '.cc', '.gq', '.ml', '.cf']
                        if any(src.endswith(tld) or f'{tld}/' in src for tld in suspicious_tlds):
                            findings.append({
                                'type': f'Suspicious External Script: {src[:60]}',
                                'severity': 'High',
                            })
        except Exception:
            pass
    return findings


async def _check_wp_core_integrity(session, url):
    findings = []
    for core_file in WP_CORE_CRITICAL:
        try:
            async with session.get(urljoin(url, core_file), timeout=aiohttp.ClientTimeout(total=6),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    for pattern, desc in INJECTED_CODE_PATTERNS[:4]:
                        if re.search(pattern, body, re.I):
                            findings.append({
                                'type': f'WP Core Modified: {core_file} ({desc})',
                                'severity': 'Critical',
                                'hash': hashlib.md5(body.encode()).hexdigest()[:16],
                            })
                    if 'eval(' in body and 'base64_decode' in body:
                        findings.append({
                            'type': f'Backdoor in Core: {core_file}',
                            'severity': 'Critical',
                        })
        except Exception:
            pass
    return findings


async def scan_backdoor_finder(session, url):
    console.print(f"\n[bold cyan]--- Backdoor Finder ---[/bold cyan]")
    all_f = []

    console.print(f"  [cyan]Scanning {len(BACKDOOR_PATHS)} backdoor paths...[/cyan]")
    all_f.extend(await _scan_backdoor_paths(session, url))

    console.print(f"  [cyan]Checking for injected code ({len(INJECTED_CODE_PATTERNS)} patterns)...[/cyan]")
    all_f.extend(await _scan_injected_code(session, url))

    console.print(f"  [cyan]WordPress core integrity check...[/cyan]")
    all_f.extend(await _check_wp_core_integrity(session, url))

    for f in all_f:
        color = 'red' if f['severity'] == 'Critical' else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not all_f:
        console.print(f"\n  [green]✓ No backdoors detected[/green]")
    return {'findings': all_f}
