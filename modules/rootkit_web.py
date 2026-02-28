"""Web Rootkit Detector — .htaccess mods, cron backdoors, config tampering."""

import aiohttp, asyncio, re
from urllib.parse import urljoin
from modules.core import console

ROOTKIT_PATHS = [
    '.htaccess', '.htpasswd', 'cgi-bin/.htaccess',
    'wp-content/.htaccess', 'wp-includes/.htaccess', 'wp-admin/.htaccess',
    'wp-content/uploads/.htaccess', '.user.ini', 'php.ini',
    '.well-known/.htaccess', 'images/.htaccess',
]

ROOTKIT_PATTERNS = [
    (r'php_value\s+auto_prepend_file', 'Auto-prepend backdoor'),
    (r'php_value\s+auto_append_file', 'Auto-append backdoor'),
    (r'AddType\s+application/x-httpd-php\s+\.(jpg|png|gif|ico|txt)', 'Image-as-PHP execution'),
    (r'SetHandler\s+application/x-httpd-php', 'Handler override rootkit'),
    (r'php_flag\s+engine\s+on', 'PHP engine enabled in uploads'),
    (r'<FilesMatch\s+"[^"]*\\\.(?:jpg|png|gif|ico)">\s*SetHandler', 'Image handler rootkit'),
    (r'RewriteRule.*\.(php|phtml|pht|php5|php7)\s+\[', 'Rewrite to PHP shell'),
    (r'ErrorDocument\s+404\s+.*\.php', '404 handler backdoor'),
    (r'Options\s+\+ExecCGI', 'CGI execution enabled'),
    (r'deny\s+from\s+all.*allow\s+from\s+\d+\.\d+\.\d+\.\d+', 'IP whitelist (attacker access)'),
]

CRON_PATHS = ['/wp-cron.php', '/cron.php', '/.cron', '/cron', '/cgi-bin/cron']

WP_MUST_USE = ['/wp-content/mu-plugins/', '/wp-content/mu-plugins/index.php',
               '/wp-content/mu-plugins/health-check.php']

USERINI_PATTERNS = [
    (r'auto_prepend_file\s*=', 'auto_prepend_file in .user.ini'),
    (r'auto_append_file\s*=', 'auto_append_file in .user.ini'),
    (r'allow_url_include\s*=\s*On', 'Remote include enabled'),
    (r'disable_functions\s*=\s*$', 'Disabled functions cleared'),
]


async def _scan_rootkit_files(session, url):
    findings = []
    for path in ROOTKIT_PATHS:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if path.endswith('.htaccess'):
                        for pattern, desc in ROOTKIT_PATTERNS:
                            if re.search(pattern, body, re.I):
                                findings.append({'type': f'Rootkit in {path}: {desc}', 'severity': 'Critical'})
                    elif path in ('.user.ini', 'php.ini'):
                        for pattern, desc in USERINI_PATTERNS:
                            if re.search(pattern, body, re.I):
                                findings.append({'type': f'Config Rootkit: {desc}', 'severity': 'Critical'})
        except Exception:
            pass
    return findings


async def _check_mu_plugins(session, url):
    findings = []
    for path in WP_MUST_USE:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if 'eval' in body or 'base64_decode' in body or 'system(' in body:
                        findings.append({'type': f'Backdoor in MU-Plugin: {path}', 'severity': 'Critical'})
                    elif '.php' in body:
                        findings.append({'type': f'MU-Plugins Directory Listing: {path}', 'severity': 'High'})
        except Exception:
            pass
    return findings


async def _check_cron_abuse(session, url):
    findings = []
    for path in CRON_PATHS:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200 and 'cron' in (await resp.text()).lower():
                    findings.append({'type': f'Cron Endpoint Accessible: {path}', 'severity': 'Medium'})
        except Exception:
            pass
    return findings


async def scan_rootkit_web(session, url):
    console.print(f"\n[bold cyan]--- Web Rootkit Detector ---[/bold cyan]")
    all_f = []
    console.print(f"  [cyan]Scanning rootkit files ({len(ROOTKIT_PATHS)})...[/cyan]")
    all_f.extend(await _scan_rootkit_files(session, url))
    console.print(f"  [cyan]Checking MU-Plugins...[/cyan]")
    all_f.extend(await _check_mu_plugins(session, url))
    console.print(f"  [cyan]Checking cron abuse...[/cyan]")
    all_f.extend(await _check_cron_abuse(session, url))
    for f in all_f:
        color = 'red' if f['severity'] == 'Critical' else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not all_f:
        console.print(f"\n  [green]✓ No rootkits detected[/green]")
    return {'findings': all_f}
