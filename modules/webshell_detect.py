"""WebShell Detector — signature-based detection for PHP/ASP/JSP shells."""

import aiohttp
import asyncio
import re
import hashlib
from urllib.parse import urljoin
from modules.core import console

WEBSHELL_SIGNATURES = {
    'c99': ['c99shell', 'c99_buff_prepare', 'c99sh_surl', 'c99ftpbrutecheck'],
    'r57': ['r57shell', 'r57_cmd', 'r57_language', 'r57_charset_langstrg'],
    'b374k': ['b374k', 'b374k_config', 'b374k_password'],
    'WSO': ['WSO_VERSION', 'wso_login', 'FilesMan', 'wso2'],
    'China Chopper': ['eval(base64_decode($_POST', 'array_map("ass"."ert"', 'eval($_POST['],
    'Weevely': ['$kh=', '$kf=', 'eval(gzinflate(base64_decode(', 'base64_decode(str_rot13('],
    'AnonymousFox': ['anonymousfox', 'foxpanel', 'anu11_f0x'],
    'FilesMan': ['FilesMan', 'Safe-mode', 'safe_mode', 'Php File Manager'],
    'Alfa Shell': ['AlfaTeam', 'Alfa-Shell', 'alfa_config', 'alx_skReSet'],
    'p0wny': ['p0wny', 'p0wnyshell', '$cmd ='],
    'Backdoor.PHP.Generic': ['eval(gzuncompress(', 'eval(gzinflate(', 'eval(str_rot13(',
                             'eval(base64_decode(', 'assert(base64_decode(', 'preg_replace("/.*/"'],
}

SHELL_PATHS = [
    'shell.php', 'cmd.php', 'c99.php', 'r57.php', 'b374k.php', 'wso.php',
    'up.php', 'upload.php', 'uploader.php', 'filemanager.php', 'fm.php',
    'config.php.bak', 'wp-config.php.bak', 'web.php', 'test.php',
    'x.php', 'xx.php', 'alfa.php', 'fox.php', 'leaf.php', 'priv.php',
    'adminer.php', 'phpinfo.php', 'info.php', 'phpMyAdmin/index.php',
    'wp-content/uploads/shell.php', 'wp-content/uploads/cmd.php',
    'wp-content/plugins/hello.php', 'wp-includes/class-wp-tmp.php',
    'wp-admin/includes/tmp.php', 'wp-content/themes/tmp/cmd.php',
    'images/shell.php', 'uploads/shell.php', 'tmp/shell.php',
    '.well-known/shell.php', 'cgi-bin/shell.php', '.ssh/shell.php',
]

SUSPICIOUS_PHP_PATTERNS = [
    (r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[', 'Direct eval from user input'),
    (r'system\s*\(\s*\$_(GET|POST|REQUEST)', 'System exec from user input'),
    (r'exec\s*\(\s*\$_(GET|POST|REQUEST)', 'Exec from user input'),
    (r'passthru\s*\(\s*\$_(GET|POST|REQUEST)', 'Passthru from user input'),
    (r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)', 'Shell_exec from user input'),
    (r'preg_replace\s*\(.*/e[\'"]', 'preg_replace /e code execution'),
    (r'assert\s*\(\s*\$_(GET|POST|REQUEST)', 'Assert from user input'),
    (r'create_function\s*\(.*\$_(GET|POST)', 'create_function backdoor'),
    (r'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)', 'Base64 decode user input'),
    (r'\$\w+\s*=\s*str_rot13\s*\(', 'ROT13 obfuscation'),
    (r'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+', 'Chr() string building'),
    (r'file_put_contents\s*\(.+\$_(GET|POST)', 'File write from user input'),
    (r'move_uploaded_file\s*\(.+\$_(FILES)', 'Unrestricted file upload'),
    (r'\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*eval', 'Hex obfuscated eval'),
    (r'gzinflate\s*\(\s*base64_decode', 'Compressed backdoor'),
]


async def _scan_shell_paths(session, url):
    """Scan for known webshell file locations."""
    findings = []
    for path in SHELL_PATHS:
        test_url = urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    ct = resp.headers.get('Content-Type', '')

                    if 'text/html' in ct and len(body) > 50:
                        shell_type = 'Unknown'
                        severity = 'Medium'

                        for name, sigs in WEBSHELL_SIGNATURES.items():
                            for sig in sigs:
                                if sig.lower() in body.lower():
                                    shell_type = name
                                    severity = 'Critical'
                                    break
                            if shell_type != 'Unknown':
                                break

                        shell_indicators = ['<input', 'password', 'execute', 'command',
                                           'upload', 'file manager', 'terminal']
                        indicator_count = sum(1 for i in shell_indicators if i.lower() in body.lower())

                        if indicator_count >= 3 or severity == 'Critical':
                            findings.append({
                                'type': f'WebShell: {shell_type} ({path})',
                                'path': path,
                                'shell_type': shell_type,
                                'severity': severity,
                                'indicators': indicator_count,
                                'size': len(body),
                                'hash': hashlib.md5(body.encode()).hexdigest()[:16],
                            })
                        elif indicator_count >= 1:
                            findings.append({
                                'type': f'Suspicious File: {path}',
                                'path': path,
                                'severity': 'High',
                                'indicators': indicator_count,
                            })
        except Exception:
            pass
    return findings


async def _scan_response_for_shells(session, url):
    """Scan page responses for embedded shell code."""
    findings = []
    pages = [url, urljoin(url, '/wp-login.php'), urljoin(url, '/index.php')]

    for page_url in pages:
        try:
            async with session.get(page_url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    for pattern, desc in SUSPICIOUS_PHP_PATTERNS:
                        if re.search(pattern, body, re.I):
                            findings.append({
                                'type': f'Embedded Backdoor Pattern: {desc}',
                                'url': page_url,
                                'severity': 'Critical',
                            })
        except Exception:
            pass
    return findings


async def _scan_upload_dirs(session, url):
    """Check upload directories for PHP files (should not exist)."""
    findings = []
    upload_dirs = [
        '/wp-content/uploads/', '/uploads/', '/images/', '/media/',
        '/wp-content/uploads/2025/', '/wp-content/uploads/2026/',
    ]
    for udir in upload_dirs:
        try:
            async with session.get(urljoin(url, udir), timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    php_files = re.findall(r'href=["\']([^"\']*\.php)["\']', body, re.I)
                    if php_files:
                        for php_file in php_files[:5]:
                            findings.append({
                                'type': f'PHP in Upload Dir: {udir}{php_file}',
                                'severity': 'Critical',
                                'detail': 'PHP files should NOT be in upload directories',
                            })
        except Exception:
            pass
    return findings


async def scan_webshell_detect(session, url):
    """WebShell detection scanner."""
    console.print(f"\n[bold cyan]--- WebShell Detector ---[/bold cyan]")
    all_f = []

    console.print(f"  [cyan]Scanning {len(SHELL_PATHS)} shell paths...[/cyan]")
    shells = await _scan_shell_paths(session, url)
    all_f.extend(shells)

    console.print(f"  [cyan]Checking responses for backdoor patterns ({len(SUSPICIOUS_PHP_PATTERNS)})...[/cyan]")
    embedded = await _scan_response_for_shells(session, url)
    all_f.extend(embedded)

    console.print(f"  [cyan]Scanning upload directories for PHP...[/cyan]")
    uploads = await _scan_upload_dirs(session, url)
    all_f.extend(uploads)

    for f in all_f:
        color = 'red' if f['severity'] == 'Critical' else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not all_f:
        console.print(f"\n  [green]✓ No webshells detected[/green]")
    return {'findings': all_f}
