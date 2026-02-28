"""Session Fixation Engine — pre-session, session adoption, cross-subdomain attacks."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin, urlparse
from modules.core import console

LOGIN_PATHS = ['/login', '/signin', '/auth', '/account/login', '/user/login', '/wp-login.php',
               '/admin/login', '/api/auth/login', '/api/login', '/member/login']
SENSITIVE_COOKIES = ['sessionid', 'session', 'sid', 'phpsessid', 'jsessionid',
                     'asp.net_sessionid', 'connect.sid', 'token', 'auth', 'jwt']


async def _check_session_fixation(session, url):
    findings = []
    for path in LOGIN_PATHS:
        login_url = urljoin(url, path)
        try:
            async with session.get(login_url, timeout=aiohttp.ClientTimeout(total=8), ssl=False,
                                   allow_redirects=False) as resp:
                if resp.status in (200, 302):
                    cookies = resp.headers.getall('Set-Cookie', [])
                    for cookie_header in cookies:
                        cookie_name = cookie_header.split('=')[0].strip().lower()
                        if any(s in cookie_name for s in SENSITIVE_COOKIES):
                            flags = cookie_header.lower()
                            issues = []
                            if 'httponly' not in flags:
                                issues.append('No HttpOnly')
                            if 'secure' not in flags:
                                issues.append('No Secure')
                            if 'samesite' not in flags:
                                issues.append('No SameSite')
                            if issues:
                                findings.append({
                                    'type': f'Session Cookie Weak: {cookie_name}',
                                    'path': path, 'issues': issues,
                                    'severity': 'High',
                                })
        except Exception:
            pass
    return findings


async def _test_session_adoption(session, url):
    findings = []
    fixed_session = 'SNAKEBITE_FIXED_SESSION_TEST_12345'
    for path in LOGIN_PATHS[:5]:
        login_url = urljoin(url, path)
        for cookie_name in ['PHPSESSID', 'sessionid', 'session', 'sid', 'JSESSIONID']:
            try:
                cookies = {cookie_name: fixed_session}
                async with session.get(login_url, cookies=cookies,
                                       timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                    body = await resp.text()
                    resp_cookies = resp.headers.getall('Set-Cookie', [])
                    session_regenerated = any(cookie_name.lower() in c.lower() and
                                             fixed_session not in c for c in resp_cookies)
                    if not session_regenerated and resp.status == 200:
                        if fixed_session not in str(resp_cookies):
                            findings.append({
                                'type': f'Session Adoption: {cookie_name}',
                                'path': path, 'severity': 'High',
                                'detail': 'Server accepted attacker-supplied session ID',
                            })
            except Exception:
                pass
    return findings


async def _test_csrf_on_login(session, url):
    findings = []
    for path in LOGIN_PATHS[:5]:
        login_url = urljoin(url, path)
        try:
            async with session.get(login_url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    has_csrf = bool(re.search(r'name=["\']?(?:csrf|_token|csrfmiddleware|__RequestVerification|nonce)["\']?',
                                             body, re.I))
                    if not has_csrf and '<form' in body.lower():
                        findings.append({
                            'type': f'Login Without CSRF Token',
                            'path': path, 'severity': 'High',
                            'detail': 'Login form has no CSRF protection',
                        })
        except Exception:
            pass
    return findings


async def _test_session_after_logout(session, url):
    findings = []
    logout_paths = ['/logout', '/signout', '/api/logout', '/auth/logout', '/user/logout']
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
            pre_cookies = resp.cookies
    except Exception:
        return findings

    for path in logout_paths:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status in (200, 302):
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp2:
                            if resp2.status == 200:
                                post_cookies = resp2.cookies
                                for name in pre_cookies:
                                    if name in post_cookies and str(pre_cookies[name]) == str(post_cookies[name]):
                                        findings.append({
                                            'type': 'Session Not Invalidated After Logout',
                                            'cookie': name, 'severity': 'High',
                                        })
                    except Exception:
                        pass
        except Exception:
            pass
    return findings


async def scan_session_fixation(session, url):
    console.print(f"\n[bold cyan]--- Session Fixation Engine ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Checking session cookie security...[/cyan]")
    cookies = await _check_session_fixation(session, url)
    all_findings.extend(cookies)

    console.print(f"  [cyan]Testing session adoption...[/cyan]")
    adopt = await _test_session_adoption(session, url)
    all_findings.extend(adopt)

    console.print(f"  [cyan]Testing CSRF on login forms...[/cyan]")
    csrf = await _test_csrf_on_login(session, url)
    all_findings.extend(csrf)

    console.print(f"  [cyan]Testing session invalidation after logout...[/cyan]")
    logout = await _test_session_after_logout(session, url)
    all_findings.extend(logout)

    for f in all_findings:
        console.print(f"  [bold red]⚠ {f['type']}[/bold red]")
    if not all_findings:
        console.print(f"\n  [green]✓ Session management looks secure[/green]")
    return {'findings': all_findings}
