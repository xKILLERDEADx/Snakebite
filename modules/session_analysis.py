"""Session Token Analysis — analyze real cookies for entropy, security flags, predictability."""

import math
import string
import aiohttp
from urllib.parse import urlparse
from collections import Counter
from modules.core import console


def calculate_entropy(token):
    """Calculate Shannon entropy of a string."""
    if not token:
        return 0.0
    counter = Counter(token)
    length = len(token)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return round(entropy, 2)


def analyze_charset(token):
    """Analyze the character set used in a token."""
    has_lower = any(c in string.ascii_lowercase for c in token)
    has_upper = any(c in string.ascii_uppercase for c in token)
    has_digit = any(c in string.digits for c in token)
    has_special = any(c not in string.ascii_letters + string.digits for c in token)
    has_hex = all(c in string.hexdigits for c in token)

    charset = []
    if has_lower: charset.append('lowercase')
    if has_upper: charset.append('uppercase')
    if has_digit: charset.append('digits')
    if has_special: charset.append('special')

    return {
        'charset': charset,
        'is_hex': has_hex and len(token) > 10,
        'is_base64': all(c in string.ascii_letters + string.digits + '+/=' for c in token) and len(token) > 10,
        'is_numeric_only': token.isdigit(),
    }


def assess_security(cookie_name, cookie_value, flags):
    """Assess session cookie security."""
    issues = []

    entropy = calculate_entropy(cookie_value)
    if entropy < 3.0:
        issues.append({'issue': 'LOW_ENTROPY', 'severity': 'High',
                       'detail': f'Entropy {entropy} — token may be predictable'})
    elif entropy < 4.0:
        issues.append({'issue': 'MEDIUM_ENTROPY', 'severity': 'Medium',
                       'detail': f'Entropy {entropy} — consider stronger randomization'})

    if len(cookie_value) < 16:
        issues.append({'issue': 'SHORT_TOKEN', 'severity': 'High',
                       'detail': f'Length {len(cookie_value)} — tokens should be ≥16 chars'})
    elif len(cookie_value) < 32:
        issues.append({'issue': 'MODERATE_LENGTH', 'severity': 'Low',
                       'detail': f'Length {len(cookie_value)} — consider ≥32 chars'})

    charset = analyze_charset(cookie_value)
    if charset['is_numeric_only']:
        issues.append({'issue': 'NUMERIC_ONLY', 'severity': 'Critical',
                       'detail': 'Token is numeric-only — easily brute-forced'})

    if not flags.get('secure'):
        issues.append({'issue': 'MISSING_SECURE', 'severity': 'Medium',
                       'detail': 'Missing Secure flag — sent over unencrypted connections'})

    if not flags.get('httponly'):
        issues.append({'issue': 'MISSING_HTTPONLY', 'severity': 'Medium',
                       'detail': 'Missing HttpOnly — accessible via JavaScript (XSS risk)'})

    if not flags.get('samesite'):
        issues.append({'issue': 'MISSING_SAMESITE', 'severity': 'Low',
                       'detail': 'Missing SameSite — vulnerable to CSRF'})

    if flags.get('path') and flags['path'] != '/':
        issues.append({'issue': 'RESTRICTED_PATH', 'severity': 'Info',
                       'detail': f'Path restricted to {flags["path"]}'})

    return {
        'entropy': entropy,
        'length': len(cookie_value),
        'charset': charset,
        'flags': flags,
        'issues': issues,
        'risk_score': sum(
            {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1}.get(i['severity'], 0)
            for i in issues
        ),
    }


def parse_set_cookie(header_value):
    """Parse a Set-Cookie header into name, value, and flags."""
    parts = header_value.split(';')
    if not parts:
        return None, None, {}

    name_value = parts[0].strip()
    if '=' not in name_value:
        return None, None, {}

    name, value = name_value.split('=', 1)

    flags = {
        'secure': False,
        'httponly': False,
        'samesite': None,
        'path': None,
        'domain': None,
        'expires': None,
        'max_age': None,
    }

    for part in parts[1:]:
        part = part.strip().lower()
        if part == 'secure':
            flags['secure'] = True
        elif part == 'httponly':
            flags['httponly'] = True
        elif part.startswith('samesite='):
            flags['samesite'] = part.split('=', 1)[1]
        elif part.startswith('path='):
            flags['path'] = part.split('=', 1)[1]
        elif part.startswith('domain='):
            flags['domain'] = part.split('=', 1)[1]
        elif part.startswith('expires='):
            flags['expires'] = part.split('=', 1)[1]
        elif part.startswith('max-age='):
            flags['max_age'] = part.split('=', 1)[1]

    return name.strip(), value.strip(), flags


async def scan_session(session, url):
    """Analyze session tokens from real Set-Cookie headers."""
    console.print(f"\n[bold cyan]--- Session Token Analysis ---[/bold cyan]")

    results = {
        'cookies': [],
        'total_risk': 0,
        'recommendations': [],
    }

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                               ssl=False, allow_redirects=True) as resp:
            set_cookies = resp.headers.getall('Set-Cookie', [])

            if not set_cookies:
                console.print(f"  [yellow]No Set-Cookie headers received[/yellow]")
                login_urls = [f"{url}/login", f"{url}/signin", f"{url}/auth",
                              f"{url}/wp-login.php", f"{url}/admin"]
                for login_url in login_urls:
                    try:
                        async with session.get(login_url, timeout=8, ssl=False) as login_resp:
                            extra_cookies = login_resp.headers.getall('Set-Cookie', [])
                            set_cookies.extend(extra_cookies)
                    except Exception:
                        pass

            if not set_cookies:
                console.print(f"  [dim]No session cookies found on target[/dim]")
                return results

            console.print(f"  [green]Found {len(set_cookies)} cookies[/green]\n")

            session_keywords = ['session', 'sess', 'sid', 'token', 'auth', 'jwt',
                                'phpsessid', 'jsessionid', 'asp.net_sessionid',
                                'csrf', 'xsrf', '_token', 'connect.sid']

            for cookie_header in set_cookies:
                name, value, flags = parse_set_cookie(cookie_header)
                if not name or not value:
                    continue

                is_session = any(kw in name.lower() for kw in session_keywords) or len(value) > 20

                analysis = assess_security(name, value, flags)
                analysis['name'] = name
                analysis['value_preview'] = value[:20] + '...' if len(value) > 20 else value
                analysis['is_session'] = is_session
                results['cookies'].append(analysis)
                risk_color = 'red' if analysis['risk_score'] >= 15 else 'yellow' if analysis['risk_score'] >= 8 else 'green'
                console.print(f"  [bold white]{name}[/bold white] {'[Session]' if is_session else ''}")
                console.print(f"    [dim]Value:[/dim] {analysis['value_preview']}")
                console.print(f"    [dim]Length:[/dim] {analysis['length']} | [dim]Entropy:[/dim] {analysis['entropy']} | [{risk_color}]Risk: {analysis['risk_score']}[/{risk_color}]")

                flag_str = []
                if flags['secure']: flag_str.append('[green]Secure ✓[/green]')
                else: flag_str.append('[red]Secure ✗[/red]')
                if flags['httponly']: flag_str.append('[green]HttpOnly ✓[/green]')
                else: flag_str.append('[red]HttpOnly ✗[/red]')
                if flags['samesite']: flag_str.append(f'[green]SameSite={flags["samesite"]} ✓[/green]')
                else: flag_str.append('[red]SameSite ✗[/red]')
                console.print(f"    {' | '.join(flag_str)}")

                if analysis['issues']:
                    for issue in analysis['issues']:
                        sev_color = {'Critical': 'red', 'High': 'red', 'Medium': 'yellow', 'Low': 'blue', 'Info': 'dim'}.get(issue['severity'], 'dim')
                        console.print(f"    [{sev_color}]⚠ [{issue['severity']}] {issue['detail']}[/{sev_color}]")
                console.print()

            results['total_risk'] = sum(c['risk_score'] for c in results['cookies'])

    except Exception as e:
        console.print(f"  [red]Session analysis error: {e}[/red]")

    return results
