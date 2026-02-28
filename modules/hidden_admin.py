"""Hidden Admin Finder — find rogue users, hidden accounts, privilege escalation."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin
from modules.core import console

ADMIN_PATHS = ['/admin', '/admin/', '/administrator', '/wp-admin/', '/wp-admin/users.php',
               '/admin/users', '/admin/accounts', '/dashboard', '/cpanel', '/phpmyadmin/',
               '/adminer.php', '/manager/', '/manage/', '/panel/', '/control/',
               '/backend/', '/admin-panel/', '/siteadmin/', '/webadmin/']

WP_USER_ENUM = [
    '/?author=1', '/?author=2', '/?author=3', '/?author=4', '/?author=5',
    '/?author=6', '/?author=7', '/?author=8', '/?author=9', '/?author=10',
]

WP_REST_USERS = ['/wp-json/wp/v2/users', '/wp-json/wp/v2/users?per_page=100',
                 '/?rest_route=/wp/v2/users']

SUSPICIOUS_USERNAMES = ['admin', 'administrator', 'root', 'test', 'user', 'manager',
                        'guest', 'support', 'info', 'webmaster', 'backup',
                        'temp', 'tmp', 'demo', 'default', 'system']


async def _enum_wp_users(session, url):
    findings = []
    users = []

    for endpoint in WP_REST_USERS:
        try:
            async with session.get(urljoin(url, endpoint), timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        for user in data:
                            u = {'id': user.get('id'), 'name': user.get('name', ''),
                                 'slug': user.get('slug', ''), 'description': user.get('description', '')}
                            users.append(u)
                            if u['slug'].lower() in SUSPICIOUS_USERNAMES:
                                findings.append({
                                    'type': f'Default/Suspicious User: {u["slug"]} (ID: {u["id"]})',
                                    'severity': 'High',
                                })
                        if users:
                            findings.append({
                                'type': f'WP User Enum via REST ({len(users)} users)',
                                'severity': 'Medium',
                                'users': [u['slug'] for u in users],
                            })
                        break
        except Exception:
            pass

    if not users:
        for author_url in WP_USER_ENUM:
            try:
                async with session.get(urljoin(url, author_url), timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False, allow_redirects=True) as resp:
                    final_url = str(resp.url)
                    if '/author/' in final_url:
                        username = final_url.split('/author/')[-1].strip('/')
                        if username and username not in [u['slug'] for u in users]:
                            users.append({'id': author_url.split('=')[1], 'slug': username})
                            if username.lower() in SUSPICIOUS_USERNAMES:
                                findings.append({
                                    'type': f'Default/Suspicious Author: {username}',
                                    'severity': 'High',
                                })
            except Exception:
                pass
        if users:
            findings.append({
                'type': f'User Enum via Author IDs ({len(users)} users)',
                'severity': 'Medium',
            })

    return findings, users


async def _check_admin_panels(session, url):
    findings = []
    for path in ADMIN_PATHS:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if 'login' in body.lower() or 'password' in body.lower():
                        findings.append({
                            'type': f'Admin Panel Accessible: {path}',
                            'severity': 'High',
                        })
                elif resp.status == 302:
                    loc = resp.headers.get('Location', '')
                    if 'login' in loc.lower():
                        findings.append({
                            'type': f'Admin Panel Found (Login Required): {path}',
                            'severity': 'Medium',
                        })
        except Exception:
            pass
    return findings


async def _check_registration(session, url):
    findings = []
    reg_paths = ['/wp-login.php?action=register', '/register', '/signup',
                 '/wp-register.php', '/user/register']
    for path in reg_paths:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=6),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if 'register' in body.lower() and ('email' in body.lower() or 'username' in body.lower()):
                        findings.append({
                            'type': f'Open Registration: {path}',
                            'severity': 'High',
                            'detail': 'Attackers can create accounts',
                        })
        except Exception:
            pass
    return findings


async def _check_xmlrpc_users(session, url):
    findings = []
    try:
        xmlrpc_url = urljoin(url, '/xmlrpc.php')
        payload = '''<?xml version="1.0"?>
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value>admin</value></param><param><value>test</value></param></params>
</methodCall>'''
        async with session.post(xmlrpc_url, data=payload,
                                headers={'Content-Type': 'text/xml'},
                                timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            body = await resp.text()
            if 'Incorrect username' in body:
                findings.append({'type': 'XML-RPC User Enumeration Active', 'severity': 'High',
                                 'detail': 'Can brute-force usernames via XML-RPC'})
            elif 'parse error' not in body.lower() and resp.status == 200:
                findings.append({'type': 'XML-RPC Enabled', 'severity': 'Medium'})
    except Exception:
        pass
    return findings


async def scan_hidden_admin(session, url):
    console.print(f"\n[bold cyan]--- Hidden Admin Finder ---[/bold cyan]")
    all_f = []

    console.print(f"  [cyan]Enumerating WordPress users...[/cyan]")
    user_findings, users = await _enum_wp_users(session, url)
    all_f.extend(user_findings)

    console.print(f"  [cyan]Scanning admin panels ({len(ADMIN_PATHS)})...[/cyan]")
    all_f.extend(await _check_admin_panels(session, url))

    console.print(f"  [cyan]Checking open registration...[/cyan]")
    all_f.extend(await _check_registration(session, url))

    console.print(f"  [cyan]Testing XML-RPC...[/cyan]")
    all_f.extend(await _check_xmlrpc_users(session, url))

    for f in all_f:
        color = 'red' if f['severity'] in ('Critical', 'High') else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not all_f:
        console.print(f"\n  [green]✓ No hidden admin issues[/green]")
    return {'users': users, 'findings': all_f}
