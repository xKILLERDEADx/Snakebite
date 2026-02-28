"""Content Discovery Engine — smart recursive directory/file brute force."""

import aiohttp
import asyncio
from urllib.parse import urljoin
from modules.core import console

WORDLIST = [
    'admin', 'login', 'dashboard', 'panel', 'config', 'configuration',
    'backup', 'backups', 'old', 'new', 'test', 'testing', 'dev',
    'development', 'staging', 'stage', 'prod', 'production',
    'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'swagger',
    'docs', 'doc', 'documentation', 'help', 'support', 'faq',
    'upload', 'uploads', 'files', 'file', 'images', 'img', 'media',
    'static', 'assets', 'css', 'js', 'javascript', 'scripts',
    'include', 'includes', 'inc', 'lib', 'libs', 'vendor', 'node_modules',
    'wp-admin', 'wp-content', 'wp-includes', 'wp-login', 'wordpress',
    'cgi-bin', 'cgi', 'bin', 'scripts', 'exec',
    'tmp', 'temp', 'cache', 'log', 'logs', 'debug',
    'data', 'database', 'db', 'sql', 'mysql', 'phpmyadmin',
    'server-status', 'server-info', 'status', 'info', 'health',
    'internal', 'private', 'secret', 'hidden', 'secure',
    'portal', 'intranet', 'extranet', 'webmail', 'mail',
    'user', 'users', 'account', 'accounts', 'profile', 'profiles',
    'register', 'signup', 'signin', 'auth', 'authenticate',
    'password', 'passwd', 'reset', 'forgot', 'recover',
    'search', 'find', 'query', 'results',
    'download', 'downloads', 'export', 'import',
    'report', 'reports', 'analytics', 'stats', 'statistics',
    'manage', 'manager', 'console', 'terminal', 'shell',
    'install', 'setup', 'wizard', 'update', 'upgrade',
    'error', 'errors', '404', '500', 'forbidden', 'denied',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'humans.txt',
    'favicon.ico', '.well-known', 'security.txt',
]

EXTENSIONS = ['', '/', '.php', '.html', '.asp', '.aspx', '.jsp',
              '.json', '.xml', '.txt', '.bak', '.old', '.zip']


async def _probe_path(session, url, path, semaphore):
    """Probe a single path."""
    async with semaphore:
        test_url = urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if len(body) > 50:
                        return {
                            'url': test_url,
                            'path': path,
                            'status': resp.status,
                            'size': len(body),
                            'content_type': resp.headers.get('Content-Type', '')[:40],
                        }
                elif resp.status in [301, 302]:
                    return {
                        'url': test_url,
                        'path': path,
                        'status': resp.status,
                        'redirect': resp.headers.get('Location', '')[:80],
                        'size': 0,
                    }
                elif resp.status == 403:
                    return {
                        'url': test_url,
                        'path': path,
                        'status': resp.status,
                        'size': 0,
                        'forbidden': True,
                    }
        except Exception:
            pass
    return None


async def scan_content_discovery(session, url):
    """Smart content/directory discovery."""
    console.print(f"\n[bold cyan]--- Content Discovery Engine ---[/bold cyan]")

    paths = []
    for word in WORDLIST:
        for ext in EXTENSIONS[:4]:
            paths.append(f'/{word}{ext}')

    console.print(f"  [cyan]Brute forcing {len(paths)} paths...[/cyan]")

    semaphore = asyncio.Semaphore(30)
    tasks = [_probe_path(session, url, path, semaphore) for path in paths]
    results_raw = await asyncio.gather(*tasks)

    found = [r for r in results_raw if r]
    accessible = [r for r in found if r['status'] == 200]
    redirects = [r for r in found if r['status'] in (301, 302)]
    forbidden = [r for r in found if r.get('forbidden')]

    if accessible:
        console.print(f"\n  [bold green]{len(accessible)} accessible paths:[/bold green]")
        for r in sorted(accessible, key=lambda x: x['size'], reverse=True)[:20]:
            console.print(f"  [green]{r['path']} ({r['size']}B) [{r.get('content_type', '')[:20]}][/green]")

    if forbidden:
        console.print(f"\n  [yellow]{len(forbidden)} forbidden (potential targets):[/yellow]")
        for r in forbidden[:10]:
            console.print(f"  [yellow]{r['path']} (403)[/yellow]")

    if redirects:
        console.print(f"\n  [dim]{len(redirects)} redirects[/dim]")

    console.print(f"\n  [bold]Total: {len(found)} paths found ({len(accessible)} open, {len(forbidden)} forbidden)[/bold]")

    return {
        'total': len(found),
        'accessible': accessible,
        'forbidden': [{'path': r['path']} for r in forbidden],
        'redirects': len(redirects),
    }
