"""GitHub Leak Scanner — search GitHub for leaked credentials/keys for a target domain."""

import aiohttp
import asyncio
from urllib.parse import urlparse, quote_plus
from modules.core import console

GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" access_token',
    '"{domain}" private_key',
    '"{domain}" AWS_SECRET',
    '"{domain}" MYSQL_PASSWORD',
    '"{domain}" DATABASE_URL',
    '"{domain}" DB_PASSWORD',
    '"{domain}" smtp_password',
    '"{domain}" client_secret',
    '"{domain}" consumer_key',
    '"{domain}" auth_token',
    '"{domain}" ssh-rsa',
    '"{domain}" BEGIN RSA PRIVATE KEY',
    '"{domain}" .env',
    '"{domain}" wp-config',
    '"{domain}" credentials',
    '"{domain}" connectionString',
    '"{domain}" jdbc:',
    '"{domain}" mongo+srv',
]

FILE_DORKS = [
    'filename:.env "{domain}"',
    'filename:config "{domain}"',
    'filename:credentials "{domain}"',
    'filename:docker-compose "{domain}"',
    'filename:.htpasswd "{domain}"',
    'filename:id_rsa "{domain}"',
    'filename:wp-config.php "{domain}"',
    'filename:settings.py "{domain}"',
    'filename:application.properties "{domain}"',
    'filename:.npmrc "{domain}"',
    'filename:.pypirc "{domain}"',
]

async def search_github(session, domain, token=None):
    """Search GitHub Code Search API for leaked data."""
    results = {
        'domain': domain,
        'leaks': [],
        'total_results': 0,
        'queries_run': 0,
        'search_urls': [],
    }

    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Snakebite-Scanner/2.0',
    }
    if token:
        headers['Authorization'] = f'token {token}'

    all_dorks = [d.format(domain=domain) for d in GITHUB_DORKS + FILE_DORKS]

    for dork in all_dorks:
        search_url_display = f"https://github.com/search?q={quote_plus(dork)}&type=code"
        results['search_urls'].append({'query': dork, 'url': search_url_display})

        if token:
            api_url = f"https://api.github.com/search/code?q={quote_plus(dork)}&per_page=5"
            try:
                async with session.get(api_url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        total = data.get('total_count', 0)
                        results['queries_run'] += 1

                        if total > 0:
                            results['total_results'] += total
                            for item in data.get('items', [])[:3]:
                                leak = {
                                    'query': dork,
                                    'repo': item.get('repository', {}).get('full_name', ''),
                                    'file': item.get('name', ''),
                                    'path': item.get('path', ''),
                                    'url': item.get('html_url', ''),
                                    'score': item.get('score', 0),
                                }
                                results['leaks'].append(leak)

                    elif resp.status == 403:
                        console.print(f"  [yellow]Rate limited — waiting 10s...[/yellow]")
                        await asyncio.sleep(10)
                    elif resp.status == 422:
                        pass

                await asyncio.sleep(2)
            except Exception:
                pass

    return results

async def scan_github_leaks(session, url, github_token=None):
    """Scan GitHub for leaked credentials related to target."""
    console.print(f"\n[bold cyan]--- GitHub Leak Scanner ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    if not github_token:
        console.print(f"  [yellow]No --github-token provided. Generating search URLs only.[/yellow]")
        console.print(f"  [dim]For API results, get a token at: https://github.com/settings/tokens[/dim]\n")

    results = await search_github(session, domain, github_token)

    if github_token and results['leaks']:
        console.print(f"\n  [bold red]🔴 Found {len(results['leaks'])} potential leaks![/bold red]\n")
        for i, leak in enumerate(results['leaks'][:15], 1):
            console.print(f"  [bold white]{i}.[/bold white] [red]{leak['repo']}[/red]")
            console.print(f"     File: {leak['path']}")
            console.print(f"     Query: {leak['query']}")
            console.print(f"     URL: {leak['url']}\n")
    elif github_token:
        console.print(f"\n  [green]✓ No leaked credentials found on GitHub[/green]")
    console.print(f"\n  [bold yellow]📋 Manual Search Links ({len(results['search_urls'])}):[/bold yellow]")
    for item in results['search_urls'][:10]:
        console.print(f"    [dim]{item['query']}[/dim]")

    console.print(f"\n  [dim]Total queries: {len(results['search_urls'])} | "
                  f"API results: {results['total_results']}[/dim]")

    return results
