"""Dark Web Monitor — check if domain appears in breach databases."""

import aiohttp
import asyncio
import hashlib
from urllib.parse import urlparse
from modules.core import console

async def _check_hibp_breaches(session, domain):
    """Check Have I Been Pwned API for known breaches (real API)."""
    results = []
    url = f'https://haveibeenpwned.com/api/v3/breaches'

    try:
        headers = {'User-Agent': 'Snakebite-Scanner'}
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                breaches = await resp.json()
                domain_lower = domain.lower()
                for breach in breaches:
                    breach_domain = breach.get('Domain', '').lower()
                    if breach_domain == domain_lower or domain_lower in breach_domain:
                        results.append({
                            'name': breach.get('Name', ''),
                            'domain': breach.get('Domain', ''),
                            'breach_date': breach.get('BreachDate', ''),
                            'pwn_count': breach.get('PwnCount', 0),
                            'data_classes': breach.get('DataClasses', []),
                            'description': breach.get('Description', '')[:200],
                            'is_verified': breach.get('IsVerified', False),
                        })
    except Exception as e:
        console.print(f"  [dim]HIBP check: {str(e)[:50]}[/dim]")

    return results


async def _check_dehashed(session, domain):
    """Check dehashed.com for leaked credentials (generates search URL)."""
    search_url = f'https://www.dehashed.com/search?query=domain:{domain}'
    return search_url


async def _check_leakcheck(session, domain):
    """Generate leak check URLs for manual verification."""
    urls = {
        'IntelligenceX': f'https://intelx.io/?s={domain}',
        'LeakCheck': f'https://leakcheck.io/api/public?check={domain}',
        'Hudson Rock': f'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}',
    }
    return urls


async def _check_password_hashes(session, test_passwords):
    """Check if common passwords appear in known breaches (k-anonymity API)."""
    breached = []
    for password in test_passwords[:10]:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            url = f'https://api.pwnedpasswords.com/range/{prefix}'
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        hash_suffix, count = line.split(':')
                        if hash_suffix.strip() == suffix:
                            breached.append({
                                'password': password[:3] + '***',
                                'count': int(count),
                            })
                            break
        except Exception:
            pass
        await asyncio.sleep(0.2)

    return breached


async def scan_dark_web(session, url):
    """Check target domain against breach databases and dark web sources."""
    console.print(f"\n[bold cyan]--- Dark Web & Breach Monitor ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    parts = domain.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    results = {
        'domain': base_domain,
        'breaches': [],
        'password_leaks': [],
        'search_urls': {},
        'risk_level': 'Low',
    }

    console.print(f"  [cyan]Checking breach databases for {base_domain}...[/cyan]")
    breaches = await _check_hibp_breaches(session, base_domain)
    results['breaches'] = breaches

    if breaches:
        total_pwned = sum(b.get('pwn_count', 0) for b in breaches)
        console.print(f"\n  [bold red]⚠ {len(breaches)} BREACHES FOUND for {base_domain}![/bold red]")
        console.print(f"  [red]Total accounts exposed: {total_pwned:,}[/red]")

        for breach in breaches[:5]:
            console.print(f"\n    [red]• {breach['name']}[/red] ({breach['breach_date']})")
            console.print(f"      [dim]Accounts: {breach['pwn_count']:,}[/dim]")
            if breach['data_classes']:
                console.print(f"      [dim]Data: {', '.join(breach['data_classes'][:5])}[/dim]")
            if breach['is_verified']:
                console.print(f"      [dim]Status: Verified breach[/dim]")

        results['risk_level'] = 'Critical' if total_pwned > 1000000 else 'High' if total_pwned > 10000 else 'Medium'
    else:
        console.print(f"  [green]✓ No known breaches found for {base_domain}[/green]")

    console.print(f"\n  [cyan]Checking common domain passwords in breach databases...[/cyan]")
    test_passwords = [
        f'{base_domain.split(".")[0]}123', f'{base_domain.split(".")[0]}@123',
        f'admin@{base_domain.split(".")[0]}', f'{base_domain.split(".")[0]}!',
        'admin123', 'password123', 'P@ssw0rd', f'{base_domain.split(".")[0]}2024',
    ]
    password_leaks = await _check_password_hashes(session, test_passwords)
    results['password_leaks'] = password_leaks

    if password_leaks:
        console.print(f"  [bold yellow]⚠ {len(password_leaks)} domain-related passwords in breach databases![/bold yellow]")
        for pl in password_leaks:
            console.print(f"    [yellow]{pl['password']} — seen {pl['count']:,} times[/yellow]")

    console.print(f"\n  [cyan]Dark Web Search URLs:[/cyan]")
    search_urls = await _check_leakcheck(session, base_domain)
    dehashed_url = await _check_dehashed(session, base_domain)
    search_urls['Dehashed'] = dehashed_url
    results['search_urls'] = search_urls

    for service, search_url in search_urls.items():
        console.print(f"    [dim]{service}: {search_url}[/dim]")

    risk_color = {'Critical': 'red', 'High': 'red', 'Medium': 'yellow', 'Low': 'green'}.get(results['risk_level'], 'dim')
    console.print(f"\n  [bold {risk_color}]Breach Risk Level: {results['risk_level']}[/bold {risk_color}]")

    return results
