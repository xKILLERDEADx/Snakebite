"""Certificate Transparency Log Scanner — find subdomains via crt.sh API."""

import aiohttp
import asyncio
from urllib.parse import urlparse
from collections import Counter
from modules.core import console


async def fetch_ct_logs(session, domain):
    """Query crt.sh Certificate Transparency database (real, free API)."""
    results = {
        'domain': domain,
        'certificates': [],
        'subdomains': set(),
        'issuers': Counter(),
        'wildcards': set(),
    }

    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        console.print(f"  [cyan]Querying crt.sh CT logs for {domain}...[/cyan]")
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), ssl=False) as resp:
            if resp.status != 200:
                console.print(f"  [yellow]crt.sh returned {resp.status}[/yellow]")
                return results

            data = await resp.json(content_type=None)
            if not data:
                console.print(f"  [yellow]No CT log entries found[/yellow]")
                return results

            for entry in data:
                name_value = entry.get('name_value', '')
                issuer = entry.get('issuer_name', '')
                not_before = entry.get('not_before', '')
                not_after = entry.get('not_after', '')

                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name and name.endswith(domain):
                        if '*' in name:
                            results['wildcards'].add(name)
                        else:
                            results['subdomains'].add(name)

                if issuer:
                    issuer_short = issuer.split('CN=')[-1].split(',')[0] if 'CN=' in issuer else issuer[:40]
                    results['issuers'][issuer_short] += 1

                results['certificates'].append({
                    'name': name_value.split('\n')[0],
                    'issuer': issuer[:60],
                    'not_before': not_before,
                    'not_after': not_after,
                })

    except asyncio.TimeoutError:
        console.print(f"  [yellow]crt.sh request timed out[/yellow]")
    except Exception as e:
        console.print(f"  [red]CT log error: {e}[/red]")

    return results


async def scan_ct_logs(session, url):
    """Scan Certificate Transparency logs for hidden subdomains."""
    console.print(f"\n[bold cyan]--- Certificate Transparency Scanner ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    parts = domain.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    results = await fetch_ct_logs(session, base_domain)

    if results['subdomains']:
        console.print(f"\n  [bold green]Found {len(results['subdomains'])} unique subdomains![/bold green]")

        interesting_keywords = ['admin', 'api', 'staging', 'dev', 'test', 'internal',
                                'vpn', 'mail', 'ftp', 'db', 'jenkins', 'git', 'ci',
                                'dashboard', 'panel', 'portal', 'backend', 'private']

        interesting = []
        regular = []
        for sub in sorted(results['subdomains']):
            if any(kw in sub for kw in interesting_keywords):
                interesting.append(sub)
            else:
                regular.append(sub)

        if interesting:
            console.print(f"\n  [bold red]🔥 Interesting Subdomains ({len(interesting)}):[/bold red]")
            for sub in interesting[:20]:
                console.print(f"    [red]• {sub}[/red]")

        console.print(f"\n  [cyan]All Subdomains ({len(regular)}):[/cyan]")
        for sub in regular[:30]:
            console.print(f"    [dim]• {sub}[/dim]")

        if len(results['subdomains']) > 50:
            console.print(f"    [dim]... and {len(results['subdomains']) - 50} more[/dim]")

    if results['wildcards']:
        console.print(f"\n  [yellow]Wildcard Certificates ({len(results['wildcards'])}):[/yellow]")
        for wc in sorted(results['wildcards'])[:10]:
            console.print(f"    [dim]{wc}[/dim]")

    if results['issuers']:
        console.print(f"\n  [cyan]Certificate Issuers:[/cyan]")
        for issuer, count in results['issuers'].most_common(5):
            console.print(f"    {issuer}: {count} certs")

    console.print(f"\n  [dim]Total CT entries: {len(results['certificates'])}[/dim]")

    results['subdomains'] = sorted(results['subdomains'])
    results['wildcards'] = sorted(results['wildcards'])

    return results
