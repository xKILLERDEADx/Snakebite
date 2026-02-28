"""WHOIS History Tracker — track domain ownership changes and registration details."""

import aiohttp
import asyncio
from urllib.parse import urlparse
from datetime import datetime
from modules.core import console

async def _fetch_whois_api(session, domain):
    """Fetch WHOIS data from free API (real-time)."""
    results = {}
    try:
        url = f'https://rdap.org/domain/{domain}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                results['rdap'] = {
                    'name': data.get('ldhName', ''),
                    'status': data.get('status', []),
                    'events': [],
                    'nameservers': [],
                    'entities': [],
                }
                for event in data.get('events', []):
                    results['rdap']['events'].append({
                        'action': event.get('eventAction', ''),
                        'date': event.get('eventDate', ''),
                    })
                for ns in data.get('nameservers', []):
                    results['rdap']['nameservers'].append(ns.get('ldhName', ''))
                for entity in data.get('entities', []):
                    roles = entity.get('roles', [])
                    vcards = entity.get('vcardArray', [])
                    name = ''
                    if vcards and len(vcards) > 1:
                        for vcard in vcards[1]:
                            if vcard[0] == 'fn':
                                name = vcard[3] if len(vcard) > 3 else ''
                    results['rdap']['entities'].append({
                        'roles': roles,
                        'name': name,
                    })
    except Exception:
        pass

    try:
        url = f'https://api.whoapi.com/?apikey=free&r=whois&domain={domain}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get('status') != '0':
                    results['whoapi'] = data
    except Exception:
        pass

    return results


async def _fetch_dns_history(session, domain):
    """Check DNS history via SecurityTrails-style API."""
    history = []
    try:
        url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                if 'error' not in text.lower():
                    for line in text.strip().splitlines()[:30]:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            history.append({
                                'hostname': parts[0].strip(),
                                'ip': parts[1].strip(),
                            })
    except Exception:
        pass
    return history


async def _analyze_domain_age(events):
    """Analyze domain age and important dates."""
    analysis = {'age_days': 0, 'created': '', 'updated': '', 'expires': ''}

    for event in events:
        action = event.get('action', '').lower()
        date_str = event.get('date', '')

        if 'registration' in action:
            analysis['created'] = date_str[:10]
        elif 'last changed' in action or 'last update' in action:
            analysis['updated'] = date_str[:10]
        elif 'expiration' in action:
            analysis['expires'] = date_str[:10]

    if analysis['created']:
        try:
            created = datetime.fromisoformat(analysis['created'])
            analysis['age_days'] = (datetime.now() - created).days
        except Exception:
            pass

    return analysis


async def scan_whois_history(session, url):
    """Track domain ownership and registration history."""
    console.print(f"\n[bold cyan]--- WHOIS History Tracker ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    parts = domain.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    results = {'domain': base_domain, 'whois': {}, 'dns_history': [], 'analysis': {}}

    console.print(f"  [cyan]Querying WHOIS/RDAP for {base_domain}...[/cyan]")
    whois_data = await _fetch_whois_api(session, base_domain)
    results['whois'] = whois_data

    if 'rdap' in whois_data:
        rdap = whois_data['rdap']
        console.print(f"  [green]Domain: {rdap['name']}[/green]")

        if rdap['status']:
            console.print(f"  [dim]Status: {', '.join(rdap['status'][:3])}[/dim]")

        events = rdap.get('events', [])
        if events:
            console.print(f"\n  [bold]Timeline:[/bold]")
            for event in events:
                console.print(f"    [dim]{event['action']}: {event['date'][:10]}[/dim]")

            analysis = await _analyze_domain_age(events)
            results['analysis'] = analysis

            if analysis['age_days'] > 0:
                years = analysis['age_days'] / 365
                console.print(f"\n  [cyan]Domain Age: {analysis['age_days']} days ({years:.1f} years)[/cyan]")
                if analysis['age_days'] < 30:
                    console.print(f"  [bold red]⚠ Very new domain (<30 days) — potential phishing![/bold red]")
                elif analysis['age_days'] < 180:
                    console.print(f"  [yellow]⚠ Relatively new domain (<6 months)[/yellow]")

        if rdap['nameservers']:
            console.print(f"\n  [dim]Nameservers: {', '.join(rdap['nameservers'][:4])}[/dim]")

        if rdap['entities']:
            console.print(f"\n  [bold]Registrant Info:[/bold]")
            for entity in rdap['entities']:
                if entity['name']:
                    console.print(f"    [dim]{', '.join(entity['roles'])}: {entity['name']}[/dim]")

    console.print(f"\n  [cyan]DNS Host Search...[/cyan]")
    dns_history = await _fetch_dns_history(session, base_domain)
    results['dns_history'] = dns_history

    if dns_history:
        console.print(f"  [green]Found {len(dns_history)} related hosts[/green]")
        for entry in dns_history[:10]:
            console.print(f"    [dim]{entry['hostname']} → {entry['ip']}[/dim]")

    return results
