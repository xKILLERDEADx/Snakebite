"""Threat Intelligence Feed — real-time threat data from public sources."""

import aiohttp
import asyncio
from urllib.parse import urlparse
import socket
from modules.core import console

async def _check_abuseipdb(session, ip):
    """Check IP reputation on AbuseIPDB (real API)."""
    try:
        url = f'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        headers = {'Accept': 'application/json', 'Key': ''}
        async with session.get(url, params=params, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get('data', {})
    except Exception:
        pass
    return {}


async def _check_urlhaus(session, url):
    """Check if URL is in URLhaus malware database (real API, free)."""
    try:
        api_url = 'https://urlhaus-api.abuse.ch/v1/url/'
        data = {'url': url}
        async with session.post(api_url, data=data,
                                timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                result = await resp.json()
                return result
    except Exception:
        pass
    return {}


async def _check_threatfox(session, domain):
    """Check domain in ThreatFox IOC database (real API, free)."""
    try:
        api_url = 'https://threatfox-api.abuse.ch/api/v1/'
        data = {'query': 'search_ioc', 'search_term': domain}
        async with session.post(api_url, json=data,
                                timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                result = await resp.json()
                return result
    except Exception:
        pass
    return {}


async def _check_phishtank(session, url):
    """Check if URL is in PhishTank database."""
    try:
        api_url = 'https://checkurl.phishtank.com/checkurl/'
        data = {'url': url, 'format': 'json'}
        async with session.post(api_url, data=data,
                                timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                result = await resp.json()
                return result.get('results', {})
    except Exception:
        pass
    return {}


async def _check_blocklist(session, ip):
    """Check IP against public blocklists."""
    blocklists = []
    lists_to_check = [
        f'https://check.spamhaus.org/listed/?searchterm={ip}',
    ]

    dnsbl_zones = [
        'zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org',
        'dnsbl.sorbs.net', 'psbl.surriel.com',
    ]

    reversed_ip = '.'.join(reversed(ip.split('.')))
    for zone in dnsbl_zones:
        try:
            query = f'{reversed_ip}.{zone}'
            socket.gethostbyname(query)
            blocklists.append(zone)
        except Exception:
            pass

    return blocklists


async def scan_threat_intel(session, url):
    """Check target against real-time threat intelligence feeds."""
    console.print(f"\n[bold cyan]--- Threat Intelligence Feed ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = None

    results = {
        'domain': domain,
        'ip': ip,
        'threats': [],
        'blocklists': [],
        'threat_level': 'Clean',
    }

    if ip:
        console.print(f"  [cyan]Checking IP {ip} reputation...[/cyan]")
        abuse_data = await _check_abuseipdb(session, ip)
        if abuse_data:
            confidence = abuse_data.get('abuseConfidenceScore', 0)
            if confidence > 0:
                results['threats'].append({
                    'source': 'AbuseIPDB',
                    'confidence': confidence,
                    'reports': abuse_data.get('totalReports', 0),
                    'severity': 'High' if confidence > 50 else 'Medium',
                })
                console.print(f"  [red]AbuseIPDB: Score {confidence}%, {abuse_data.get('totalReports', 0)} reports[/red]")

        console.print(f"  [cyan]Checking DNS blocklists...[/cyan]")
        blocklists = await asyncio.get_event_loop().run_in_executor(
            None, lambda: None)
        bl_results = await _check_blocklist(session, ip)
        results['blocklists'] = bl_results
        if bl_results:
            console.print(f"  [red]Listed on {len(bl_results)} blocklists: {', '.join(bl_results)}[/red]")

    console.print(f"  [cyan]Checking URLhaus malware database...[/cyan]")
    urlhaus = await _check_urlhaus(session, url)
    if urlhaus.get('query_status') == 'listed':
        results['threats'].append({
            'source': 'URLhaus',
            'detail': 'URL listed as malware distribution',
            'severity': 'Critical',
        })
        console.print(f"  [bold red]⚠ LISTED IN URLHAUS MALWARE DATABASE![/bold red]")

    console.print(f"  [cyan]Checking ThreatFox IOC database...[/cyan]")
    threatfox = await _check_threatfox(session, domain)
    if threatfox.get('query_status') == 'ok' and threatfox.get('data'):
        ioc_count = len(threatfox['data'])
        results['threats'].append({
            'source': 'ThreatFox',
            'ioc_count': ioc_count,
            'severity': 'Critical',
        })
        console.print(f"  [bold red]⚠ {ioc_count} IOCs found in ThreatFox![/bold red]")

    console.print(f"  [cyan]Checking PhishTank...[/cyan]")
    phish = await _check_phishtank(session, url)
    if phish.get('in_database'):
        results['threats'].append({
            'source': 'PhishTank',
            'valid': phish.get('valid', False),
            'severity': 'Critical',
        })
        console.print(f"  [bold red]⚠ KNOWN PHISHING URL![/bold red]")

    if any(t['severity'] == 'Critical' for t in results['threats']):
        results['threat_level'] = 'Critical'
    elif results['blocklists'] or any(t['severity'] == 'High' for t in results['threats']):
        results['threat_level'] = 'Suspicious'
    elif results['threats']:
        results['threat_level'] = 'Warning'

    level_color = {'Critical': 'red', 'Suspicious': 'yellow', 'Warning': 'yellow', 'Clean': 'green'}.get(results['threat_level'], 'dim')
    console.print(f"\n  [bold {level_color}]Threat Level: {results['threat_level']}[/bold {level_color}]")

    if not results['threats'] and not results['blocklists']:
        console.print(f"  [green]✓ No threats detected in intelligence feeds[/green]")

    return results
