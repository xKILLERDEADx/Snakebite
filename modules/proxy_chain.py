"""Proxy Chain / Tor Routing — route scans through proxy chains for anonymity."""

import aiohttp
import asyncio
import os
from urllib.parse import urlparse
from modules.core import console

DEFAULT_TOR_PROXY = 'socks5://127.0.0.1:9050'
DEFAULT_SOCKS_PROXY = 'socks5://127.0.0.1:1080'

def parse_proxy_chain(proxy_string):
    """Parse proxy chain string (comma-separated proxies)."""
    if not proxy_string:
        return []
    proxies = []
    for p in proxy_string.split(','):
        p = p.strip()
        if p:
            if not p.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                p = f'socks5://{p}'
            proxies.append(p)
    return proxies


async def check_tor_connection(session):
    """Check if Tor is running and accessible."""
    try:
        async with session.get('https://check.torproject.org/api/ip',
                               timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            data = await resp.json()
            return {
                'connected': True,
                'is_tor': data.get('IsTor', False),
                'ip': data.get('IP', 'unknown'),
            }
    except Exception as e:
        return {'connected': False, 'is_tor': False, 'error': str(e)[:60]}


async def check_proxy(proxy_url):
    """Check if a proxy is alive and working."""
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get('https://httpbin.org/ip',
                                   proxy=proxy_url,
                                   timeout=aiohttp.ClientTimeout(total=15),
                                   ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        'proxy': proxy_url,
                        'alive': True,
                        'external_ip': data.get('origin', 'unknown'),
                    }
    except Exception as e:
        return {'proxy': proxy_url, 'alive': False, 'error': str(e)[:60]}

    return {'proxy': proxy_url, 'alive': False, 'error': 'Unknown'}


def create_proxy_session(proxy_url):
    """Create an aiohttp session routed through a proxy."""
    connector = aiohttp.TCPConnector(ssl=False)
    return aiohttp.ClientSession(
        connector=connector,
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    ), proxy_url


async def get_real_ip(session):
    """Get current external IP address."""
    try:
        async with session.get('https://api.ipify.org?format=json',
                               timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            data = await resp.json()
            return data.get('ip', 'unknown')
    except Exception:
        return 'unknown'


async def setup_proxy_chain(proxy_config=None, use_tor=False):
    """Setup and verify proxy chain for scanning."""
    console.print(f"\n[bold cyan]--- Proxy Chain Setup ---[/bold cyan]")

    results = {
        'proxy_active': False,
        'proxy_url': None,
        'real_ip': 'unknown',
        'proxy_ip': 'unknown',
        'chain': [],
        'tor_active': False,
    }

    async with aiohttp.ClientSession() as temp_session:
        results['real_ip'] = await get_real_ip(temp_session)
        console.print(f"  [dim]Real IP: {results['real_ip']}[/dim]")

    if use_tor:
        console.print(f"  [cyan]Checking Tor connection...[/cyan]")
        proxy_url = DEFAULT_TOR_PROXY
        check = await check_proxy(proxy_url)

        if check['alive']:
            results['proxy_active'] = True
            results['proxy_url'] = proxy_url
            results['proxy_ip'] = check['external_ip']
            results['tor_active'] = True
            console.print(f"  [bold green]Tor connected! IP: {check['external_ip']}[/bold green]")
        else:
            console.print(f"  [red]Tor not available: {check.get('error', 'Connection failed')}[/red]")
            console.print(f"  [dim]Install Tor: https://www.torproject.org/download/[/dim]")
            console.print(f"  [dim]Or run: tor --runasdaemon 1[/dim]")

    elif proxy_config:
        proxies = parse_proxy_chain(proxy_config)
        console.print(f"  [cyan]Checking {len(proxies)} proxies...[/cyan]")

        for proxy_url in proxies:
            check = await check_proxy(proxy_url)
            results['chain'].append(check)

            if check['alive']:
                console.print(f"  [green]✓ {proxy_url} → IP: {check['external_ip']}[/green]")
                if not results['proxy_active']:
                    results['proxy_active'] = True
                    results['proxy_url'] = proxy_url
                    results['proxy_ip'] = check['external_ip']
            else:
                console.print(f"  [red]✗ {proxy_url} — {check.get('error', 'Dead')}[/red]")

    if results['proxy_active']:
        console.print(f"\n  [bold green]Proxy active: {results['real_ip']} → {results['proxy_ip']}[/bold green]")
    else:
        console.print(f"\n  [yellow]No proxy configured — scanning with direct IP[/yellow]")
        console.print(f"  [dim]Use --proxy socks5://ip:port or --tor to enable[/dim]")

    return results
