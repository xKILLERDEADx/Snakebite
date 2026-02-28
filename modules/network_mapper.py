"""Network Topology Mapper — map target infrastructure (ASN, CIDR, CDN, relationships)."""

import aiohttp
import asyncio
import socket
import json
from urllib.parse import urlparse
from modules.core import console

async def _get_ip_info(session, ip):
    """Get detailed IP intelligence from ip-api.com (free, real-time)."""
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                return await resp.json()
    except Exception:
        pass
    return {}


async def _get_asn_info(session, ip):
    """Get ASN details from BGPView API (free, real-time)."""
    try:
        url = f'https://api.bgpview.io/ip/{ip}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get('data', {})
    except Exception:
        pass
    return {}


async def _resolve_host(hostname):
    """Resolve hostname to IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ips = set()
        for result in results:
            ips.add(result[4][0])
        return list(ips)
    except Exception:
        return []


async def _check_cdn(session, url, ip):
    """Detect CDN provider from headers and IP ranges."""
    cdn_detected = None
    cdn_headers = {}

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            cdn_checks = {
                'Cloudflare': ['cf-ray', 'cf-cache-status'],
                'Akamai': ['x-akamai-transformed', 'x-akamai-request-id'],
                'CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'Fastly': ['x-served-by', 'x-cache', 'fastly'],
                'Google Cloud CDN': ['via', 'x-goog-'],
                'Azure CDN': ['x-msedge-ref', 'x-azure-ref'],
                'Incapsula': ['x-iinfo', 'x-cdn'],
                'StackPath': ['x-sp-'],
                'KeyCDN': ['x-edge-location'],
                'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            }

            for cdn_name, header_list in cdn_checks.items():
                for h in header_list:
                    matching = [k for k in headers if h in k]
                    if matching:
                        cdn_detected = cdn_name
                        for m in matching:
                            cdn_headers[m] = headers[m]
                        break

            if not cdn_detected:
                server = headers.get('server', '').lower()
                if 'cloudflare' in server:
                    cdn_detected = 'Cloudflare'
                elif 'akamaighost' in server:
                    cdn_detected = 'Akamai'
    except Exception:
        pass

    return cdn_detected, cdn_headers


async def _reverse_dns(ip):
    """Perform reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


async def scan_network_topology(session, url):
    """Map target network infrastructure."""
    console.print(f"\n[bold cyan]--- Network Topology Mapper ---[/bold cyan]")

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]

    results = {
        'hostname': hostname,
        'ips': [],
        'asn': {},
        'geo': {},
        'cdn': None,
        'reverse_dns': {},
        'infrastructure': {},
        'related_hosts': [],
    }

    console.print(f"  [cyan]Resolving {hostname}...[/cyan]")
    ips = await asyncio.get_event_loop().run_in_executor(None, lambda: None)
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ips = list(set(r[4][0] for r in addr_info))
    except Exception:
        ips = []

    results['ips'] = ips
    if ips:
        console.print(f"  [green]IPs: {', '.join(ips)}[/green]")
    else:
        console.print(f"  [red]Could not resolve hostname[/red]")
        return results

    primary_ip = ips[0]

    console.print(f"  [cyan]Fetching IP intelligence...[/cyan]")
    ip_info = await _get_ip_info(session, primary_ip)
    results['geo'] = ip_info

    if ip_info:
        console.print(f"  [dim]Location: {ip_info.get('city', '')}, {ip_info.get('regionName', '')}, {ip_info.get('country', '')}[/dim]")
        console.print(f"  [dim]ISP: {ip_info.get('isp', 'N/A')}[/dim]")
        console.print(f"  [dim]Org: {ip_info.get('org', 'N/A')}[/dim]")
        console.print(f"  [dim]ASN: {ip_info.get('as', 'N/A')}[/dim]")

        if ip_info.get('hosting'):
            console.print(f"  [yellow]Hosted on cloud/datacenter infrastructure[/yellow]")
        if ip_info.get('proxy'):
            console.print(f"  [yellow]IP identified as proxy/VPN[/yellow]")

    console.print(f"  [cyan]Querying ASN data...[/cyan]")
    asn_info = await _get_asn_info(session, primary_ip)
    results['asn'] = asn_info

    if asn_info:
        prefixes = asn_info.get('prefixes', [])
        if prefixes:
            console.print(f"  [dim]IP Prefixes ({len(prefixes)}):[/dim]")
            for prefix in prefixes[:5]:
                console.print(f"    [dim]{prefix.get('prefix', '')} — {prefix.get('name', '')}[/dim]")

        rir_alloc = asn_info.get('rir_allocation', {})
        if rir_alloc:
            console.print(f"  [dim]RIR: {rir_alloc.get('rir_name', 'N/A')} (Allocated: {rir_alloc.get('date_allocated', 'N/A')})[/dim]")

    console.print(f"  [cyan]Detecting CDN...[/cyan]")
    cdn_name, cdn_headers = await _check_cdn(session, url, primary_ip)
    results['cdn'] = cdn_name

    if cdn_name:
        console.print(f"  [bold yellow]CDN: {cdn_name}[/bold yellow]")
        for h, v in cdn_headers.items():
            console.print(f"    [dim]{h}: {v}[/dim]")
    else:
        console.print(f"  [dim]No CDN detected (direct hosting)[/dim]")

    console.print(f"  [cyan]Reverse DNS lookups...[/cyan]")
    for ip in ips[:5]:
        rdns = await asyncio.get_event_loop().run_in_executor(None, lambda i=ip: None)
        try:
            rdns_host, _, _ = socket.gethostbyaddr(ip)
            results['reverse_dns'][ip] = rdns_host
            console.print(f"  [dim]{ip} → {rdns_host}[/dim]")
        except Exception:
            results['reverse_dns'][ip] = None

    console.print(f"\n  [bold]Infrastructure Summary:[/bold]")
    console.print(f"    Hostname: {hostname}")
    console.print(f"    IPs: {', '.join(ips)}")
    console.print(f"    ASN: {ip_info.get('as', 'N/A')}")
    console.print(f"    CDN: {cdn_name or 'None'}")
    console.print(f"    Hosting: {'Cloud/DC' if ip_info.get('hosting') else 'Residential/Other'}")

    return results
