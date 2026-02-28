"""Shodan + VirusTotal Integration — real API queries (optional keys)."""

import aiohttp
import asyncio
from urllib.parse import urlparse
from modules.core import console

async def scan_shodan(session, url, api_key=None):
    """Query Shodan API for target intelligence."""
    console.print(f"\n[bold cyan]--- Shodan Intelligence ---[/bold cyan]")
    if not api_key:
        console.print(f"  [yellow]No --shodan-key provided. Skipping Shodan scan.[/yellow]")
        console.print(f"  [dim]Get free key at: https://account.shodan.io/register[/dim]")
        return {}

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    results = {'domain': domain, 'ip': '', 'ports': [], 'vulns': [], 'services': [], 'data': {}}

    try:
        import socket
        ip = await asyncio.get_event_loop().run_in_executor(
            None, socket.gethostbyname, domain
        )
        results['ip'] = ip
        console.print(f"  [green]Resolved: {domain} → {ip}[/green]")
        shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        async with session.get(shodan_url, timeout=aiohttp.ClientTimeout(total=20), ssl=False) as resp:
            if resp.status == 401:
                console.print(f"  [red]Invalid Shodan API key[/red]")
                return results
            if resp.status == 404:
                console.print(f"  [yellow]No Shodan data found for {ip}[/yellow]")
                return results
            if resp.status != 200:
                console.print(f"  [yellow]Shodan API returned {resp.status}[/yellow]")
                return results

            data = await resp.json()
            results['data'] = data
            ports = data.get('ports', [])
            results['ports'] = ports
            console.print(f"  [green]Open Ports: {', '.join(str(p) for p in ports[:20])}[/green]")
            vulns = data.get('vulns', [])
            results['vulns'] = vulns
            if vulns:
                console.print(f"\n  [bold red]🔴 Vulnerabilities ({len(vulns)}):[/bold red]")
                for vuln in vulns[:15]:
                    console.print(f"    [red]• {vuln}[/red]")

            for item in data.get('data', [])[:10]:
                service_info = {
                    'port': item.get('port', 0),
                    'transport': item.get('transport', ''),
                    'product': item.get('product', ''),
                    'version': item.get('version', ''),
                    'banner': (item.get('data', '') or '')[:200],
                    'os': item.get('os', ''),
                }
                results['services'].append(service_info)
                if service_info['product']:
                    console.print(f"    [cyan]Port {service_info['port']}:[/cyan] {service_info['product']} {service_info['version']}")

            org = data.get('org', '')
            isp = data.get('isp', '')
            os_info = data.get('os', '')
            if org:
                console.print(f"\n  [green]Organization:[/green] {org}")
            if isp:
                console.print(f"  [green]ISP:[/green] {isp}")
            if os_info:
                console.print(f"  [green]OS:[/green] {os_info}")

    except Exception as e:
        console.print(f"  [red]Shodan error: {e}[/red]")

    return results


async def scan_virustotal(session, url, api_key=None):
    """Query VirusTotal API for domain reputation."""
    console.print(f"\n[bold cyan]--- VirusTotal Intelligence ---[/bold cyan]")

    if not api_key:
        console.print(f"  [yellow]No --vt-key provided. Skipping VirusTotal scan.[/yellow]")
        console.print(f"  [dim]Get free key at: https://www.virustotal.com/gui/join-us[/dim]")
        return {}

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    results = {'domain': domain, 'malicious': 0, 'suspicious': 0, 'clean': 0,
               'categories': {}, 'dns': [], 'whois': '', 'engines': []}

    try:
        headers = {'x-apikey': api_key}

        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        async with session.get(vt_url, headers=headers, timeout=aiohttp.ClientTimeout(total=20), ssl=False) as resp:
            if resp.status == 401:
                console.print(f"  [red]Invalid VirusTotal API key[/red]")
                return results
            if resp.status != 200:
                console.print(f"  [yellow]VirusTotal API returned {resp.status}[/yellow]")
                return results
            data = await resp.json()
            attrs = data.get('data', {}).get('attributes', {})
            analysis = attrs.get('last_analysis_stats', {})
            results['malicious'] = analysis.get('malicious', 0)
            results['suspicious'] = analysis.get('suspicious', 0)
            results['clean'] = analysis.get('undetected', 0) + analysis.get('harmless', 0)
            mal_count = results['malicious']
            sus_count = results['suspicious']
            if mal_count > 0:
                console.print(f"  [bold red]🔴 MALICIOUS: {mal_count} engines flagged this domain![/bold red]")
            elif sus_count > 0:
                console.print(f"  [bold yellow]🟡 SUSPICIOUS: {sus_count} engines flagged this domain[/bold yellow]")
            else:
                console.print(f"  [bold green]✓ CLEAN: No engines flagged this domain[/bold green]")
            console.print(f"  [dim]Malicious: {mal_count} | Suspicious: {sus_count} | Clean: {results['clean']}[/dim]")
            categories = attrs.get('categories', {})
            results['categories'] = categories
            if categories:
                cat_values = set(categories.values())
                console.print(f"  [green]Categories:[/green] {', '.join(cat_values)}")
            dns_records = attrs.get('last_dns_records', [])
            results['dns'] = dns_records
            if dns_records:
                console.print(f"\n  [cyan]DNS Records ({len(dns_records)}):[/cyan]")
                for rec in dns_records[:10]:
                    console.print(f"    {rec.get('type', '')}: {rec.get('value', '')}")
            reputation = attrs.get('reputation', 0)
            console.print(f"  [green]Reputation Score:[/green] {reputation}")
            last_analysis = attrs.get('last_analysis_results', {})
            for engine, result in last_analysis.items():
                if result.get('category') in ('malicious', 'suspicious'):
                    results['engines'].append({
                        'engine': engine,
                        'category': result['category'],
                        'result': result.get('result', ''),
                    })

            if results['engines']:
                console.print(f"\n  [bold red]Flagged by:[/bold red]")
                for eng in results['engines'][:10]:
                    console.print(f"    [red]• {eng['engine']}: {eng['result']}[/red]")

    except Exception as e:
        console.print(f"  [red]VirusTotal error: {e}[/red]")

    return results
