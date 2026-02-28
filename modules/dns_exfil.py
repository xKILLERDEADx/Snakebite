"""DNS Exfiltration Detector — test DNS as data exfiltration channel."""

import aiohttp
import asyncio
import socket
import base64
import hashlib
from urllib.parse import urlparse
from modules.core import console

DNS_EXFIL_PARAMS = [
    'url', 'redirect', 'next', 'callback', 'path', 'file',
    'img', 'src', 'load', 'page', 'domain', 'host',
]

async def _test_dns_resolution(domain):
    """Test if a domain resolves — indicates DNS exfil possible."""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return result is not None
    except Exception:
        return False


async def _check_dns_rebinding_window(session, url):
    """Check if DNS rebinding is possible via TTL analysis."""
    findings = []
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    try:
        loop = asyncio.get_event_loop()
        ip1 = await loop.run_in_executor(None, socket.gethostbyname, domain)
        await asyncio.sleep(1)
        ip2 = await loop.run_in_executor(None, socket.gethostbyname, domain)

        if ip1 != ip2:
            findings.append({
                'type': 'DNS Inconsistency (Rebinding Risk)',
                'ip1': ip1, 'ip2': ip2,
                'severity': 'High',
            })
    except Exception:
        pass

    return findings


async def _test_oob_dns(session, url):
    """Test Out-of-Band DNS exfiltration via parameters."""
    findings = []
    canary = hashlib.md5(url.encode()).hexdigest()[:8]

    oob_payloads = [
        f'{canary}.oob-dns-test.example.com',
        f'http://{canary}.callback.example.com',
        f'https://{canary}.exfil.example.com/data',
        f'//{canary}.dns-check.example.com',
    ]

    for param in DNS_EXFIL_PARAMS:
        for payload in oob_payloads[:2]:
            try:
                async with session.get(url, params={param: payload},
                                       timeout=aiohttp.ClientTimeout(total=8),
                                       ssl=False) as resp:
                    body = await resp.text()

                    if resp.status != 400 and canary in body:
                        findings.append({
                            'type': 'OOB DNS Reflection',
                            'param': param,
                            'payload': payload[:40],
                            'severity': 'High',
                            'detail': 'Canary reflected — external interaction likely',
                        })
            except Exception:
                pass

    return findings


async def _test_dns_zone_transfer(domain):
    """Check for DNS zone transfer vulnerability."""
    findings = []
    try:
        loop = asyncio.get_event_loop()
        ns_records = await loop.run_in_executor(None, socket.getfqdn, domain)

        try:
            import dns.resolver
            import dns.zone
            import dns.query

            answers = dns.resolver.resolve(domain, 'NS')
            for ns in answers:
                ns_host = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                    if zone:
                        records = [str(name) for name in zone.nodes.keys()]
                        findings.append({
                            'type': 'DNS Zone Transfer Allowed!',
                            'nameserver': ns_host,
                            'records_count': len(records),
                            'sample_records': records[:10],
                            'severity': 'Critical',
                        })
                except Exception:
                    pass
        except ImportError:
            pass
    except Exception:
        pass

    return findings


async def _check_dangling_dns(session, url):
    """Check for dangling DNS records (subdomain takeover indicators)."""
    findings = []
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    dangling_indicators = {
        'GitHub Pages': ['github.io', "There isn't a GitHub Pages site here"],
        'Heroku': ['heroku', 'No such app'],
        'AWS S3': ['s3.amazonaws.com', 'NoSuchBucket'],
        'Azure': ['azurewebsites.net', 'not found'],
        'Shopify': ['myshopify.com', 'Sorry, this shop is unavailable'],
        'Fastly': ['fastly', 'Fastly error: unknown domain'],
        'Pantheon': ['pantheonsite.io', '404 error unknown site'],
        'Tumblr': ['tumblr.com', "There's nothing here"],
        'Fly.io': ['fly.dev', '404 Not Found'],
    }

    cname_prefixes = ['www', 'blog', 'shop', 'app', 'api', 'dev', 'staging',
                      'cdn', 'mail', 'docs', 'status', 'help']

    for prefix in cname_prefixes[:8]:
        subdomain = f'{prefix}.{domain}'
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain)

            try:
                test_url = f'http://{subdomain}'
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    for provider, indicators in dangling_indicators.items():
                        for indicator in indicators:
                            if indicator.lower() in body.lower():
                                findings.append({
                                    'type': f'Dangling DNS ({provider})',
                                    'subdomain': subdomain,
                                    'severity': 'Critical',
                                    'detail': f'Subdomain takeover possible',
                                })
                                break
            except Exception:
                pass
        except socket.gaierror:
            pass
        except Exception:
            pass

    return findings


async def scan_dns_exfil(session, url):
    """DNS exfiltration and security analysis."""
    console.print(f"\n[bold cyan]--- DNS Exfiltration Detector ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    all_findings = []

    console.print(f"  [cyan]Testing OOB DNS via {len(DNS_EXFIL_PARAMS)} parameters...[/cyan]")
    oob = await _test_oob_dns(session, url)
    all_findings.extend(oob)
    for f in oob:
        console.print(f"  [red]{f['type']}: ?{f['param']}[/red]")

    console.print(f"  [cyan]Checking DNS rebinding window...[/cyan]")
    rebind = await _check_dns_rebinding_window(session, url)
    all_findings.extend(rebind)

    console.print(f"  [cyan]Testing zone transfer...[/cyan]")
    zone = await _test_dns_zone_transfer(domain)
    all_findings.extend(zone)
    for f in zone:
        console.print(f"  [bold red]⚠ {f['type']}: {f['nameserver']}[/bold red]")

    console.print(f"  [cyan]Checking dangling DNS records...[/cyan]")
    dangling = await _check_dangling_dns(session, url)
    all_findings.extend(dangling)
    for f in dangling:
        console.print(f"  [bold red]⚠ {f['type']}: {f['subdomain']}[/bold red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} DNS security issues![/bold red]")
    else:
        console.print(f"\n  [green]✓ DNS security looks clean[/green]")

    return {'findings': all_findings}
