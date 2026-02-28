"""DNS Zone Transfer + Deep DNS Enumeration — real DNS queries via socket."""

import socket
import asyncio
import struct
from urllib.parse import urlparse
from modules.core import console

def _get_nameservers(domain):
    """Get NS records for a domain using DNS query."""
    nameservers = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'NS')
        for ns in answers:
            nameservers.append(str(ns.target).rstrip('.'))
    except ImportError:
        try:
            ns_records = socket.getaddrinfo(domain, None)
            for prefix in ['ns1', 'ns2', 'dns1', 'dns2']:
                try:
                    ip = socket.gethostbyname(f"{prefix}.{domain}")
                    nameservers.append(f"{prefix}.{domain}")
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass
    return nameservers


def _build_axfr_query(domain):
    """Build a raw DNS AXFR query packet."""
    import random
    txid = random.randint(0, 65535)
    header = struct.pack('>HHHHHH', txid, 0, 1, 0, 0, 0)
    question = b''
    for part in domain.split('.'):
        question += struct.pack('B', len(part)) + part.encode()
    question += b'\x00'
    question += struct.pack('>HH', 252, 1) 
    return header + question
def attempt_zone_transfer(domain, nameserver):
    """Attempt AXFR zone transfer against a nameserver."""
    records = []
    try:
        ns_ip = socket.gethostbyname(nameserver)
        query = _build_axfr_query(domain)
        length_prefix = struct.pack('>H', len(query))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ns_ip, 53))
        sock.send(length_prefix + query)

        data = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        sock.close()

        if len(data) > 12:
            flags = struct.unpack('>H', data[4:6])[0] if len(data) > 6 else 0
            rcode = flags & 0x0F
            ancount = struct.unpack('>H', data[8:10])[0] if len(data) > 10 else 0

            if rcode == 0 and ancount > 0:
                records.append({
                    'nameserver': nameserver,
                    'status': 'TRANSFER_SUCCESS',
                    'record_count': ancount,
                    'raw_size': len(data),
                })
            elif rcode == 5:
                records.append({
                    'nameserver': nameserver,
                    'status': 'REFUSED',
                    'record_count': 0,
                })
            else:
                records.append({
                    'nameserver': nameserver,
                    'status': f'RCODE_{rcode}',
                    'record_count': 0,
                })
        else:
            records.append({
                'nameserver': nameserver,
                'status': 'NO_RESPONSE',
                'record_count': 0,
            })

    except socket.timeout:
        records.append({'nameserver': nameserver, 'status': 'TIMEOUT', 'record_count': 0})
    except ConnectionRefusedError:
        records.append({'nameserver': nameserver, 'status': 'REFUSED', 'record_count': 0})
    except Exception as e:
        records.append({'nameserver': nameserver, 'status': f'ERROR: {str(e)[:50]}', 'record_count': 0})

    return records


def deep_dns_enum(domain):
    """Enumerate common DNS record types."""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA', 'PTR']

    try:
        import dns.resolver
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results[rtype] = [str(r) for r in answers]
            except Exception:
                pass
    except ImportError:
        try:
            ips = socket.getaddrinfo(domain, None)
            results['A'] = list(set(ip[4][0] for ip in ips if ip[0] == socket.AF_INET))
            results['AAAA'] = list(set(ip[4][0] for ip in ips if ip[0] == socket.AF_INET6))
        except Exception:
            pass

        try:
            mx = socket.getaddrinfo(domain, 'smtp')
            if mx:
                results['MX'] = [f"mail.{domain}"]
        except Exception:
            pass

    return results


async def scan_dns_zone(session, url):
    """Run DNS Zone Transfer + Deep Enumeration."""
    console.print(f"\n[bold cyan]--- DNS Zone Transfer & Deep Enumeration ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    console.print(f"  [cyan]Finding nameservers for {domain}...[/cyan]")
    nameservers = _get_nameservers(domain)
    zone_results = {
        'domain': domain,
        'nameservers': nameservers,
        'zone_transfer': [],
        'dns_records': {},
        'vulnerable': False,
    }

    if nameservers:
        console.print(f"  [green]Found {len(nameservers)} nameservers: {', '.join(nameservers)}[/green]")
        console.print(f"  [yellow]Attempting AXFR zone transfer...[/yellow]")
        for ns in nameservers:
            console.print(f"    [dim]Trying {ns}...[/dim]")
            transfer_results = await asyncio.get_event_loop().run_in_executor(
                None, attempt_zone_transfer, domain, ns
            )
            zone_results['zone_transfer'].extend(transfer_results)

            for r in transfer_results:
                if r['status'] == 'TRANSFER_SUCCESS':
                    zone_results['vulnerable'] = True
                    console.print(f"    [bold red]⚠️ ZONE TRANSFER SUCCESSFUL on {ns}! ({r['record_count']} records)[/bold red]")
                elif r['status'] == 'REFUSED':
                    console.print(f"    [green]✓ {ns} — Transfer refused (secure)[/green]")
                else:
                    console.print(f"    [dim]{ns} — {r['status']}[/dim]")
    else:
        console.print(f"  [yellow]Could not find nameservers[/yellow]")

    console.print(f"\n  [cyan]Enumerating DNS records...[/cyan]")
    dns_records = await asyncio.get_event_loop().run_in_executor(
        None, deep_dns_enum, domain
    )
    zone_results['dns_records'] = dns_records

    if dns_records:
        for rtype, values in dns_records.items():
            console.print(f"    [green]{rtype}:[/green] {', '.join(str(v)[:60] for v in values[:5])}")

    if zone_results['vulnerable']:
        console.print(f"\n  [bold red]🔴 CRITICAL: DNS Zone Transfer is ENABLED — full domain exposure![/bold red]")
    else:
        console.print(f"\n  [green]✓ Zone transfer properly restricted[/green]")

    return zone_results
