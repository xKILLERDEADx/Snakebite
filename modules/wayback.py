"""Wayback Machine Deep Recon — fetch historical URLs from archive.org CDX API."""

import aiohttp
import asyncio
from urllib.parse import urlparse, urljoin
from collections import Counter
from modules.core import console


async def fetch_wayback_urls(session, domain, limit=5000):
    """Fetch archived URLs from Wayback Machine CDX API (real, free, no key)."""
    results = {
        'urls': [],
        'endpoints': set(),
        'file_types': Counter(),
        'status_codes': Counter(),
        'years': Counter(),
        'interesting': [],
    }

    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*&output=json&fl=timestamp,original,statuscode,mimetype"
        f"&collapse=urlkey&limit={limit}"
    )

    try:
        console.print(f"  [cyan]Querying Wayback Machine CDX API...[/cyan]")
        async with session.get(cdx_url, timeout=aiohttp.ClientTimeout(total=30), ssl=False) as resp:
            if resp.status != 200:
                console.print(f"  [yellow]Wayback API returned {resp.status}[/yellow]")
                return results

            data = await resp.json(content_type=None)
            if not data or len(data) < 2:
                console.print(f"  [yellow]No archived URLs found[/yellow]")
                return results

            headers = data[0]
            rows = data[1:]

            console.print(f"  [green]Found {len(rows):,} archived URLs[/green]")

            interesting_extensions = {
                '.sql', '.bak', '.old', '.zip', '.tar', '.gz', '.config',
                '.env', '.log', '.txt', '.xml', '.json', '.csv', '.db',
                '.sqlite', '.dump', '.conf', '.ini', '.yml', '.yaml',
                '.key', '.pem', '.crt', '.passwd', '.shadow', '.htpasswd',
            }
            interesting_paths = {
                'admin', 'login', 'dashboard', 'config', 'backup',
                'debug', 'test', 'staging', 'api', 'internal', 'secret',
                'phpinfo', 'phpmyadmin', '.git', '.env', 'wp-config',
                'database', 'dump', 'export', 'upload', 'private',
            }

            for row in rows:
                if len(row) < 4:
                    continue
                timestamp, url, status, mime = row[0], row[1], row[2], row[3]
                results['urls'].append(url)
                year = timestamp[:4] if len(timestamp) >= 4 else 'unknown'
                results['years'][year] += 1
                results['status_codes'][status] += 1
                parsed = urlparse(url)
                path = parsed.path.lower()
                for ext in interesting_extensions:
                    if path.endswith(ext):
                        results['file_types'][ext] += 1
                path_lower = path.lower()
                for keyword in interesting_paths:
                    if keyword in path_lower:
                        results['interesting'].append({
                            'url': url,
                            'keyword': keyword,
                            'timestamp': timestamp,
                            'status': status,
                        })
                        break

                results['endpoints'].add(parsed.path)

    except asyncio.TimeoutError:
        console.print(f"  [yellow]Wayback Machine request timed out[/yellow]")
    except Exception as e:
        console.print(f"  [red]Wayback error: {e}[/red]")
    return results
async def scan_wayback(session, url):
    """Run Wayback Machine deep recon."""
    console.print(f"\n[bold cyan]--- Wayback Machine Deep Recon ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc

    results = await fetch_wayback_urls(session, domain)

    if results['urls']:
        console.print(f"\n  [bold green]📊 Wayback Results:[/bold green]")
        console.print(f"    [green]Total Archived URLs:[/green]  {len(results['urls']):,}")
        console.print(f"    [green]Unique Endpoints:[/green]     {len(results['endpoints']):,}")

        if results['years']:
            years_sorted = sorted(results['years'].items())
            year_str = ', '.join(f"{y}:{c}" for y, c in years_sorted[-5:])
            console.print(f"    [green]Archive Years:[/green]        {year_str}")

        if results['file_types']:
            console.print(f"\n  [bold yellow]📁 Sensitive File Types Found:[/bold yellow]")
            for ext, count in results['file_types'].most_common(10):
                console.print(f"    [red]{ext}[/red] — {count} files")

        if results['interesting']:
            console.print(f"\n  [bold red]🔥 Interesting URLs ({len(results['interesting'])}):[/bold red]")
            seen = set()
            for item in results['interesting'][:20]:
                if item['url'] not in seen:
                    seen.add(item['url'])
                    console.print(f"    [{item['keyword']}] {item['url']}")
    else:
        console.print(f"  [dim]No archived data found for {domain}[/dim]")

    results['endpoints'] = list(results['endpoints'])
    return results
