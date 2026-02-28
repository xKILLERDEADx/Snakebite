import asyncio
from modules.core import console

# Memcached Dumper (Data Leak)
# Focus: Unauthenticated Memcached (Port 11211).
# Vector: Connect and run 'stats' or 'dump'.

async def check_memcached(session, url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = 11211
    
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
        
        # Send stats command
        writer.write(b"stats\r\n")
        await writer.drain()
        
        data = await asyncio.wait_for(reader.read(1024), timeout=3)
        response = data.decode('utf-8', errors='ignore')
        
        writer.close()
        await writer.wait_closed()

        if "STAT pid" in response or "STAT version" in response:
             return {
                "url": f"{host}:{port}",
                "type": "Memcached Unauthenticated",
                "evidence": "Stats command successful. Data dump possible."
            }

    except Exception:
        pass
    return None

async def scan_memcached(session, url):
    """
    Scan for Memcached Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Memcached Scanner ---[/bold cyan]")
    
    results = []
    res = await check_memcached(session, url)
    if res:
         console.print(f"  [bold red][!] MEMCACHED EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No exposed Memcached service found on default port.[/dim]")
        
    return results
