import asyncio
from modules.core import console

# Redis Scanner (Unauth RCE)
# Focus: Unauthenticated Redis Instances (Port 6379 usually).
# Vector: Write SSH keys / Web Shells via CONFIG SET dir/dbfilename.

async def check_redis(session, url):
    # Redis uses a raw TCP protocol, not HTTP.
    # However, if we are strictly HTTP based, we look for:
    # 1. Webshells already planted? (Not useful for discovery)
    # 2. SSRF to Redis? (Complex)
    # 3. HTTP-to-Redis bridge?
    
    # Realistically, for this tool's scope (mostly HTTP), scanning RAW Redis on the same host requires socket connection.
    # I will implement a TCP check for the default Redis port (6379) on the target host.
    
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = 6379 
    
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
        
        # Send INFO command
        writer.write(b"INFO\r\n")
        await writer.drain()
        
        data = await asyncio.wait_for(reader.read(1024), timeout=3)
        response = data.decode('utf-8', errors='ignore')
        
        writer.close()
        await writer.wait_closed()

        if "redis_version" in response:
             return {
                "url": f"{host}:{port}",
                "type": "Redis Unauthenticated Access",
                "evidence": "Redis INFO command successful. RCE possible."
            }
        elif "NOAUTH" in response:
             return {
                "url": f"{host}:{port}",
                "type": "Redis Auth Required",
                "evidence": "Service detected but password protected."
            }

    except Exception:
        pass
    return None

async def scan_redis(session, url):
    """
    Scan for Redis Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Redis Scanner ---[/bold cyan]")
    
    results = []
    res = await check_redis(session, url)
    if res:
         console.print(f"  [bold red][!] REDIS EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No exposed Redis service found on default port.[/dim]")
        
    return results
