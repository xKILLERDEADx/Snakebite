import asyncio
from modules.core import console

# H2C Smuggling (HTTP/2 Cleartext Upgrade)
# Vulnerability: Some reverse proxies (like HAProxy, Nginx, Traefik in certain configs) 
# allow the 'Upgrade: h2c' header to pass through to the backend.
# The backend then switches to HTTP/2, but the proxy still thinks it's HTTP/1.1.
# This tunnel allows bypassing path-based access controls defined at the proxy level.

async def check_h2c(session, url):
    try:
        # We send a standard HTTP/1.1 request with Upgrade headers
        headers = {
            "Connection": "Upgrade, HTTP2-Settings",
            "Upgrade": "h2c",
            "HTTP2-Settings": "AAMAAABkAAQAAP__", # Empty settings frame base64
        }
        
        async with session.get(url, headers=headers, timeout=5, ssl=False) as resp:
            # If the server responds with "101 Switching Protocols", it supports H2C
            if resp.status == 101:
                 return {
                     "url": url,
                     "status": "VULNERABLE (101 Switching Protocols)",
                     "details": "Server accepted h2c upgrade. Proxy bypass possible."
                 }
            
            # Sometimes it doesn't switch but the header is present in Vary or Allow?
            # Less reliable. 101 is the gold standard here.

    except Exception:
        pass
    return None

async def scan_h2c_smuggler(session, url):
    """
    Scan for H2C Smuggling (HTTP/2 Cleartext Upgrade).
    """
    console.print(f"\n[bold cyan]--- H2C Smuggling Scanner ---[/bold cyan]")
    
    # Check root and maybe a few other paths
    targets = [url]
    if not url.endswith("/"): targets.append(url + "/")
    
    # Also check /admin or /private as those are the targets of this attack
    base = url.rstrip("/")
    targets.append(f"{base}/admin")
    targets.append(f"{base}/internal")
    
    tasks = [check_h2c(session, t) for t in targets]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] H2C SMUGGLING DETECTED: {res['url']}[/bold red]")
             console.print(f"      Details: {res['details']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No H2C upgrade vulnerability detected (101 status not received).[/dim]")
        
    return found
