import asyncio
from modules.core import console

# Docker API Scanner (Host Takeover)
# Focus: Exposed Docker Socket / API (Port 2375/2376).
# Vector: /version or /containers/json

async def check_docker(session, url):
    # Check default port 2375 (Unencrypted Docker Socket)
    # We can try HTTP request to http://HOST:2375/version
    
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    
    target = f"http://{host}:2375/version"
    
    try:
        async with session.get(target, timeout=3, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                if "ApiVersion" in text or "Arch" in text or "GoVersion" in text:
                     return {
                        "url": target,
                        "type": "Docker API Exposed (Root Access)",
                        "evidence": "Docker /version accessible unauthenticated."
                    }
    except Exception:
        pass
        
    # Also check /containers/json
    try:
        target_c = f"http://{host}:2375/containers/json"
        async with session.get(target_c, timeout=3, ssl=False) as resp:
             if resp.status == 200 and "Image" in await resp.text():
                  return {
                        "url": target_c,
                        "type": "Docker API Exposed (Root Access)",
                        "evidence": "Container list accessible."
                    }
    except Exception:
        pass
        
    return None

async def scan_docker(session, url):
    """
    Scan for Exposed Docker API.
    """
    console.print(f"\n[bold cyan]--- Docker API Scanner ---[/bold cyan]")
    
    results = []
    res = await check_docker(session, url)
    if res:
         console.print(f"  [bold red][!] DOCKER API EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No exposed Docker API found on port 2375.[/dim]")
        
    return results
