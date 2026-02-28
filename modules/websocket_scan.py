import asyncio
import aiohttp
from modules.core import console

# Note: aiohttp has websocket support.
# CSWSH Check: Can we connect with a malicious Origin?

async def check_websocket(session, url):
    # Convert http/https to ws/wss
    ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
    
    # We attempt to connect with a fake Origin
    headers = {"Origin": "https://evil.com"}
    
    try:
        # aiohttp.ClientSession.ws_connect
        async with session.ws_connect(ws_url, headers=headers, timeout=5, ssl=False) as ws:
            # If we connected successfully, it MIGHT be vulnerable if it didn't check Origin.
            # We send a ping or small msg
            await ws.ping()
            
            # If we stay connected without immediate closure (403), it's a finding.
            # Ideally the server should reject the handshake if Origin is bad.
            
            return {
                "url": ws_url,
                "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                "evidence": "Connected with Origin: https://evil.com"
            }
    except Exception as e:
        # Connection failed or rejected (Good)
        pass
    return None

async def scan_websocket(session, urls):
    """
    Scan for WebSocket Vulnerabilities (CSWSH).
    """
    console.print(f"\n[bold cyan]--- WebSocket Scanner ---[/bold cyan]")
    
    # Identify potential WS endpoints.
    # Usually hard to guess, but we check if any crawled URL was a WS or if main URL upgrades.
    # For now, we test the main URL and any explicit ws:// links found (unlikely in http crawl).
    # We will try to upgrade the main Base URL.
    
    targets = set()
    # Try base URL
    targets.add(urls[0] if urls else "http://example.com") 
    
    # Scan crawled for "chat", "socket", "ws" keywords in path
    for u in urls:
        if "chat" in u or "socket" in u or "ws" in u or "notify" in u:
             targets.add(u)
             
    targets = list(targets)[:10]
    
    console.print(f"[dim]Testing {len(targets)} potential WebSocket endpoints...[/dim]")
    
    tasks = [check_websocket(session, u) for u in targets]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] WEBSOCKET HIJACKING POSSIBLE![/bold red]")
             console.print(f"      Endpoint: {res['url']}")
             console.print(f"      Evidence: {res['evidence']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No CSWSH vulnerabilities detected.[/green]")
        
    return vulns
