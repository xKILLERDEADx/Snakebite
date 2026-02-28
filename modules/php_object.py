import asyncio
import re
from modules.core import console

# PHP Object Injection
# Look for serialized data in params or cookies: e.g. O:4:"User":2:{...}
# If found, it indicates deserialization might be happening.

SERIALIZED_PATTERN = r'O:\d+:"[a-zA-Z0-9_]+":\d+:{'

async def check_php_object(session, url, param=None, cookie=None):
    # This is primarily a passive scan (looking for the pattern)
    # followed by an active probe if found.
    
    try:
        if param:
            target = f"{url}?{param}=O:8:\"SnakeBite\":0:{{}}" # Simple probe
            if "?" in url: target = f"{url}&{param}=O:8:\"SnakeBite\":0:{{}}"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                if "SnakeBite" in text and ("unserialize()" in text or "object" in text.lower()):
                     return {
                         "url": target,
                         "param": param,
                         "type": "PHP Object Injection (Likely)",
                         "evidence": "Serialized payload accepted/reflected"
                     }
        
        # Check Cookies (Passive primarily)
        # We need to see the Set-Cookie headers from a normal request first.
        # But this module is structured as an active scanner.
        # We'll just define the param probe for now.
        
    except Exception:
        pass
    return None

async def scan_php_object(session, url):
    """
    Scan for PHP Object Injection (Deserialization).
    """
    console.print(f"\n[bold cyan]--- PHP Object Injection Scanner ---[/bold cyan]")
    
    # Check params that often hold state
    params = ["data", "state", "user", "session", "cookie", "token", "auth"]
    
    tasks = [check_php_object(session, url, param=p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    
    # Also Check Response Body for Serialized Strings (Passive)
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            matches = re.findall(SERIALIZED_PATTERN, text)
            if matches:
                console.print(f"  [bold yellow][!] SERIALIZED PHP DATA FOUND IN RESPONSE[/bold yellow]")
                console.print(f"      Pattern: {matches[0]}...")
                found.append({"url": url, "type": "Serialized Data Leak", "evidence": matches[0]})
    except Exception:
        pass
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] PHP OBJECT INJECTION INDICATED: {res['param']}[/bold red]")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No PHP serialization indicators found.[/dim]")
        
    return found
