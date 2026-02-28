import asyncio
from modules.core import console

# Client-Side Prototype Pollution
# Vulnerability: URL parsers merge query params into objects recursively.
# Attackers inject properties into Object.prototype, affecting all objects in the app.
# Payload: ?__proto__[polluted]=true
# Detection: In a real browser, we'd check window.polluted.
# In HTTP client, we check if the frame/code reflects this weird structure or errors out differently.

async def check_proto_client(session, url):
    try:
        # Payload
        # We try to inject a recognizable property.
        # Since we can't execute JS, we look for:
        # 1. Reflection of the payload in a JS block (e.g. var config = {...})
        # 2. Errors suggesting something broke.
        
        target = f"{url}?__proto__[snakebite]=true&constructor[prototype][snakebite]=true"
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # If the application blindly reflects query params into a JSON or JS object
            # e.g. var init = {"__proto__": {"snakebite": "true"}}
            # This indicates vulnerability possibility.
            
            if '"__proto__":' in text or "'__proto__':" in text:
                 return {
                    "url": target,
                    "type": "Prototype Pollution (Reflection)",
                    "evidence": "Reflection of __proto__ key in response (Gadget Risk)"
                }
            
            if "snakebite" in text and ("prototype" in text or "__proto__" in text):
                 return {
                    "url": target,
                    "type": "Prototype Pollution (Reflection)",
                    "evidence": "Reflection of prototype poisoning payload"
                }

    except Exception:
        pass
    return None

async def scan_proto_client(session, url):
    """
    Scan for Client-Side Prototype Pollution.
    """
    console.print(f"\n[bold cyan]--- Client-Side Prototype Pollution ---[/bold cyan]")
    
    results = []
    res = await check_proto_client(session, url)
    
    if res:
         console.print(f"  [bold red][!] PROTOTYPE POLLUTION VECTOR: {res['url']}[/bold red]")
         console.print(f"      Evidence: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Proto Pollution reflection found.[/dim]")
        
    return results
