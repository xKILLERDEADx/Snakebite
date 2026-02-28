import asyncio
from modules.core import console

# Spring4Shell Scanner (CVE-2022-22965)
# Vulnerability: Incorrect data binding in Spring MVC allows accessing AccessLogValve via classLoader.
# Attack: Overwriting properties to write a JSP shell.
# Detection: Non-destructive probe. We try to bind to `class.module.classLoader`.
# If the server accepts it (200 OK) or returns a specific error (400 Bad Request with "PropertyReferenceException"), it might be vulnerable.

async def check_spring4shell(session, url):
    try:
        # Probe Payload
        # We try to access a non-existent property on the classloader to trigger a specific error.
        # This confirms we can traverse the graph.
        
        # Valid traversal: class.module.classLoader.DefaultServlet.context.abc
        params = {
            "class.module.classLoader.DefaultServlet.context.abc": "pwn"
        }
        
        # Usually GET or POST with form-data
        async with session.post(url, data=params, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # Indicators
            # 1. 400 Bad Request is common because 'abc' doesn't technically exist, 
            # BUT if the error message says "Invalid property 'abc' of bean class '...ClassLoader'", 
            # IT MEANS WE REACHED THE CLASSLOADER.
            
            if "Invalid property 'abc'" in text and "ClassLoader" in text:
                 return {
                    "url": url,
                    "type": "Spring4Shell (ClassLoader Access)",
                    "evidence": "Error confirmed ClassLoader property access."
                }
                
            # 2. 200 OK
            # If it swallows it without error, it's inconclusive but suspicious for older Spring.
            if resp.status == 200 and "pwn" in text: # Reflection?
                pass

    except Exception:
        pass
    return None

async def scan_spring4shell(session, url):
    """
    Scan for Spring4Shell (CVE-2022-22965).
    """
    console.print(f"\n[bold cyan]--- Spring4Shell Scanner ---[/bold cyan]")
    
    targets = [url]
    # Try creating path variations?
    
    results = []
    res = await check_spring4shell(session, url)
    
    if res:
         console.print(f"  [bold red][!] SPRING4SHELL VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Evidence: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No direct ClassLoader access confirmed.[/dim]")
        
    return results
