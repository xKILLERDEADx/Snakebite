import asyncio
from modules.core import console

REDIRECT_PAYLOADS = [
    "http://example.com",
    "//example.com",
    "https://google.com",
    "javascript:alert(1)"
]

async def test_redirect_url(session, url, param, payload):
    target = url.replace(f"{param}=", f"{param}={payload}")
    try:
        # Don't follow redirects automatically, check the Location header
        async with session.get(target, timeout=5, allow_redirects=False) as resp:
            if resp.status in [301, 302, 307]:
                location = resp.headers.get("Location", "")
                if payload in location or (payload.startswith("//") and location.startswith("http:")):
                     return {
                         "url": target,
                         "param": param,
                         "payload": payload,
                         "redirect_to": location
                     }
    except Exception:
        pass
    return None

async def scan_redirect(session, fuzzable_urls):
    """
    Scan URLs with parameters for Open Redirects.
    """
    console.print(f"\n[bold cyan]--- Open Redirect Scanner ---[/bold cyan]")
    
    if not fuzzable_urls:
         console.print("[yellow][!] No parameters found to fuzz.[/yellow]")
         return []
         
    console.print(f"[dim]Testing {len(fuzzable_urls)} URLs for unsafe redirects...[/dim]")
    
    vulnerable = []
    tasks = []
    
    for url in fuzzable_urls:
        if "=" in url:
            base, qs = url.split("?", 1)
            params = qs.split("&")
            for p in params:
                if "=" in p:
                    key = p.split("=")[0]
                    for payload in REDIRECT_PAYLOADS:
                        tasks.append(test_redirect_url(session, url, key, payload))
                        
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] OPEN REDIRECT FOUND![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Redirects To: {res['redirect_to']}")
             vulnerable.append(res)
             
    if not vulnerable:
        console.print("[green][+] No Open Redirect vulnerabilities detected.[/green]")
        
    return vulnerable
