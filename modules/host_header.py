import asyncio
from modules.core import console

HOST_PAYLOADS = [
    "evil.com",
    "bing.com",
    "example.com"
]

async def check_host_header(session, url, payload):
    # Method 1: Host header replacement
    try:
        # We need a custom request to override Host, which aiohttp handles a bit strictly
        # But we can try setting the header manually.
        headers = {"Host": payload, "X-Forwarded-Host": payload}
        async with session.get(url, headers=headers, timeout=5, ssl=False, allow_redirects=False) as resp:
            # Check for reflection in Location (Redirect Poisoning)
            if "Location" in resp.headers:
                loc = resp.headers["Location"]
                if payload in loc:
                    return {
                        "url": url,
                        "type": "Host Header Injection (Redirect)",
                        "payload": payload,
                        "evidence": f"Location: {loc}"
                    }
            
            # Check for reflection in Body (Link Poisoning)
            # Only relevant if status is 200/OK usually, but sometimes error pages reflect it too
            text = await resp.text()
            if payload in text:
                 # False positive check: ensure payload wasn't already there? 
                 # Unlikely for 'evil.com' unless the site is evil.com
                 return {
                        "url": url,
                        "type": "Host Header Injection (Reflected)",
                        "payload": payload,
                        "evidence": "Payload found in response body"
                    }
    except Exception:
        pass
    return None

async def scan_host_header(session, url):
    """
    Scan for Host Header Injection.
    """
    console.print(f"\n[bold cyan]--- Host Header Injection Scanner ---[/bold cyan]")
    
    # We test the base URL and maybe a few others
    tasks = []
    
    for payload in HOST_PAYLOADS:
        tasks.append(check_host_header(session, url, payload))
        
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] HOST HEADER INJECTION FOUND![/bold red]")
             console.print(f"      Type: {res['type']}")
             console.print(f"      Evidence: {res['evidence']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No Host Header vulnerabilities detected.[/green]")
        
    return vulns
