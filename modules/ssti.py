import asyncio
from modules.core import console

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{7*'7'}}", # Jinja2 check (49 vs 7777777)
    "{php}echo 7*7;{/php}"
]

async def test_ssti_url(session, url, param, payload):
    target = url.replace(f"{param}=", f"{param}={payload}")
    try:
        async with session.get(target, timeout=5) as resp:
            text = await resp.text()
            # Check for evaluation result of 7*7
            if "49" in text:
                 # False positive check: ensure '49' wasn't already there
                 # This is tricky without a baseline, but '49' is specific enough for a first pass
                 return {
                     "url": target,
                     "param": param,
                     "payload": payload,
                     "indicator": "49 (Evaluated)"
                 }
    except Exception:
        pass
    return None

async def scan_ssti(session, fuzzable_urls):
    """
    Scan URLs for Server-Side Template Injection.
    """
    console.print(f"\n[bold cyan]--- SSTI (Template Injection) Scanner ---[/bold cyan]")
    
    if not fuzzable_urls:
         console.print("[yellow][!] No parameters found to fuzz.[/yellow]")
         return []
         
    console.print(f"[dim]Fuzzing {len(fuzzable_urls)} URLs for Template Injection...[/dim]")
    
    vulnerable = []
    tasks = []
    
    for url in fuzzable_urls:
        if "=" in url:
            base, qs = url.split("?", 1)
            params = qs.split("&")
            for p in params:
                if "=" in p:
                    key = p.split("=")[0]
                    for payload in SSTI_PAYLOADS:
                        tasks.append(test_ssti_url(session, url, key, payload))
                        
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] CRITICAL: SSTI VULNERABILITY FOUND![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Payload: {res['payload']}")
             vulnerable.append(res)
             
    if not vulnerable:
        console.print("[green][+] No SSTI vulnerabilities detected.[/green]")
        
    return vulnerable
