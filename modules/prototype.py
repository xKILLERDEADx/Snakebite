import asyncio
from modules.core import console

PROTO_PAYLOADS = [
    "__proto__[test]=polluted",
    "constructor[prototype][test]=polluted"
]

async def test_proto_url(session, url, param, payload):
    target = url.replace(f"{param}=", f"{param}={payload}")
    try:
        async with session.get(target, timeout=5) as resp:
            text = await resp.text()
            # Simple reflection check for now. 
            # Advanced check requires checking if 'polluted' property appears in subsequent unrelated object dumps, 
            # which is hard in blackbox. We check if the injection reflects in a way that suggests processing.
            if "polluted" in text:
                 # Heuristic: If we sent `__proto__[test]=polluted` and see `test` or `polluted` inside a JSON structure
                 # it might just be reflection. True confirmation is complex.
                 # We'll flag it as "Potential" if the server responds 200 and reflects it.
                 return {
                     "url": target,
                     "param": param,
                     "payload": payload,
                     "indicator": "Reflection (Potential Pollution)"
                 }
    except Exception:
        pass
    return None

async def scan_prototype(session, fuzzable_urls):
    """
    Scan URLs for Prototype Pollution.
    """
    console.print(f"\n[bold cyan]--- Prototype Pollution (NodeJS) Scanner ---[/bold cyan]")
    
    if not fuzzable_urls:
         console.print("[yellow][!] No parameters found to fuzz.[/yellow]")
         return []
         
    console.print(f"[dim]Fuzzing {len(fuzzable_urls)} URLs for Prototype Injection...[/dim]")
    
    vulnerable = []
    tasks = []
    
    for url in fuzzable_urls:
        if "=" in url:
            base, qs = url.split("?", 1)
            params = qs.split("&")
            for p in params:
                if "=" in p:
                    key = p.split("=")[0]
                    for payload in PROTO_PAYLOADS:
                        tasks.append(test_proto_url(session, url, key, payload))
                        
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] POTENTIAL PROTOTYPE POLLUTION![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Payload: {res['payload']}")
             vulnerable.append(res)
             
    if not vulnerable:
        console.print("[green][+] No Prototype Pollution indicators found.[/green]")
        
    return vulnerable
