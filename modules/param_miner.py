import asyncio
from modules.core import console

# Common debug/hidden parameters
HIDDEN_PARAMS = [
    "debug", "test", "admin", "admin_mode", "impersonate",
    "prompt", "source", "show", "user_id", "role", "access",
    "log", "redirect", "url", "func", "cmd", "exec"
]

async def check_param(session, url, param):
    try:
        # Measure baseline first? Ideally yes. 
        # But here we just append ?param=1 and see if content drastically changes or length changes.
        
        # Simple heuristic: If response size or status differs from base request.
        # This is noisy without a baseline comparison.
        # We will look for explicit errors or debug output in text.
        
        target = f"{url}?{param}=1"
        if "?" in url: target = f"{url}&{param}=1"
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # Checks
            if "debug" in text.lower() and len(text) > 500: # "debug" word might appear naturally
                 return {
                     "url": target,
                     "param": param,
                     "type": "Debug Output Detected"
                 }
            
            if "stack trace" in text.lower() or "exception" in text.lower():
                 return {
                     "url": target,
                     "param": param,
                     "type": "Error/Stack Trace Triggered"
                 }

            # If status changes (e.g. 200 -> 500 or 403 -> 200)
            # Hard to know base status here without re-requesting base every time.
            # We skip this for speed unless we do a base check once.
            
    except Exception:
        pass
    return None

async def scan_param_miner(session, url):
    """
    Scan for Hidden/Debug Parameters.
    """
    console.print(f"\n[bold cyan]--- Hidden Parameter Miner ---[/bold cyan]")
    
    tasks = [check_param(session, url, p) for p in HIDDEN_PARAMS]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold yellow][!] POTENTIAL HIDDEN PARAM: {res['param']}[/bold yellow]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No obvious hidden parameters detected.[/dim]")
        
    return found
