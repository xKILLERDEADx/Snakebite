import asyncio
from modules.core import console

# HTTP Parameter Pollution (HPP)
# Vulnerability: Server handles duplicate parameters in unexpected ways.
# e.g. ?id=1&id=2 -> application might see id=1, id=2, id=[1,2], or id=2.
# Usage: WAF Bypass (split payload), Logic Bypass (override hardcoded values).

async def check_hpp(session, url, param):
    try:
        # We test how the server responds to duplicates.
        # Baseline: ?param=original
        # Polluted: ?param=original&param=polluted
        
        target_base = f"{url}?{param}=snakebite_orig"
        target_polluted = f"{url}?{param}=snakebite_orig&{param}=snakebite_polluted"
        
        async with session.get(target_base, timeout=5, ssl=False) as resp_base:
            text_base = await resp_base.text()
            
        async with session.get(target_polluted, timeout=5, ssl=False) as resp_poll:
            text_poll = await resp_poll.text()
            
            # Analysis
            # 1. Reflection: Does it reflect both? "snakebite_orig,snakebite_polluted"
            if "snakebite_orig" in text_poll and "snakebite_polluted" in text_poll:
                 return {
                    "url": target_polluted,
                    "param": param,
                    "behavior": "Concatenation/Both",
                    "evidence": "Server accepts duplicate parameters (potential logic bypass)"
                }
            
            # 2. Override: Does it reflect only the second one?
            if "snakebite_orig" not in text_poll and "snakebite_polluted" in text_poll:
                 return {
                    "url": target_polluted,
                    "param": param,
                    "behavior": "Last Parameter Wins",
                    "evidence": "Second parameter overwrote the first (useful for overriding internal vars)"
                }

    except Exception:
        pass
    return None

async def scan_hpp(session, url):
    """
    Scan for HTTP Parameter Pollution (Logic Bypass).
    """
    console.print(f"\n[bold cyan]--- HPP Scanner (Param Pollution) ---[/bold cyan]")
    
    params = ["id", "user", "role", "action", "auth", "token", "email"]
    
    tasks = [check_hpp(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] HPP BEHAVIOR DETECTED: {res['param']}[/bold red]")
             console.print(f"      Behavior: {res['behavior']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No interesting HPP behavior observed (Server likely strict).[/dim]")
        
    return found
