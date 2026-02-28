import asyncio
from modules.core import console

async def check_idor(session, url, param, original_val):
    if not original_val.isdigit():
        return None
        
    val = int(original_val)
    # Test prev and next
    test_vals = [val - 1, val + 1]
    
    # Get baseline size (original)
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            baseline_len = len(await resp.read())
            baseline_status = resp.status
    except Exception:
        return None

    results = []
    
    for test_val in test_vals:
        if test_val < 0: continue
        target = url.replace(f"{param}={original_val}", f"{param}={test_val}")
        try:
            async with session.get(target, timeout=5, ssl=False) as resp:
                data = await resp.read()
                curr_len = len(data)
                
                # Logic: If status is same (e.g. 200) AND length is similar but not identical (different data?) or identical (static page?)
                # IDOR detection is hard. 
                # If we get 200 OK for ID+1, and length is > 0, it's a "Potential IDOR". 
                # We filter out 404/403.
                if resp.status == 200 and resp.status == baseline_status:
                     # Calculate diff percentage
                     diff = abs(curr_len - baseline_len)
                     if diff > 0: # If content is exactly same, scanning might be static. If different, maybe new data?
                         results.append({
                             "url": target,
                             "param": param,
                             "original": original_val,
                             "fuzzed": str(test_val),
                             "status": resp.status
                         })
        except Exception:
            pass
            
    return results

async def scan_idor(session, fuzzable_urls):
    """
    Scan for IDOR (Insecure Direct Object Reference).
    """
    console.print(f"\n[bold cyan]--- IDOR Detector (Logic Flaw) ---[/bold cyan]")
    
    if not fuzzable_urls:
         console.print("[yellow][!] No parameters found to fuzz.[/yellow]")
         return []
         
    console.print(f"[dim]Analyzing URLs for numeric IDs...[/dim]")
    
    tasks = []
    for url in fuzzable_urls:
        if "?" in url and "=" in url:
            parts = url.split("?")[1].split("&")
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                    if v.isdigit():
                        tasks.append(check_idor(session, url, k, v))
                        
    if not tasks:
         console.print("[yellow][!] No numeric parameters found to test.[/yellow]")
         return []
         
    results_lists = await asyncio.gather(*tasks)
    
    # Flatten
    vulns = []
    for rlist in results_lists:
        if rlist:
            vulns.extend(rlist)
            
    for v in vulns:
         console.print(f"  [bold red][!] POTENTIAL IDOR FOUND![/bold red]")
         console.print(f"      Target: {v['url']}")
         console.print(f"      Param: {v['param']} (Changed {v['original']} -> {v['fuzzed']})")
         
    if not vulns:
        console.print("[green][+] No IDOR patterns detected.[/green]")
        
    return vulns
