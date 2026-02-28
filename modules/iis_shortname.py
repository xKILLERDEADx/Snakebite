import asyncio
from modules.core import console

# IIS Shortname Vulnerability (Microsoft IIS)
# Allows enumeration of files by using the ~ character (e.g. A~1.aspx, ADMIN~1.aspx)
# If the server responds differently (e.g. 404 vs 400 vs 200), we know the file prefix exists.

async def check_iis_shortname(session, url, prefix):
    # This is a simplified check. A full exploit requires iterating A-Z at each position.
    # Here we just check common prefixes to demonstrate the vuln.
    
    # Common hidden file prefixes
    target = f"{url.rstrip('/')}/{prefix}~1" 
    
    try:
        # For IIS Shortname, often we look for 404 vs 400/500/200 differences
        # But specifically, a request to *~1 might return 404 if it DOES exist but extension is wrong
        # And something else (like 400 Bad Request) if it doesn't.
        # It varies by IIS version.
        
        # A simple robust check:
        # Try a definitely non-existent prefix: ZZZZZZ~1
        # Try a target prefix: ADMIN~1
        
        # We will iterate a few common starts
        
        target_check = f"{url.rstrip('/')}/{prefix}*~1*/.aspx" # IIS Magic
        
        async with session.get(target_check, timeout=3, ssl=False) as resp:
            # If we get 404, it usually means "File starts with prefix, but .aspx part is wrong" -> FOUND
            # If we get 400/Bad Request, it means "Invalid wildcards" -> NOT FOUND (maybe)
            
            if resp.status == 404:
                 return {
                     "url": url,
                     "prefix": prefix,
                     "type": "IIS Shortname Found"
                 }
    except Exception:
        pass
    return None

async def scan_iis_shortname(session, url):
    """
    Scan for IIS Shortname Enumeration (Hidden Windows Files).
    """
    console.print(f"\n[bold cyan]--- IIS Shortname Scanner ---[/bold cyan]")
    
    # Check if header says IIS?
    # We'll skip that check to be safe and just run.
    
    prefixes = ["ADMIN", "BACKUP", "CONFIG", "SECRET", "DATA", "WEB"]
    
    console.print(f"[dim]Checking for hidden files starting with {', '.join(prefixes)}...[/dim]")
    
    tasks = [check_iis_shortname(session, url, p) for p in prefixes]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold yellow][!] HIDDEN FILE PREFIX FOUND: {res['prefix']}~1[/bold yellow]")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No IIS shortnames found (Server might not be IIS).[/dim]")
        
    return found
