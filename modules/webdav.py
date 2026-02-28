import asyncio
from modules.core import console

async def check_webdav(session, url):
    try:
        # Check OPTIONS method to see allowed methods
        async with session.options(url, timeout=5, ssl=False) as resp:
            allow_header = resp.headers.get("Allow", "")
            public_header = resp.headers.get("Public", "") # IIS specific
            
            methods = []
            if allow_header: methods.extend(allow_header.upper().replace(" ", "").split(","))
            if public_header: methods.extend(public_header.upper().replace(" ", "").split(","))
            
            methods = list(set(methods))
            
            dangerous = []
            if "PUT" in methods: dangerous.append("PUT")
            if "DELETE" in methods: dangerous.append("DELETE")
            if "PROPFIND" in methods: dangerous.append("PROPFIND (WebDAV)")
            
            if dangerous:
                 return {
                     "url": url,
                     "methods": dangerous,
                     "type": "Dangerous HTTP Methods Enabled"
                 }
                 
        # Active Check: Try to PUT a small file?
        # That's very aggressive and could be considered an attack.
        # We stick to passive OPTIONS check for legality.
        
    except Exception:
        pass
    return None

async def scan_webdav(session, urls):
    """
    Scan for WebDAV / Dangerous HTTP Methods.
    """
    console.print(f"\n[bold cyan]--- WebDAV Scanner ---[/bold cyan]")
    
    # We check the root URL and maybe a few others
    targets = set()
    targets.add(urls[0] if urls else "http://example.com")
    
    # If we found any /uploads/ or /dav/ directories, check those too
    for u in urls:
        if "/uploads" in u or "/dav" in u or "/files" in u:
            targets.add(u)
            
    targets = list(targets)[:5]
    console.print(f"[dim]Checking {len(targets)} endpoints for enabled WebDAV methods...[/dim]")
    
    tasks = [check_webdav(session, u) for u in targets]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] DANGEROUS METHODS: {', '.join(res['methods'])}[/bold red]")
             console.print(f"      URL: {res['url']}")
             found.append(res)
             
    if not found:
        console.print("[green][+] No dangerous methods (PUT/DELETE) detected.[/green]")
        
    return found
