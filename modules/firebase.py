import asyncio
from modules.core import console

# Firebase Scanner (Cloud Databases)
# Focus: Open Realtime Databases.
# Method: https://<project-id>.firebaseio.com/.json
# We try to guess Project ID from the hostname.

async def check_firebase(session, name):
    try:
        target = f"https://{name}.firebaseio.com/.json"
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            # 200 OK means Open
            # 401 Unauthorized means Locked
            # 404 Not Found means name is wrong or DB doesn't exist
            
            if resp.status == 200:
                text = await resp.text()
                # Check if it looks like data
                if text.strip().startswith("{"):
                     preview = text[:100].replace("\n", " ")
                     return {
                        "url": target,
                        "type": "Open Firebase DB",
                        "evidence": f"Data accessible: {preview}..."
                    }
            elif resp.status == 401:
                # It exists but is secure.
                pass
                
    except Exception:
        pass
    return None

async def scan_firebase(session, url):
    """
    Scan for Open Firebase Databases.
    """
    console.print(f"\n[bold cyan]--- Firebase Scanner ---[/bold cyan]")
    
    # Extract names from URL
    # e.g. https://my-app.com -> my-app
    # e.g. https://staging.uber.com -> uber, staging-uber
    
    names = []
    domain = url.split("://")[-1].split("/")[0] # site.com
    
    # Heuristics for project names
    parts = domain.split(".")
    if len(parts) >= 2:
        names.append(parts[0]) # sub
        names.append(parts[-2]) # domain
        names.append(f"{parts[0]}-{parts[-2]}") # sub-domain
        names.append(domain.replace(".", "-"))
    
    tasks = [check_firebase(session, n) for n in set(names) if n]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] OPEN FIREBASE DB: {res['url']}[/bold red]")
             console.print(f"      Evidence: {res['evidence']}")
             found.append(res)
             
    if not found:
        console.print(f"[dim][-] No open Firebase databases found for derived names {names}.[/dim]")
        
    return found
