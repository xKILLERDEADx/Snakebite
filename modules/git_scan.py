import asyncio
from modules.core import console

async def check_git(session, url):
    # Standard check: Try to read .git/HEAD
    target = f"{url.rstrip('/')}/.git/HEAD"
    config_target = f"{url.rstrip('/')}/.git/config"
    
    try:
        # Check HEAD
        async with session.get(target, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                content = await resp.text()
                # HEAD usually contains "ref: refs/heads/master" or similar
                if "ref: refs/" in content:
                    return {
                        "url": target,
                        "type": "Source Code Exposure (.git/HEAD)",
                        "evidence": content.strip()[:50]
                    }
                    
        # Double check with config if HEAD fails or for more info
        async with session.get(config_target, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                content = await resp.text()
                if "[core]" in content and "repositoryformatversion" in content:
                     return {
                        "url": config_target,
                        "type": "Source Code Exposure (.git/config)",
                        "evidence": "Valid git config found"
                    }
    except Exception:
        pass
    return None

async def scan_git_exposure(session, urls):
    """
    Scan for Exposed .git Repositories.
    """
    console.print(f"\n[bold cyan]--- Git Exposure Scanner ---[/bold cyan]")
    
    # We mainly care about the root URL or base directories found
    # Checking every single page for /.git/ is redundant if they share a root
    # But for safety, we check unique bases.
    
    bases = set()
    for u in urls:
        # Extract base e.g. http://site.com/app/v1 -> http://site.com/app/
        if u.count("/") > 2:
             parts = u.split("/")
             # potential bases: root, subdirs
             bases.add(f"{parts[0]}//{parts[2]}") # root
             # If there are subdirs, maybe check them too? usually .git is at root.
    
    if not bases: bases = {urls[0]} if urls else set()
    
    console.print(f"[dim]Checking {len(bases)} unique base locations for .git...[/dim]")
    
    tasks = [check_git(session, base) for base in bases]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] CRITICAL: GIT REPOSITORY EXPOSED![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Evidence: {res['evidence']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No exposed .git repositories found.[/green]")
        
    return vulns
