import asyncio
import json
from modules.core import console

# Indicators of internal/private packages that might be claimed publicly
INTERNAL_KEYWORDS = ["internal", "private", "corp", "dev", "local", "test", "my-", "our-"]

async def check_dependencies(session, url, file_type):
    target = f"{url.rstrip('/')}/{file_type}" # package.json / requirements.txt
    
    try:
        async with session.get(target, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                
                vulns = []
                packages = []
                
                if file_type == "package.json":
                    try:
                        data = json.loads(text)
                        # Check dependencies and devDependencies
                        deps = data.get("dependencies", {})
                        devDeps = data.get("devDependencies", {})
                        packages.extend(deps.keys())
                        packages.extend(devDeps.keys())
                    except Exception:
                        pass
                elif file_type == "requirements.txt":
                    # Parse lines
                    lines = text.splitlines()
                    for line in lines:
                        if line and not line.startswith("#"):
                            pkg = line.split("==")[0].split(">=")[0].strip()
                            packages.append(pkg)
                            
                # Analyze packages
                for pkg in packages:
                    # Heuristic: Does it look like an internal package?
                    # 1. Scoped packages @company/pkg are safer usually but still checkable
                    # 2. Key words
                    is_suspicious = False
                    if "@" in pkg and "/" in pkg:
                         # Scoped: e.g. @mycorp/utils
                         # Could be public (e.g. @angular/core) or private
                         is_suspicious = True # Worth flagging for manual review
                         
                    for kw in INTERNAL_KEYWORDS:
                        if kw in pkg:
                            is_suspicious = True
                            
                    if is_suspicious:
                         vulns.append({
                             "url": target,
                             "package": pkg,
                             "type": "Dependency Confusion (Potential)",
                             "details": "Internal-sounding package name found exposed."
                         })
                         
                return vulns
    except Exception:
        pass
    return None

async def scan_dependencies(session, url):
    """
    Scan for Supply Chain / Dependency Risks.
    """
    console.print(f"\n[bold cyan]--- Dependency Confusion Scanner ---[/bold cyan]")
    
    tasks = [
        check_dependencies(session, url, "package.json"),
        check_dependencies(session, url, "requirements.txt"),
        check_dependencies(session, url, "composer.json") # PHP
    ]
    
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             for v in res:
                 console.print(f"  [bold red][!] SUPPLY CHAIN RISK: {v['package']}[/bold red]")
                 console.print(f"      Source: {v['url']}")
                 found.append(v)
             
    if not found:
        console.print("[dim][-] No exposed dependency files found.[/dim]")
        
    return found
