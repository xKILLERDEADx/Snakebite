import asyncio
from modules.core import console

# Gitea Scanner (Git Service RCE)
# Focus: Gitea instances.
# Vulnerability: CVE-2022-30781 (RCE via Repo Migration) and general version exposure.

async def check_gitea(session, url):
    try:
        # Check for Gitea footer or meta
        target = url.rstrip('/')
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            is_gitea = False
            version = "Unknown"
            
            if "Powered by Gitea" in text or 'content="Gitea' in text:
                is_gitea = True
                
            # Try API for version
            # /api/v1/version
            api_target = f"{target}/api/v1/version"
            async with session.get(api_target, timeout=5, ssl=False) as api_resp:
                if api_resp.status == 200:
                    api_data = await api_resp.json()
                    if "version" in api_data:
                         version = api_data["version"]
                         is_gitea = True
            
            if is_gitea:
                 # Check for vulnerable versions for CVE-2022-30781
                 # Vulnerable: < 1.16.8
                 
                 evidence = f"Gitea Version: {version}"
                 vuln_type = "Gitea Instance Detected"
                 
                 # Basic semantic version check (very simple)
                 # 1.16.0 -> vulnerable
                 if version != "Unknown":
                     try:
                         # Strip prefixes like 'v'
                         v_clean = version.lstrip('v').split('.')
                         if len(v_clean) >= 2:
                             major = int(v_clean[0])
                             minor = int(v_clean[1])
                             if major == 1 and minor < 16:
                                 evidence += " (VULNERABLE to CVE-2022-30781 RCE)"
                                 vuln_type = "Gitea RCE (CVE-2022-30781)"
                     except Exception:
                         pass

                 return {
                    "url": target,
                    "type": vuln_type,
                    "evidence": evidence
                }

    except Exception:
        pass
    return None

async def scan_gitea(session, url):
    """
    Scan for Gitea Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Gitea Scanner ---[/bold cyan]")
    
    results = []
    res = await check_gitea(session, url)
    if res:
         console.print(f"  [bold red][!] GITEA FOUND: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Gitea instance found.[/dim]")
        
    return results
