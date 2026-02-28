import asyncio
from modules.core import console

# SonarQube Scanner (Code Leak)
# Focus: Publicly exposed projects and source code.
# Endpoint: /api/components/search_projects, /api/sources/raw

async def check_sonarqube(session, url):
    try:
        # Check API access
        api_url = f"{url.rstrip('/')}/api/system/status"
        
        async with session.get(api_url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "SonarQube" in text or "sonarqube" in text or '"status":' in text:
                pass # API likely exists
                
        # Check for Public Projects
        projects_url = f"{url.rstrip('/')}/api/components/search_projects"
        async with session.get(projects_url, timeout=5, ssl=False) as p_resp:
            p_text = await p_resp.text()
            if '"components":[' in p_text:
                 # We found public projects.
                 # Parse one to show evidence?
                 count = p_text.count('"key":')
                 return {
                    "url": projects_url,
                    "type": "SonarQube: Public Projects Exposed",
                    "evidence": f"Found {count} accessible components/projects."
                }
            elif p_resp.status == 401:
                 return {
                    "url": projects_url,
                    "type": "SonarQube Login Page",
                    "evidence": "Auth required (Standard)."
                }

    except Exception:
        pass
    return None

async def scan_sonarqube(session, url):
    """
    Scan for SonarQube Exposures.
    """
    console.print(f"\n[bold cyan]--- SonarQube Scanner ---[/bold cyan]")
    
    results = []
    res = await check_sonarqube(session, url)
    if res:
         console.print(f"  [bold red][!] SONARQUBE EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No public SonarQube projects found.[/dim]")
        
    return results
