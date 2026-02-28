import asyncio
from modules.core import console

# Jenkins Scanner (DevOps Exposure)
# Focus: Unauthenticated Jenkins instances, Script Console (RCE).
# Paths: /jenkins/, /ci/, /script, /login

JENKINS_PATHS = [
    "/", "/jenkins/", "/ci/", "/job/", 
    "/script", # Critical RCE
    "/manage",
    "/view/All/newJob"
]

async def check_jenkins(session, url):
    try:
        # Check if Jenkins is running
        # Header: X-Jenkins or header "Server: Jenkins" or html body "Dashboard [Jenkins]"
        
        async with session.get(url, timeout=5, ssl=False) as resp:
            is_jenkins = False
            version = resp.headers.get("X-Jenkins", "Unknown")
            if "X-Jenkins" in resp.headers:
                is_jenkins = True
                
            text = await resp.text()
            if "Dashboard [Jenkins]" in text or "Remember me on this computer" in text:
                 is_jenkins = True
                 
            if is_jenkins:
                 # Check for critical access
                 # If we can see /script, it's game over.
                 script_access = False
                 async with session.get(f"{url.rstrip('/')}/script", timeout=5, ssl=False) as script_resp:
                      if script_resp.status == 200 and "println" in await script_resp.text():
                           script_access = True
                 
                 findings = []
                 findings.append(f"Jenkins Instance Found (Version: {version})")
                 
                 risk = "Medium (Exposure)"
                 if script_access:
                      findings.append("CRITICAL: Groovy Script Console Accessible (RCE)")
                      risk = "Critical (RCE)"
                 elif resp.status == 200 and "login" not in resp.url and "Dashboard" in text:
                      findings.append("Unauthenticated Dashboard Access")
                      risk = "High (Info Leak)"
                 
                 return {
                    "url": url,
                    "type": f"Jenkins ({risk})",
                    "evidence": " | ".join(findings)
                }

    except Exception:
        pass
    return None

async def scan_jenkins(session, url):
    """
    Scan for Jenkins CI Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Jenkins Scanner ---[/bold cyan]")
    
    # Create potential paths
    base_url = url.rstrip("/")
    targets = [base_url]
    for p in ["/jenkins", "/ci", "/server"]:
        targets.append(base_url + p)
        
    tasks = [check_jenkins(session, t) for t in targets]
    results = await asyncio.gather(*tasks)
    
    found = []
    # Deduplicate by findings
    seen_evidence = set()
    
    for res in results:
        if res and res['evidence'] not in seen_evidence:
             seen_evidence.add(res['evidence'])
             console.print(f"  [bold red][!] JENKINS FOUND: {res['url']}[/bold red]")
             console.print(f"      Status: {res['evidence']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No Jenkins instances detected.[/dim]")
        
    return found
