import asyncio
import base64
from modules.core import console

# Apache Tomcat Scanner (Server RCE)
# Focus: Manager App exposure (/manager/html) and Default Creds.
# Valid Creds -> WAR Upload -> RCE.

TOMCAT_CREDS = [
    ("tomcat", "tomcat"),
    ("admin", "admin"),
    ("root", "root"),
    ("role1", "role1"),
    ("both", "tomcat"),
    ("tomcat", "s3cret")
]

async def check_tomcat(session, url):
    try:
        manager_url = f"{url.rstrip('/')}/manager/html"
        
        # 1. Check Existence
        async with session.get(manager_url, timeout=5, ssl=False) as resp:
            if resp.status == 404:
                return None
            # 401 Unauthorized means it exists!
            if resp.status == 401:
                pass # Proceed to bruteforce
            elif resp.status == 200:
                 return {
                    "url": manager_url,
                    "type": "Tomcat Manager Exposed (No Auth?)",
                    "evidence": "Access to /manager/html 200 OK without creds."
                }
        
        # 2. Bruteforce
        for user, password in TOMCAT_CREDS:
            creds = f"{user}:{password}"
            b64_creds = base64.b64encode(creds.encode()).decode()
            headers = {"Authorization": f"Basic {b64_creds}"}
            
            async with session.get(manager_url, headers=headers, timeout=3, ssl=False) as resp:
                if resp.status == 200:
                     return {
                        "url": manager_url,
                        "type": "Tomcat Weak Credentials",
                        "evidence": f"Logged in with {user}:{password}"
                    }

    except Exception:
        pass
    return None

async def scan_tomcat(session, url):
    """
    Scan for Tomcat Manager RCE.
    """
    console.print(f"\n[bold cyan]--- Tomcat Scanner ---[/bold cyan]")
    
    results = []
    res = await check_tomcat(session, url)
    if res:
         console.print(f"  [bold red][!] TOMCAT COMPROMISED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No open Tomcat Manager or default creds found.[/dim]")
        
    return results
