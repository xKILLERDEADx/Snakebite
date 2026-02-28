import asyncio
from modules.core import console

# JBoss/WildFly Scanner (JMX RCE)
# Focus: Exposed Management Interfaces.
# Vulnerability: Unauthenticated JMX Console allows deploying WAR files (RCE).
# Endpoints: /jmx-console, /web-console, /management

async def check_jboss(session, url):
    paths = [
        "/jmx-console/",
        "/web-console/",
        "/management"
    ]
    
    found = []
    
    for path in paths:
        target = f"{url.rstrip('/')}{path}"
        try:
            async with session.get(target, timeout=5, ssl=False) as resp:
                if resp.status == 200 or resp.status == 401:
                    # 401 means it exists but is protected (still good info)
                    # 200 means CRITICAL (Unauth Access)
                    
                    status_msg = "Exposed"
                    if resp.status == 401:
                        status_msg = "Protected (Auth Required)"
                    elif resp.status == 200:
                        status_msg = "VULNERABLE (Unauthenticated Access)"
                        
                        # Extra check for JBoss text
                        text = await resp.text()
                        if "JBoss" in text or "WildFly" in text or "Management" in text:
                             found.append({
                                "url": target,
                                "type": f"JBoss/WildFly Interface {status_msg}",
                                "evidence": f"Found {path} returning {resp.status}"
                            })
        except Exception:
             pass
             
    if found:
        return found[0] # Return finding
    return None

async def scan_jboss(session, url):
    """
    Scan for JBoss/WildFly Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- JBoss/WildFly Scanner ---[/bold cyan]")
    
    results = []
    res = await check_jboss(session, url)
    if res:
         console.print(f"  [bold red][!] JBOSS INTERFACE FOUND: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No JBoss/WildFly interfaces found.[/dim]")
        
    return results
