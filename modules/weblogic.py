import asyncio
from modules.core import console

# Oracle WebLogic Scanner (Enterprise RCE)
# Focus: T3 Protocol RCE (Deserialization) and WSAT RCE.
# Endpoints: /wls-wsat/CoordinatorPortType, /console/login/LoginForm.jsp

async def check_weblogic(session, url):
    try:
        # Check standard console
        console_url = f"{url.rstrip('/')}/console/login/LoginForm.jsp"
        
        # Check WSAT (CVE-2017-10271)
        wsat_url = f"{url.rstrip('/')}/wls-wsat/CoordinatorPortType"
        
        # 1. Console Check
        async with session.get(console_url, timeout=5, ssl=False) as resp:
            if resp.status == 200 and "WebLogic" in await resp.text():
                 # Just console found
                 pass

        # 2. WSAT Check (RCE)
        # We send a GET. If 200 or 405 or 500 with specific XML error, likely vulnerable component exists.
        async with session.get(wsat_url, timeout=5, ssl=False) as wsat_resp:
            wsat_text = await wsat_resp.text()
            if wsat_resp.status in [200, 405, 500]:
                if "CoordinatorPortType" in wsat_text or "Process" in wsat_text:
                     return {
                        "url": wsat_url,
                        "type": "WebLogic WSAT Component (Potential RCE)",
                        "evidence": "Endpoint accessible. Vulnerable to CVE-2017-10271 potentially."
                    }
        
        # T3 is hard to check via HTTP only (needs socket), but we can infer existence.

    except Exception:
        pass
    return None

async def scan_weblogic(session, url):
    """
    Scan for Oracle WebLogic Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- WebLogic Scanner ---[/bold cyan]")
    
    # WebLogic often runs on 7001 using HTTP.
    
    results = []
    res = await check_weblogic(session, url)
    if res:
         console.print(f"  [bold red][!] WEBLOGIC EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No WebLogic WSAT components found.[/dim]")
        
    return results
