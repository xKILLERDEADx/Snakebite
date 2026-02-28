import asyncio
from modules.core import console

# VMware vCenter Scanner (Infrastructure RCE)
# Focus: CVE-2021-21972 (RCE via vROPS plugin) and Exposure.
# Endpoint: /ui/vropspluginui/rest/services/uploadova

async def check_vmware(session, url):
    try:
        # 1. Basic Exposure
        # /ui/ or /vsphere-client/
        basic_url = f"{url.rstrip('/')}/ui/"
        
        async with session.get(basic_url, timeout=5, ssl=False) as resp:
            if "VMware" in await resp.text():
                 pass # Confirmed VMware

        # 2. CVE-2021-21972 (RCE)
        payload_url = f"{url.rstrip('/')}/ui/vropspluginui/rest/services/uploadova"
        
        async with session.get(payload_url, timeout=5, ssl=False) as v_resp:
            # 405 Method Not Allowed means endpoint EXISTS (Vulnerable)
            # 404 means patched/removed.
            if v_resp.status == 405:
                 return {
                    "url": payload_url,
                    "type": "VMware vCenter RCE (CVE-2021-21972)",
                    "evidence": "Endpoint /uploadova returned 405 (Exists & Unauthorized)."
                }
            elif v_resp.status == 200:
                 return {
                    "url": payload_url,
                    "type": "VMware vCenter RCE (Critical)",
                    "evidence": "Endpoint accessible (200 OK)."
                }

    except Exception:
        pass
    return None

async def scan_vmware(session, url):
    """
    Scan for VMware vCenter Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- VMware vCenter Scanner ---[/bold cyan]")
    
    results = []
    res = await check_vmware(session, url)
    if res:
         console.print(f"  [bold red][!] VMWARE VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No VMware RCE vectors found.[/dim]")
        
    return results
