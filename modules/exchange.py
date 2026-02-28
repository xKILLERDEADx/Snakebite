import asyncio
from modules.core import console

# Microsoft Exchange Scanner (Mail Server RCE)
# Focus: ProxyLogon (CVE-2021-26855) and ProxyShell (CVE-2021-34473).
# Impact: Pre-auth RCE / Mailbox Access.

async def check_exchange(session, url):
    try:
        # 1. Basic OWA Check
        owa_url = f"{url.rstrip('/')}/owa/auth.owa"
        async with session.get(owa_url, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                pass # Exchange exists.

        # 2. ProxyLogon (CVE-2021-26855)
        # Bypasses auth via cookie: X-AnonResource=true; X-BEResource=localhost/owa/auth/Logon.aspx
        # We just check if the initial SSRF path is accessible or generates valid FQDN leakage
        
        pl_url = f"{url.rstrip('/')}/owa/auth/Current/themes/resources/logon.css"
        headers = {
            "Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/Current/themes/resources/logon.css"
        }
        
        # A 200 OK on this generally just means CSS found, unless we can abuse the SSRF.
        # Better simple check: /ecp/xx.js (ProxyLogon Indicator)
        
        # ProxyShell is easier to fingerprint via the autodiscover path being open/weird.
        # Path: /autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com
        
        ps_url = f"{url.rstrip('/')}/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com"
        
        async with session.get(ps_url, timeout=5, ssl=False) as ps_resp:
            # If vulnerable to ProxyShell, this often returns a 200 or 302 related to OWA login but Bypassed,
            # or a specific detailed error rather than 400/404.
            # A stock exchange returns 400/404 for this garbage path.
            # Vulnerable ones might process it.
            
            if ps_resp.status in [200, 302] and "Exchange" in ps_resp.headers.get("X-Powered-By", ""):
                 return {
                    "url": ps_url,
                    "type": "Exchange ProxyShell (Likely Vulnerable)",
                    "evidence": f"Path accepted with status {ps_resp.status}."
                }

        # Header Check for Version
        async with session.get(f"{url.rstrip('/')}/owa/", timeout=5, ssl=False) as ver_resp:
             if "X-FEServer" in ver_resp.headers:
                 return {
                    "url": f"{url.rstrip('/')}/owa/",
                    "type": "Exchange Server Exposed",
                    "evidence": f"X-FEServer: {ver_resp.headers['X-FEServer']}"
                }

    except Exception:
        pass
    return None

async def scan_exchange(session, url):
    """
    Scan for Microsoft Exchange Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Microsoft Exchange Scanner ---[/bold cyan]")
    
    results = []
    res = await check_exchange(session, url)
    if res:
         console.print(f"  [bold red][!] EXCHANGE SERVER FOUND: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']} - {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No critical Exchange indicators found.[/dim]")
        
    return results
