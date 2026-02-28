import asyncio
from modules.core import console

# Zabbix Scanner (Auth Bypass)
# Focus: CVE-2022-23131 (SAML Auth Bypass).
# Vector: Manipulate zbx_session cookie on SAML-enabled instances.

async def check_zabbix(session, url):
    try:
        # Check if Zabbix is present
        # /zabbix/ or root
        
        target = f"{url.rstrip('/')}/index_sso.php" # SAML endpoint usually
        
        # We look for the presence of SAML configuration behavior.
        # CVE-2022-23131 requires SAML to be configured.
        # If we send a request and get a session cookie, we might analyze it.
        # But a simpler check is often just checking if the SSO endpoint exists and behaves like Zabbix.
        
        async with session.get(target, timeout=5, ssl=False) as resp:
             headers = resp.headers
             if resp.status == 200 or resp.status == 302:
                 # Check for Zabbix specific headers or cookies
                 if "zbx_session" in headers.get("Set-Cookie", ""):
                      return {
                        "url": target,
                        "type": "Zabbix Exposed (Potential SAML Bypass)",
                        "evidence": "Zabbix SSO endpoint found with zbx_session cookie."
                    }
        
    except Exception:
        pass
    return None

async def scan_zabbix(session, url):
    """
    Scan for Zabbix Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Zabbix Scanner ---[/bold cyan]")
    
    results = []
    res = await check_zabbix(session, url)
    if res:
         console.print(f"  [bold red][!] ZABBIX FOUND: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Zabbix SSO endpoint found.[/dim]")
        
    return results
