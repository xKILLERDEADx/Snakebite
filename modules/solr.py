import asyncio
from modules.core import console

# Apache Solr Scanner (Search Engine RCE)
# Focus: Exposed Admin UI and Config API RCE.
# Endpoint: /solr/admin/info/system

async def check_solr(session, url):
    try:
        # Check standard Admin UI
        # /solr/
        
        base_url = f"{url.rstrip('/')}/solr/"
        async with session.get(base_url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "Solr Admin" in text or "Solr Core" in text:
                 pass # Confirmed Solr

        # Check System Info (often open without auth)
        # /solr/admin/info/system
        sys_url = f"{url.rstrip('/')}/solr/admin/info/system"
        async with session.get(sys_url, timeout=5, ssl=False) as s_resp:
            if s_resp.status == 200 and "lucene" in await s_resp.text():
                 return {
                    "url": sys_url,
                    "type": "Apache Solr Admin Exposed",
                    "evidence": "System info accessible. Potential for Config API RCE."
                }

        # Check for Log4j specific to Solr?
        # Solr was a major target for Log4Shell.
        # This is covered by the general log4shell module, but detecting Solr presence helps prioritization.

    except Exception:
        pass
    return None

async def scan_solr(session, url):
    """
    Scan for Apache Solr Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Apache Solr Scanner ---[/bold cyan]")
    
    results = []
    res = await check_solr(session, url)
    if res:
         console.print(f"  [bold red][!] SOLR EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Solr Admin endpoints found.[/dim]")
        
    return results
