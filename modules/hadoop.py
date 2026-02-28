import asyncio
from modules.core import console

# Hadoop YARN Scanner (Cluster RCE)
# Focus: Unauthenticated REST API in Resource Manager.
# Endpoint: /ws/v1/cluster/apps/new-application
# Risk: RCE by submitting malicious job.

async def check_hadoop(session, url):
    # Standard YARN UI Port is 8088. If scanning base URL, we check /ws/v1/cluster/info
    
    target_info = f"{url.rstrip('/')}/ws/v1/cluster/info"
    
    try:
        async with session.get(target_info, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                if "clusterInfo" in data:
                     # YARN is Present and API is accessible.
                     # Check if we can start a new app (Auth check)
                     target_new = f"{url.rstrip('/')}/ws/v1/cluster/apps/new-application"
                     
                     async with session.post(target_new, timeout=5, ssl=False) as resp_new:
                         if resp_new.status == 200:
                             return {
                                "url": target_new,
                                "type": "Hadoop YARN RCE (Unauthenticated API)",
                                "evidence": "Successfully requested 'new-application'. Cluster is wide open."
                            }
                         else:
                              return {
                                "url": target_info,
                                "type": "Hadoop YARN Exposed",
                                "evidence": "Cluster info accessible, but submission blocked."
                            }
    except Exception:
        pass
    return None

async def scan_hadoop(session, url):
    """
    Scan for Hadoop YARN Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Hadoop YARN Scanner ---[/bold cyan]")
    
    results = []
    res = await check_hadoop(session, url)
    if res:
         console.print(f"  [bold red][!] HADOOP YARN EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Hadoop YARN API found.[/dim]")
        
    return results
