import asyncio
from modules.core import console

# Elasticsearch Scanner (Big Data Leak)
# Focus: Unauthenticated 9200 ports.
# Endpoints: /_cat/indices?v, /_cluster/health

async def check_elastic(session, url):
    try:
        # Standard ES port is 9200, but often behind reverse proxy at 80/443.
        # We assume URL provided is correct base.
        
        target = url
        
        # 1. Check Root
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "You Know, for Search" in text:
                # Confirmed ES
                
                # 2. Check for Indices (Data)
                indices_url = f"{target.rstrip('/')}/_cat/indices?v"
                async with session.get(indices_url, timeout=5, ssl=False) as i_resp:
                    if i_resp.status == 200:
                        data_preview = (await i_resp.text())[:200]
                        return {
                            "url": target,
                            "type": "Open Elasticsearch Cluster",
                            "evidence": f"Root confirmed. Indices accessible: {data_preview}..."
                        }
                    else:
                         return {
                            "url": target,
                            "type": "Elasticsearch Found (Indices Locked)",
                            "evidence": "Root accessible but /_cat/indices returned non-200."
                        }

    except Exception:
        pass
    return None

async def scan_elastic(session, url):
    """
    Scan for Open Elasticsearch Clusters.
    """
    console.print(f"\n[bold cyan]--- Elasticsearch Scanner ---[/bold cyan]")
    
    # If the user provided a standard web URL, we might want to check port 9200 specifically too.
    # checking base URL first.
    
    results = []
    res = await check_elastic(session, url)
    if res:
         console.print(f"  [bold red][!] ELASTICSEARCH EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
    else:
        # Optional: Try port 9200 if not present
        if ":9200" not in url:
            base = url.split("://")[1].split("/")[0] # domain.com
            protocol = url.split("://")[0]
            target_9200 = f"{protocol}://{base}:9200"
            res_9200 = await check_elastic(session, target_9200)
            if res_9200:
                 console.print(f"  [bold red][!] ELASTICSEARCH EXPOSED (Port 9200): {res_9200['url']}[/bold red]")
                 console.print(f"      Status: {res_9200['type']}")
                 results.append(res_9200)

    if not results:
        console.print("[dim][-] No open Elasticsearch instances found.[/dim]")
        
    return results
