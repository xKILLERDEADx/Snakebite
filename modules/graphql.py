import asyncio
from modules.core import console

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graph",
    "/interface/graphql"
]

INTROSPECTION_QUERY = """
query {
  __schema {
    types {
      name
    }
  }
}
"""

async def check_graphql(session, url, endpoint):
    target = f"{url.rstrip('/')}{endpoint}"
    try:
        # Check GET
        async with session.get(target, params={"query": INTROSPECTION_QUERY}, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                json_resp = await resp.json()
                if "data" in json_resp and "__schema" in json_resp["data"]:
                     return {
                         "url": target,
                         "method": "GET",
                         "type": "Introspection Enabled"
                     }

        # Check POST
        async with session.post(target, json={"query": INTROSPECTION_QUERY}, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                json_resp = await resp.json()
                if "data" in json_resp and "__schema" in json_resp["data"]:
                     return {
                         "url": target,
                         "method": "POST",
                         "type": "Introspection Enabled"
                     }
    except Exception:
        pass
    return None

async def scan_graphql(session, url):
    """
    Scan for GraphQL Introspection.
    """
    console.print(f"\n[bold cyan]--- GraphQL Security Scanner ---[/bold cyan]")
    
    console.print(f"[dim]Checking {len(GRAPHQL_ENDPOINTS)} common GraphQL endpoints...[/dim]")
    
    tasks = [check_graphql(session, url, ep) for ep in GRAPHQL_ENDPOINTS]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] GRAPHQL INTROSPECTION EXPOSED![/bold red]")
             console.print(f"      Endpoint: {res['url']}")
             console.print(f"      Method: {res['method']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No exposed GraphQL endpoints found.[/green]")
        
    return vulns
