import asyncio
import json
from modules.core import console

# GraphQL Batching
# Attack: Send an array of queries instead of a single query object.
# If the server processes all of them, one can brute-force thousands of times in 1 request.

async def check_graphql_batch(session, url):
    # We need a valid query payload usually.
    # We'll try a generic introspection or simple query.
    query = "query { __typename }"
    
    # 1. Array Batching: [ {query...}, {query...} ]
    # We send 10 identical queries in an array.
    batch_payload = []
    for _ in range(10):
        batch_payload.append({"query": query})
        
    try:
        async with session.post(url, json=batch_payload, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                try:
                    data = json.loads(text)
                    # If response is a LIST and has length 10, Batching is ENABLED
                    if isinstance(data, list) and len(data) == 10:
                         return {
                             "url": url,
                             "type": "GraphQL Array Batching (Rate Limit Bypass)",
                             "details": "Server processed 10 queries in 1 request."
                         }
                except Exception:
                    pass
    except Exception:
        pass
    return None

async def scan_graphql_batch(session, url):
    """
    Scan for GraphQL Batching (Rate Limit Bypass).
    """
    console.print(f"\n[bold cyan]--- GraphQL Batching Scanner ---[/bold cyan]")
    
    # Check if URL looks like GraphQL
    if "graphql" not in url and "api" not in url:
        # Try to append /graphql
        targets = [url, f"{url.rstrip('/')}/graphql", f"{url.rstrip('/')}/api/graphql"]
    else:
        targets = [url]
        
    tasks = [check_graphql_batch(session, t) for t in targets]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] GRAPHQL BATCHING ENABLED: {res['url']}[/bold red]")
             console.print(f"      {res['details']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No GraphQL batching detected (or not a GraphQL endpoint).[/dim]")
        
    return found
