import asyncio
from modules.core import console

SWAGGER_PATHS = [
    "/swagger.json",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/api-docs",
    "/docs",
    "/api/docs",
    "/openapi.json"
]

async def check_swagger(session, url, path):
    target = f"{url.rstrip('/')}{path}"
    try:
        async with session.get(target, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                # Validate it's likely swagger/openapi
                if '"swagger":' in text or '"openapi":' in text or "swagger-ui" in text:
                     return {
                         "url": target,
                         "path": path,
                         "status": "Found (200 OK)"
                     }
    except Exception:
        pass
    return None

async def scan_swagger(session, url):
    """
    Scan for Swagger / OpenAPI Documentation.
    """
    console.print(f"\n[bold cyan]--- API Swagger Hunter ---[/bold cyan]")
    
    console.print(f"[dim]Fuzzing {len(SWAGGER_PATHS)} common API doc paths...[/dim]")
    
    tasks = [check_swagger(session, url, p) for p in SWAGGER_PATHS]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold green][+] SWAGGER DOCS FOUND![/bold green]")
             console.print(f"      URL: {res['url']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No Swagger/OpenAPI docs found.[/dim]")
        
    return found
