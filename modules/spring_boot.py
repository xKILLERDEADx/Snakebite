import asyncio
from modules.core import console

SPRING_ENDPOINTS = [
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/metrics",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/trace",
    "/actuator/info",
    "/actuator/configprops",
    "/actuator/mappings",
    "/env",
    "/heapdump",
    "/trace",
    "/mappings"
]

async def check_spring(session, url, endpoint):
    target = f"{url.rstrip('/')}{endpoint}"
    try:
        async with session.get(target, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                # Validate content to reduce false positives
                is_valid = False
                
                # Health is common and low risk, but indicates actuator exists
                if "status" in text and ("UP" in text or "DOWN" in text):
                     is_valid = True
                     
                # Env/ConfigProps often return JSON properties
                if "propertySources" in text or "activeProfiles" in text:
                     is_valid = True
                     
                # Heapdump is binary, usually large. We rely on 200 OK + content-type ideally, but here just status for now.
                if "heapdump" in endpoint and len(text) > 1000:
                     is_valid = True

                if is_valid:
                    return {
                        "url": target,
                        "endpoint": endpoint,
                        "status": "Exposed (200 OK)"
                    }
    except Exception:
        pass
    return None

async def scan_spring_boot(session, url):
    """
    Scan for Spring Boot Actuator Endpoints.
    """
    console.print(f"\n[bold cyan]--- Spring Boot Actuator Scanner ---[/bold cyan]")
    
    console.print(f"[dim]Checking {len(SPRING_ENDPOINTS)} common Actuator endpoints...[/dim]")
    
    tasks = [check_spring(session, url, ep) for ep in SPRING_ENDPOINTS]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             risk = "CRITICAL" if "env" in res['endpoint'] or "heapdump" in res['endpoint'] else "INFO"
             color = "red" if risk == "CRITICAL" else "green"
             
             console.print(f"  [bold {color}][!] SPRING BOOT ENDPOINT FOUND![/bold {color}]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Risk: {risk}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No exposed Spring Boot endpoints found.[/green]")
        
    return vulns
