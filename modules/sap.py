import asyncio
from modules.core import console

# SAP NetWeaver Scanner (ERP Recon)
# Focus: Exposed SAP services and Info leaks.
# Endpoints: /sap/public/info, /sap/bc/ping, /sap/public/ping

SAP_PATHS = [
    "/sap/public/info",
    "/sap/public/ping", 
    "/sap/bc/ping",
    "/sap/bc/soap/wsdl"
]

async def check_sap(session, url):
    try:
        for path in SAP_PATHS:
            target = f"{url.rstrip('/')}{path}"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                
                # Check for SAP indicators
                if resp.status == 200:
                    if "sap" in text.lower() or "service" in text.lower():
                         return {
                            "url": target,
                            "type": "SAP Service Exposed",
                            "evidence": f"Endpoint {path} is accessible (200 OK)."
                        }
                    
                # 401 might mean SAP is there but auth required (still intel)
                elif resp.status == 401:
                     if "SAP" in resp.headers.get("WWW-Authenticate", ""):
                          return {
                            "url": target,
                            "type": "SAP Login Exposed",
                            "evidence": "SAP Authentication required."
                        }

    except Exception:
        pass
    return None

async def scan_sap(session, url):
    """
    Scan for SAP NetWeaver Exposure.
    """
    console.print(f"\n[bold cyan]--- SAP NetWeaver Scanner ---[/bold cyan]")
    
    results = []
    res = await check_sap(session, url)
    if res:
         console.print(f"  [bold red][!] SAP DETECTED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No SAP endpoints detected.[/dim]")
        
    return results
