import asyncio
from modules.core import console

async def scan_clickjacking(session, url):
    """
    Check for Clickjacking protection headers.
    """
    console.print(f"\n[bold cyan]--- Clickjacking Protection Scanner ---[/bold cyan]")
    
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            headers = resp.headers
            xfo = headers.get("X-Frame-Options", "MISSING")
            csp = headers.get("Content-Security-Policy", "MISSING")
            
            vulnerable = True
            
            if xfo != "MISSING":
                if xfo.upper() in ["DENY", "SAMEORIGIN"]:
                    vulnerable = False
                    
            if csp != "MISSING":
                if "frame-ancestors" in csp:
                    vulnerable = False
            
            if vulnerable:
                console.print(f"  [bold red][!] Website is VULNERABLE to Clickjacking![/bold red]")
                console.print(f"      X-Frame-Options: {xfo}")
                console.print(f"      CSP frame-ancestors: {csp}")
                return {
                    "status": "VULNERABLE",
                    "xfo": xfo,
                    "csp": csp
                }
            else:
                console.print(f"  [bold green][+] Website is Protected against Clickjacking.[/bold green]")
                console.print(f"      X-Frame-Options: {xfo}")
                return {
                    "status": "PROTECTED",
                    "xfo": xfo,
                    "csp": csp
                }

    except Exception:
        console.print("[red][!] Could not retrieve headers.[/red]")
        return {"error": "Connection Failed"}
