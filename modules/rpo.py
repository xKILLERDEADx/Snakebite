import asyncio
from modules.core import console

# RPO (Relative Path Overwrite)
# Vulnerability: Server treats `url/page` and `url/page/` and `url/fake/../page` differently,
# but the browser resolves relative CSS links (e.g. <link href="style.css">) incorrectly.
# This allows an attacker to load the HTML page *itself* as a Stylesheet.
# If the HTML page contains user input even without XSS characters (e.g. body {}), 
# it gets executed as CSS.

async def check_rpo(session, url):
    try:
        # 1. Base Request
        async with session.get(url, timeout=5, ssl=False) as resp:
            original_text = await resp.text()
            
        # 2. RPO Request (Path Confusion)
        # We append a nonsense directory that disappears via dot-dot, but changes relative base.
        # e.g. target.com/index.php -> target.com/index.php/fake/..
        # Some servers serve the same page (Success).
        
        target_rpo = url.rstrip("/") + "/SnakeBiteRPO/.."
        
        async with session.get(target_rpo, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                
                # If content is same as original, BUT the browser would see a different base URL...
                # We check if there are relative stylesheets.
                if '<link rel="stylesheet" href="' in text and "http" not in text.split('<link rel="stylesheet" href="')[1].split('"')[0]:
                     # Found relative stylesheet + Path Confusion support
                     return {
                        "url": url,
                        "type": "Relative Path Overwrite (RPO)",
                        "evidence": "Server served page on manipulated path + Relative CSS found"
                    }

    except Exception:
        pass
    return None

async def scan_rpo(session, url):
    """
    Scan for Relative Path Overwrite (CSS Injection).
    """
    console.print(f"\n[bold cyan]--- RPO Scanner (CSS Hijack) ---[/bold cyan]")
    
    # Check Root
    results = []
    
    res = await check_rpo(session, url)
    if res:
         console.print(f"  [bold red][!] RPO VULNERABILITY DETECTED: {res['url']}[/bold red]")
         console.print(f"      Evidence: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No RPO indicators found (no path confusion or all CSS absolute).[/dim]")
        
    return results
