import aiohttp
import asyncio
from modules.core import console

async def scan_general(session, url):
    """
    Run general website checks for non-CMS or unknown-CMS sites:
    1. Security Headers Analysis
    2. Robots/Sitemap
    3. Basic Error Page Fingerprinting
    """
    console.print(f"\n[bold magenta]--- General Website Analysis ---[/bold magenta]")
    results = {}
    
    # 1. Security Headers
    results['headers'] = await check_security_headers(session, url)
    
    # 2. Robots & Sitemap
    results['files'] = await check_std_files(session, url)
    
    return results

async def check_security_headers(session, url):
    headers_to_check = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]
    
    found_headers = {}
    missing_headers = []
    
    console.print("[cyan]    [*] Analyzing Security Headers...[/cyan]")
    try:
        async with session.get(url, timeout=10) as resp:
            headers = resp.headers
            for h in headers_to_check:
                if h in headers:
                    found_headers[h] = headers[h]
                    console.print(f"[green]    [+] {h} is present.[/green]")
                else:
                    missing_headers.append(h)
                    
            if missing_headers:
                console.print(f"[yellow]    [!] Missing Security Headers: {', '.join(missing_headers)}[/yellow]")
            else:
                console.print(f"[bold green]    [+] All critical security headers detected![/bold green]")
                
    except Exception as e:
        console.print(f"[red]Error checking headers: {e}[/red]")
        
    return {"present": found_headers, "missing": missing_headers}

async def check_std_files(session, url):
    """Check for standard files like robots.txt and sitemap.xml"""
    files = ["robots.txt", "sitemap.xml", ".well-known/security.txt"]
    found = []
    
    console.print("[cyan]    [*] Checking standard web files...[/cyan]")
    for f in files:
        target = f"{url.rstrip('/')}/{f}"
        try:
            async with session.get(target, timeout=5) as resp:
                if resp.status == 200:
                    console.print(f"    [green][+] Found {f}[/green]")
                    found.append(f)
                else:
                    pass
        except Exception:
            pass
    return found
