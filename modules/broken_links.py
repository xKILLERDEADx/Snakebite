import asyncio
from urllib.parse import urlparse
from modules.core import console

# Social Media domains to prioritize
SOCIAL_DOMAINS = [
    "twitter.com", "instagram.com", "facebook.com", "linkedin.com", 
    "github.com", "youtube.com", "medium.com", "tiktok.com"
]

async def check_link(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            if resp.status == 404:
                return {
                    "url": url,
                    "status": 404,
                    "type": "Broken Link (Potential Hijack)"
                }
    except Exception:
        pass
    return None

async def scan_broken_links(session, all_links):
    """
    Scan for Broken External Links (Hijacking).
    """
    console.print(f"\n[bold cyan]--- Broken Link Hijacker ---[/bold cyan]")
    
    # Filter external links
    external_links = set()
    for link in all_links:
        try:
            parsed = urlparse(link)
            domain = parsed.netloc
            # Check if domain is in our social list or just any external
            # Ideally we want social media mostly
            for social in SOCIAL_DOMAINS:
                if social in domain:
                    external_links.add(link)
                    break 
        except Exception:
            pass
            
    if not external_links:
         console.print("[yellow][!] No social media links found to check.[/yellow]")
         return []
         
    console.print(f"[dim]Checking {len(external_links)} social links for 404s...[/dim]")
    
    tasks = [check_link(session, l) for l in external_links]
    results = await asyncio.gather(*tasks)
    
    broken = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] BROKEN SOCIAL LINK FOUND![/bold red]")
             console.print(f"      URL: {res['url']}")
             broken.append(res)
             
    if not broken:
        console.print("[green][+] No broken social links detected.[/green]")
        
    return broken
