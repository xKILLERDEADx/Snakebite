import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from modules.core import console

async def check_tabnabbing(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            soup = BeautifulSoup(text, 'html.parser')
            
            vulns = []
            host = urlparse(url).netloc
            
            for a in soup.find_all('a', href=True):
                href = a['href']
                target = a.get('target', '')
                rel = a.get('rel', []) # rel is usually a list in BS4
                
                # Check for external links
                if "http" in href and host not in href:
                    # Check for target="_blank"
                    if target == "_blank":
                        # Check for missing noopener/noreferrer
                        # rel attribute comes as list of strings
                        has_protection = False
                        if "noopener" in rel or "noreferrer" in rel:
                             has_protection = True
                             
                        if not has_protection:
                             vulns.append({
                                 "url": url,
                                 "link": href,
                                 "type": "Reverse Tabnabbing (Phishing)",
                                 "evidence": f"<a href='{href}' target='_blank'>"
                             })
            return vulns
    except Exception:
        pass
    return []

async def scan_tabnabbing(session, urls):
    """
    Scan for Reverse Tabnabbing (Unsafe External Links).
    """
    console.print(f"\n[bold cyan]--- Reverse Tabnabbing Scanner ---[/bold cyan]")
    
    # Check top 20 pages
    targets = urls[:20]
    
    console.print(f"[dim]Checking links on {len(targets)} pages for missing 'noopener'...[/dim]")
    
    tasks = [check_tabnabbing(session, u) for u in targets]
    results_list = await asyncio.gather(*tasks)
    
    all_vulns = []
    for r in results_list:
        if r:
            all_vulns.extend(r)
            
    # De-duplicate
    unique_vulns = []
    seen = set()
    for v in all_vulns:
        sig = v['link']
        if sig not in seen:
            unique_vulns.append(v)
            seen.add(sig)
            
    for v in unique_vulns:
         console.print(f"  [bold yellow][!] UNSAFE EXTERNAL LINK (TABNABBING)[/bold yellow]")
         console.print(f"      Source: {v['url']}")
         console.print(f"      Unsafe Link: {v['link']}")
         
    if not unique_vulns:
        console.print("[green][+] No unsafe target='_blank' links found.[/green]")
        
    return unique_vulns
