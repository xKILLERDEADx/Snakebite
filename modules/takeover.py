import asyncio
from modules.core import console

# Fingerprints for common services
# Service Name: Unclaimed/Error String
TAKEOVER_SIGNATURES = {
    "GitHub Pages": "There is no app configured at that hostname",
    "Heroku": "Heroku | No such app",
    "Tumblr": "Whatever you were looking for doesn't currently exist at this address",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Ghost": "The thing you were looking for is no longer here",
    "BigCartel": "This shop is currently unavailable",
    "Wix": "Error 404 - Web-Server",
    "Unbounce": "The requested URL was not found on this server",
    "HelpScout": "No settings were found for this company",
    "Cargo": "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel",
    "FeedPress": "The feed has not been found",
    "Surge.sh": "project not found",
    "AWS S3": "The specified bucket does not exist"
}

async def check_url_takeover(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as response:
            text = await response.text()
            
            for service, fingerprint in TAKEOVER_SIGNATURES.items():
                if fingerprint in text:
                    return {
                        "url": url,
                        "service": service,
                        "status": "VULNERABLE"
                    }
    except Exception:
        pass
    return None

async def scan_takeover(session, subdomains):
    """
    Check a list of subdomains for potential takeover.
    """
    console.print(f"\n[bold cyan]--- Subdomain Takeover Scanner ---[/bold cyan]")
    if not subdomains:
        console.print("[yellow][!] No subdomains found to test.[/yellow]")
        return []

    console.print(f"[dim]Checking {len(subdomains)} subdomains for takeover signatures...[/dim]")
    
    vulnerable_hosts = []
    
    # Ensure protocol is present
    tasks = []
    for sub in subdomains:
        url = sub if sub.startswith("http") else f"http://{sub}"
        tasks.append(check_url_takeover(session, url))
        
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] POTENTIAL TAKEOVER: {res['url']} ({res['service']})[/bold red]")
             vulnerable_hosts.append(res)
             
    if not vulnerable_hosts:
        console.print("[green][+] No takeover vulnerabilities detected.[/green]")
        
    return vulnerable_hosts
