import re
import asyncio
from modules.core import console

# Patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Heroku API Key": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Generic Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Twitter OAuth": r"[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Generic High Entropy": r"(api_key|access_token|secret_key)[\s]*[:=][\s]*['\"][0-9a-zA-Z\-_]{20,}['\"]"
}

async def fetch_js(session, url):
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            if response.status == 200:
                return await response.text(), url
    except Exception:
        pass
    return None, url

async def scan_js_secrets(session, js_urls):
    """
    Scan a list of JS URLs for regex patterns of known secrets.
    """
    console.print(f"\n[bold cyan]--- JavaScript Secrets Scanner ---[/bold cyan]")
    if not js_urls:
         console.print("[yellow][!] No JS files found to scan.[/yellow]")
         return []

    console.print(f"[dim]Scaling {len(js_urls)} JS files...[/dim]")
    
    found_secrets = []
    
    tasks = [fetch_js(session, url) for url in js_urls]
    results = await asyncio.gather(*tasks)
    
    for content, url in results:
        if not content:
            continue
            
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                secret = match.group()
                # Basic False Positive Reduction (too short or common words)
                if len(secret) < 8: continue
                
                # Censoring secret for display
                censored = secret[:4] + "*" * (len(secret)-8) + secret[-4:] if len(secret) > 8 else "***"
                
                console.print(f"  [bold red][!] {name} Found![/bold red]")
                console.print(f"      URL: {url}")
                console.print(f"      Match: {censored}")
                
                found_secrets.append({
                    "type": name,
                    "url": url,
                    "match": secret # stored uncensored for report
                })

    if not found_secrets:
        console.print("[green][+] No secrets found in JS files.[/green]")
        
    return found_secrets
