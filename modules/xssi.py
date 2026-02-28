import asyncio
from modules.core import console

# XSSI (Cross-Site Script Inclusion)
# Vulnerability: Sensitive JSON data is dynamic (generated per user) but can be loaded via <script src="...">.
# Browsers allow cross-origin script inclusion despite SOP.
# Attacker redefines Array constructor or steals variables to read the data.
# Mitigation: "X-Content-Type-Options: nosniff" OR Infinite Loop Prefix (while(1);)

async def check_xssi(session, url):
    try:
        # We only care about JSON endpoints or dynamic JS
        if not (url.endswith(".json") or "api" in url or "user" in url):
            return None
            
        async with session.get(url, timeout=5, ssl=False) as resp:
            # Must be authenticated usually, but we check structural weakness.
            text = await resp.text()
            headers = resp.headers
            
            ct = headers.get("Content-Type", "").lower()
            
            # If it serves JSON/JS data...
            if "json" in ct or "javascript" in ct:
                # 1. Check for nosniff header
                nosniff = "nosniff" in headers.get("X-Content-Type-Options", "").lower()
                
                # 2. Check for Parser Breakers (Anti-XSSI)
                # Google/Facebook use "while(1);" or "for(;;);"
                has_breaker = "while(1);" in text or "for(;;);" in text or ")]}'," in text
                
                if not nosniff and not has_breaker:
                    # If it's pure JSON array/object without protection, it might be vulnerable.
                    # Especially Array-based JSON is vulnerable in older browsers, but modern ones are tougher.
                    # Object-based is harder but still risky if header missing.
                     return {
                        "url": url,
                        "type": "XSSI (Potential Data Theft)",
                        "evidence": "Missing 'nosniff' and Anti-XSSI tokens on JSON/JS"
                    }

    except Exception:
        pass
    return None

async def scan_xssi(session, url):
    """
    Scan for XSSI (Cross-Site Script Inclusion).
    """
    console.print(f"\n[bold cyan]--- XSSI Scanner (JSON Theft) ---[/bold cyan]")
    
    # Check current URL and maybe some common API endpoints
    targets = [url]
    if not url.endswith(".json"):
        targets.append(url.rstrip("/") + "/api/user")
        targets.append(url.rstrip("/") + "/user.json")
        targets.append(url.rstrip("/") + "/config.json")
        
    tasks = [check_xssi(session, t) for t in targets]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] XSSI RISK DETECTED: {res['url']}[/bold red]")
             console.print(f"      Evidence: {res['evidence']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No XSSI indicators found (Endpoints protected or not JSON).[/dim]")
        
    return found
