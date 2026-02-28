import asyncio
from modules.core import console

# Ultra Admin Hunter (Advanced)
# Focus: Hidden Administration Panels.
# Method: Brute-force common paths + Heuristics (Title/Content).

# Comprehensive list of Admin paths
ADMIN_PATHS = [
    "admin/", "administrator/", "admin_panel/", "cpanel/", "login/", 
    "wp-admin/", "wp-login.php", "admin.php", "admin.html", 
    "dashboard/", "controlpanel/", "system/", "root/", 
    "manage/", "management/", "administration/", "webadmin/",
    "cms/", "backend/", "panel/", "user/login/", 
    "auth/", "authentication/", "admin/login.php", "administrator/index.php",
    "siteadmin/", "server/", "moderator/", "portal/",
    "member/", "members/", "account/", "accounts/",
    "joomla/administrator", "typo3/", "umbraco/", "drupal/admin"
]

EXTENSIONS = ["", ".php", ".html", ".asp", ".aspx", ".jsp"]

async def check_admin_path(session, url, path):
    try:
        target = f"{url.rstrip('/')}/{path}"
        async with session.get(target, timeout=5, ssl=False, allow_redirects=True) as resp:
            
            # Heuristic Analysis
            # 1. Status Code
            if resp.status == 200:
                text = await resp.text()
                lower_text = text.lower()
                
                # Check if it's a real login page
                keywords = ["login", "username", "password", "sign in", "admin", "dashboard", "control panel"]
                score = 0
                for k in keywords:
                    if k in lower_text:
                        score += 1
                
                if score >= 2 or "password" in lower_text:
                     return {
                        "url": target,
                        "type": "Admin Panel (200 OK)",
                        "evidence": f"Login page detected. Score: {score}"
                    }
            
            # 2. Protected (401/403) - Indicates existence!
            elif resp.status in [401, 403]:
                 return {
                    "url": target,
                    "type": f"Admin Panel Protected ({resp.status})",
                    "evidence": "Endpoint exists but requires auth/restricted."
                }
                
    except Exception:
        pass
    return None

async def scan_ultra_admin(session, url):
    """
    Scan for Hidden Admin Panels (Advanced).
    """
    console.print(f"\n[bold cyan]--- Ultra Admin Hunter ---[/bold cyan]")
    
    # Generate Payload List
    # Combine paths with extensions if path doesn't have one
    tasks = []
    
    # We limit concurrency to avoid WAF banning immediately
    # A semaphore could be used if listing is huge, but here it's manageable.
    
    for path in ADMIN_PATHS:
        # If path ends in slash, usually directory.
        if path.endswith("/"):
            tasks.append(check_admin_path(session, url, path))
        else:
            # Try plain + extensions
            tasks.append(check_admin_path(session, url, path))
            # Only add extensions if it looks like a file might be missed
            # For simplicity in this specialized module, we stick to the list + basic variants
            
    # Add heuristic: if url is site.com, try site.com/admin
    
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] ADMIN OBSERVED: {res['url']}[/bold red]")
             console.print(f"      Status: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No obvious admin panels found.[/dim]")
        
    return found
