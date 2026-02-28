import aiohttp
import asyncio
from modules.core import console

async def scan_wordpress(session, url):
    """
    Run WordPress specific checks:
    1. Version Detection
    2. User Enumeration
    3. XML-RPC
    4. Sensitive Files (wp-config backups, debug logs)
    """
    console.print(f"\n[bold magenta]--- WordPress Advanced Scan ---[/bold magenta]")
    results = {}
    
    # 1. Version Detection
    results['version'] = await check_version(session, url)
    
    # 2. User Enumeration
    results['users'] = await enum_users(session, url)
    
    # 3. XML-RPC
    results['xmlrpc'] = await check_xmlrpc(session, url)
    
    # 4. WP Specific Files
    results['files'] = await check_wp_files(session, url)
    
    return results

async def check_version(session, url):
    """Try to detect WP version from meta tags or files"""
    version = "Unknown"
    try:
        async with session.get(url, timeout=10) as resp:
            text = await resp.text()
            # aggressive check for meta generator
            if 'name="generator" content="WordPress' in text:
                import re
                match = re.search(r'content="WordPress ([\d.]+)"', text)
                if match:
                    version = match.group(1)
                    console.print(f"[green][+] WordPress Version Detected: {version}[/green]")
                else:
                    console.print("[green][+] WordPress detected via meta tag (Version hidden)[/green]")
    except Exception:
        pass
    return version

async def enum_users(session, url):
    """Enumerate users via WP REST API"""
    users = []
    api_url = f"{url.rstrip('/')}/wp-json/wp/v2/users"
    console.print("[cyan]    [*] Checking for User Enumeration (REST API)...[/cyan]")
    try:
        async with session.get(api_url, timeout=10) as resp:
            if resp.status == 200:
                data = await resp.json()
                for user in data:
                    users.append(user.get('name', 'Unknown'))
                
                if users:
                    console.print(f"[red][!] Users Found: {', '.join(users)}[/red]")
                else:
                    console.print("[green]    [-] User enumeration enabled but no users returned.[/green]")
            else:
                 console.print("[green]    [-] REST API User Enumeration seems disabled.[/green]")
    except Exception:
         console.print("[yellow]    [!] Failed to check REST API.[/yellow]")
    return users

async def check_xmlrpc(session, url):
    """Check if XML-RPC is enabled"""
    target = f"{url.rstrip('/')}/xmlrpc.php"
    is_enabled = False
    console.print("[cyan]    [*] Checking XML-RPC...[/cyan]")
    try:
        async with session.get(target, timeout=10) as resp:
            if resp.status == 405 or "XML-RPC server accepts POST requests only" in await resp.text():
                 console.print(f"[red][!] XML-RPC is ENABLED at {target}[/red]")
                 is_enabled = True
            else:
                 console.print("[green]    [-] XML-RPC seems disabled/not found.[/green]")
    except Exception:
        pass
    return is_enabled

async def check_wp_files(session, url):
    """Check for WP specific backup files or debug logs"""
    files_to_check = [
        "wp-config.php.bak",
        "wp-config.php.save",
        "wp-content/debug.log",
        "wp-content/uploads/dump.sql"
    ]
    found = []
    console.print("[cyan]    [*] Checking specific WordPress sensitive files...[/cyan]")
    
    for f in files_to_check:
        target = f"{url.rstrip('/')}/{f}"
        try:
            async with session.get(target, timeout=5) as resp:
                if resp.status == 200:
                    console.print(f"[bold red][!] FOUND VULNERABLE FILE: {target}[/bold red]")
                    found.append(target)
        except Exception:
            pass
            
    if not found:
        console.print("[green]    [-] No obvious WP backup files found.[/green]")
        
    return found
