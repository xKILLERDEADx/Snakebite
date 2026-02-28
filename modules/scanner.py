import asyncio
import aiohttp
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from modules.core import console

async def fetch_url(session, url):
    """Fetch a single URL and return status + size"""
    try:
        async with session.get(url, allow_redirects=False) as response:
            content = await response.read()
            return response.status, len(content), response.url
    except Exception:
        return None, 0, url

async def generic_scan(session, target_url, paths, description="Scanning"):
    found_items = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True
    ) as progress:
        task_id = progress.add_task(f"[cyan]{description}...", total=len(paths))
        
        tasks = []
        path_map = {} # Map task to path
        
        for path in paths:
            full_url = f"{target_url.rstrip('/')}/{path}"
            tasks.append(fetch_url(session, full_url))
            path_map[full_url] = path

        # Run all tasks concurrently
        results = await asyncio.gather(*tasks)
        
        for i, (status, size, url) in enumerate(results):
            path = paths[i]
            progress.advance(task_id)
            
            if status:
                if status in [200, 301, 302, 403, 401]:
                     # Filter out 404s (some servers return 200 for 404 pages, logic needed but skipping for now)
                    if status == 404: continue
                    
                    color = "green" if status == 200 else "yellow"
                    console.print(f"  [{color}][FOUND] /{path:<20} Status: {status}  Size: {size}b[/{color}]")
                    found_items.append({"path": path, "status": status, "size": size})
    
    return found_items

async def find_admin(session, url):
    admin_paths = [
        'admin', 'admin/', 'admin.php', 'admin.html', 'adm/',
        'wp-admin', 'wp-login.php', 'wp-admin/', 'login', 'login.php',
        'administrator', 'administrator/', 'cpanel', 'dashboard', 
        'manager', 'phpmyadmin', 'sqladmin', 'user/login'
    ]
    console.print("\n[bold]2.1 Admin Panel Search[/bold]")
    return await generic_scan(session, url, admin_paths, "Hunting Admin Panels")

async def check_sensitive_files(session, url):
    files = [
        '.env', '.env.local', '.git/HEAD', '.git/config', '.gitignore',
        'backup.zip', 'backup.sql', 'db.sql', 'database.sql', 'dump.sql',
        'robots.txt', 'sitemap.xml', 'config.php', 'wp-config.php',
        '.htaccess', '.htpasswd', 'web.config', 'phpinfo.php', 'info.php',
        'id_rsa', 'id_rsa.pub'
    ]
    console.print("\n[bold]2.2 Sensitive Files Discovery[/bold]")
    return await generic_scan(session, url, files, "Checking Sensitive Files")

async def directory_bruteforce(session, url):
    dirs = [
        'uploads', 'images', 'assets', 'static', 'css', 'js',
        'includes', 'templates', 'search', 'api', 'v1', 'v2',
        'doc', 'docs', 'backup', 'backups', 'private', 'tmp',
        'logs', 'cache', 'test', 'tests', 'dev'
    ]
    console.print("\n[bold]2.3 Directory Enumeration[/bold]")
    return await generic_scan(session, url, dirs, "Bruteforcing Directories")

async def run_active_scan(session, url):
    """Run all active scans"""
    results = {}
    
    results['admin'] = await find_admin(session, url)
    results['sensitive'] = await check_sensitive_files(session, url)
    results['directories'] = await directory_bruteforce(session, url)
    
    return results