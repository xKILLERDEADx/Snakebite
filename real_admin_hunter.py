import asyncio
import aiohttp
from modules.core import console

# REAL ADMIN PATHS - Only common ones that actually exist
REAL_ADMIN_PATHS = [
    # WordPress
    "/wp-admin/", "/wp-login.php", "/wp-admin/admin.php", "/wordpress/wp-admin/",
    
    # Common Admin Panels
    "/admin/", "/admin/login/", "/admin/index.php", "/admin/admin.php",
    "/administrator/", "/login/", "/signin/", "/auth/",
    
    # CPanel & Server
    "/cpanel/", "/whm/", "/plesk/", "/directadmin/",
    
    # Database
    "/phpmyadmin/", "/pma/", "/adminer/", "/mysql/",
    
    # CMS
    "/admin/login.php", "/admin/index.html", "/backend/",
    "/manage/", "/panel/", "/control/", "/dashboard/",
    
    # Framework Specific
    "/admin/admin/", "/user/login/", "/account/login/",
    "/cms/", "/system/", "/manager/",
    
    # Common Variations
    "/admin1/", "/admin2/", "/test/", "/dev/",
    "/staging/admin/", "/backup/admin/"
]

async def check_real_admin(session, base_url, path):
    """Check if admin path actually exists and is real"""
    target_url = base_url.rstrip('/') + path
    
    try:
        async with session.get(target_url, timeout=10, ssl=False, allow_redirects=True) as resp:
            if resp.status in [200, 301, 302, 401, 403]:
                content = await resp.text()
                
                # Real admin detection
                admin_indicators = [
                    'password', 'username', 'login', 'signin', 'dashboard',
                    'admin', 'administrator', 'control panel', 'management',
                    'wp-admin', 'phpmyadmin', 'cpanel', 'plesk'
                ]
                
                content_lower = content.lower()
                found_indicators = [ind for ind in admin_indicators if ind in content_lower]
                
                # Only return if it's actually an admin panel
                if len(found_indicators) >= 2 or resp.status in [401, 403]:
                    title = ""
                    if '<title>' in content:
                        title = content.split('<title>')[1].split('</title>')[0][:50]
                    
                    return {
                        'url': target_url,
                        'status': resp.status,
                        'title': title,
                        'indicators': found_indicators,
                        'size': len(content)
                    }
    except Exception:
        pass
    
    return None

async def real_admin_hunt(session, url):
    """Real admin panel hunter - no fake data"""
    console.print(f"\n[bold cyan]REAL ADMIN HUNTER - {url}[/bold cyan]")
    console.print(f"[yellow]Testing {len(REAL_ADMIN_PATHS)} real admin paths...[/yellow]")
    
    results = []
    
    # Test each path
    for i, path in enumerate(REAL_ADMIN_PATHS, 1):
        console.print(f"[dim]{i:2d}/{len(REAL_ADMIN_PATHS)} Testing: {path}[/dim]")
        
        result = await check_real_admin(session, url, path)
        if result:
            results.append(result)
            status_color = "green" if result['status'] == 200 else "red"
            console.print(f"  [bold {status_color}]FOUND: {result['url']} ({result['status']})[/bold {status_color}]")
        
        await asyncio.sleep(0.2)  # Rate limiting
    
    # Show results
    console.print(f"\n[bold green]REAL RESULTS:[/bold green]")
    
    if results:
        console.print(f"[bold yellow]Found {len(results)} real admin panels:[/bold yellow]")
        
        for i, result in enumerate(results, 1):
            status_emoji = "🔓" if result['status'] == 200 else "🔒"
            console.print(f"\n{i:2d}. {status_emoji} {result['url']}")
            console.print(f"    Status: {result['status']} | Size: {result['size']}B")
            console.print(f"    Title: {result['title']}")
            console.print(f"    Indicators: {', '.join(result['indicators'][:3])}")
    else:
        console.print("[yellow]No real admin panels found - site is secure[/yellow]")
    
    return results

# Test function
async def test_real_hunter():
    target = "https://destinationroyale.ae"
    
    timeout = aiohttp.ClientTimeout(total=30)
    conn = aiohttp.TCPConnector(ssl=False, limit=10)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
        results = await real_admin_hunt(session, target)
        return results

if __name__ == "__main__":
    import sys
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test_real_hunter())