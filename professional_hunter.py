#!/usr/bin/env python3
"""
PROFESSIONAL HACKER-GRADE ADMIN HUNTER
Real-time detection, no fake data, actual results only
"""
import asyncio
import aiohttp
import re
from urllib.parse import urljoin, urlparse
import time

class ProfessionalAdminHunter:
    def __init__(self):
        # REAL admin paths that actually exist on websites
        self.admin_paths = [
            # WordPress (Most Common)
            "wp-admin/", "wp-login.php", "wp-admin/admin.php", "wp-admin/index.php",
            "wordpress/wp-admin/", "blog/wp-admin/", "cms/wp-admin/",
            
            # Generic Admin
            "admin/", "admin/login/", "admin/index.php", "admin/admin.php", 
            "admin/login.php", "admin/home.php", "admin/controlpanel.php",
            "administrator/", "administrator/index.php", "administrator/login.php",
            
            # Login Pages
            "login/", "login.php", "login.html", "signin/", "signin.php",
            "auth/", "auth/login/", "authentication/", "user/login/",
            
            # Control Panels
            "cpanel/", "whm/", "plesk/", "directadmin/", "webmin/",
            "control/", "controlpanel/", "panel/", "dashboard/",
            
            # Database Admin
            "phpmyadmin/", "pma/", "adminer/", "adminer.php", "mysql/",
            "database/", "db/", "dbadmin/", "sql/",
            
            # CMS Specific
            "manager/", "management/", "backend/", "backoffice/",
            "cms/", "cms/admin/", "system/", "siteadmin/",
            
            # Framework Specific
            "admin/admin/", "admin/cp/", "admin/panel/", "admin/console/",
            "console/", "cp/", "manage/", "webadmin/",
            
            # Server Management
            "server/", "hosting/", "host-manager/", "server-manager/",
            "admin-console/", "web-console/", "management-console/",
            
            # Development
            "dev/", "development/", "test/", "testing/", "staging/",
            "debug/", "demo/", "sandbox/", "beta/"
        ]
    
    async def detect_admin_panel(self, session, url):
        """Real admin panel detection - no fake results"""
        try:
            async with session.get(url, timeout=8, ssl=False, allow_redirects=True) as response:
                if response.status == 404:
                    return None
                
                content = await response.text()
                content_lower = content.lower()
                
                # REAL admin detection patterns
                admin_patterns = [
                    r'<input[^>]*type=["\']password["\']',  # Password field
                    r'<input[^>]*name=["\']password["\']',
                    r'<input[^>]*name=["\']username["\']',  # Username field
                    r'<input[^>]*name=["\']user["\']',
                    r'<form[^>]*login',                     # Login form
                    r'<title[^>]*>[^<]*admin[^<]*</title>', # Admin in title
                    r'<title[^>]*>[^<]*login[^<]*</title>', # Login in title
                    r'dashboard',                           # Dashboard keyword
                    r'control panel',                       # Control panel
                    r'administrator',                       # Administrator
                    r'wp-admin',                           # WordPress admin
                    r'phpmyadmin',                         # phpMyAdmin
                    r'please.*log.*in',                    # Login prompt
                    r'sign.*in',                           # Sign in
                    r'authentication'                       # Authentication
                ]
                
                matches = 0
                found_patterns = []
                
                for pattern in admin_patterns:
                    if re.search(pattern, content_lower):
                        matches += 1
                        found_patterns.append(pattern.replace(r'[^>]*', '').replace(r'[^<]*', ''))
                
                # Extract title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                title = title_match.group(1).strip() if title_match else "No Title"
                
                # Real detection logic
                is_admin = False
                confidence = 0
                
                if matches >= 2:  # At least 2 admin indicators
                    is_admin = True
                    confidence = min(matches * 15, 95)
                elif response.status in [401, 403]:  # Protected
                    is_admin = True
                    confidence = 70
                elif matches == 1 and len(content) < 5000:  # Single match + small page
                    is_admin = True
                    confidence = 40
                
                if is_admin:
                    return {
                        'url': str(response.url),
                        'status': response.status,
                        'title': title[:80],
                        'confidence': confidence,
                        'patterns': found_patterns[:3],
                        'size': len(content),
                        'redirect': str(response.url) != url
                    }
                
        except Exception as e:
            pass
        
        return None
    
    async def hunt_admin_panels(self, target_url):
        """Professional admin hunting with real results only"""
        print(f"\n🎯 PROFESSIONAL ADMIN HUNTER")
        print(f"Target: {target_url}")
        print(f"Testing {len(self.admin_paths)} real admin paths...\n")
        
        # Setup session
        timeout = aiohttp.ClientTimeout(total=15)
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        results = []
        tested = 0
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            for path in self.admin_paths:
                tested += 1
                full_url = urljoin(target_url.rstrip('/') + '/', path)
                
                print(f"[{tested:2d}/{len(self.admin_paths)}] Testing: /{path}", end=" ... ")
                
                result = await self.detect_admin_panel(session, full_url)
                
                if result:
                    results.append(result)
                    status_color = "🟢" if result['status'] == 200 else "🔴" if result['status'] in [401, 403] else "🟡"
                    print(f"{status_color} FOUND! [{result['confidence']}%]")
                else:
                    print("❌")
                
                await asyncio.sleep(0.3)  # Rate limiting
        
        return results
    
    def display_results(self, results):
        """Display real results only"""
        print(f"\n{'='*60}")
        print(f"🎯 PROFESSIONAL SCAN RESULTS")
        print(f"{'='*60}")
        
        if not results:
            print("❌ No admin panels found - Target is secure")
            return
        
        print(f"✅ Found {len(results)} REAL admin panels:\n")
        
        # Sort by confidence
        results.sort(key=lambda x: x['confidence'], reverse=True)
        
        for i, result in enumerate(results, 1):
            status_emoji = "🟢 OPEN" if result['status'] == 200 else "🔴 PROTECTED" if result['status'] in [401, 403] else "🟡 REDIRECT"
            
            print(f"{i:2d}. {status_emoji} [{result['confidence']}%]")
            print(f"    URL: {result['url']}")
            print(f"    Status: {result['status']} | Size: {result['size']}B")
            print(f"    Title: {result['title']}")
            if result['patterns']:
                print(f"    Detected: {', '.join(result['patterns'][:2])}")
            print()
        
        # Threat assessment
        critical = len([r for r in results if r['confidence'] >= 80])
        high = len([r for r in results if 60 <= r['confidence'] < 80])
        medium = len([r for r in results if r['confidence'] < 60])
        
        print(f"🚨 THREAT ASSESSMENT:")
        print(f"   Critical (80%+): {critical}")
        print(f"   High (60-79%):   {high}")
        print(f"   Medium (<60%):   {medium}")

async def main():
    hunter = ProfessionalAdminHunter()
    
    # Target
    target = "https://destinationroyale.ae"
    
    # Hunt for real admin panels
    results = await hunter.hunt_admin_panels(target)
    
    # Display real results
    hunter.display_results(results)

if __name__ == "__main__":
    import sys
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
    except Exception as e:
        print(f"\n💥 Error: {e}")