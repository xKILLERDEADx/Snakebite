import aiohttp
import asyncio
import dns.resolver
from urllib.parse import urlparse, urljoin
from modules.core import console
import json
import re

class ResourceDiscovery:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.base_url = f"{urlparse(target_url).scheme}://{self.domain}"
        self.discovered_resources = {
            'directories': set(),
            'files': set(),
            'subdomains': set(),
            'technologies': {},
            'dns_records': {},
            'endpoints': set(),
            'parameters': set(),
            'headers': {}
        }

    async def dns_enumeration(self):
        """Real-time DNS record enumeration"""
        console.print("[bold cyan]DNS Enumeration:[/bold cyan]")
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                answers = resolver.resolve(self.domain, record_type)
                records = [str(rdata) for rdata in answers]
                self.discovered_resources['dns_records'][record_type] = records
                console.print(f"  [green]{record_type}:[/green] {len(records)} records")
            except Exception:
                continue

    async def subdomain_enumeration(self):
        """Real-time subdomain discovery"""
        console.print("[bold cyan]Subdomain Discovery:[/bold cyan]")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 
            'blog', 'shop', 'app', 'mobile', 'secure', 'vpn', 'remote',
            'portal', 'dashboard', 'panel', 'cpanel', 'webmail', 'mx',
            'ns1', 'ns2', 'cdn', 'static', 'assets', 'img', 'images'
        ]
        
        tasks = []
        for sub in common_subdomains:
            tasks.append(self.check_subdomain(f"{sub}.{self.domain}"))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        active_subs = [sub for sub in results if sub and not isinstance(sub, Exception)]
        
        for subdomain in active_subs:
            self.discovered_resources['subdomains'].add(subdomain)
            console.print(f"  [green][+] {subdomain}[/green]")

    async def check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.resolve(subdomain, 'A')
            return subdomain
        except Exception:
            return None

    async def directory_bruteforce(self, session):
        """Real-time directory discovery"""
        console.print("[bold cyan]Directory Discovery:[/bold cyan]")
        
        common_dirs = [
            'admin', 'administrator', 'api', 'app', 'assets', 'backup', 'bin',
            'blog', 'cache', 'config', 'css', 'data', 'db', 'debug', 'dev',
            'docs', 'download', 'files', 'images', 'img', 'includes', 'js',
            'lib', 'login', 'logs', 'mail', 'media', 'old', 'panel', 'private',
            'public', 'scripts', 'secure', 'src', 'static', 'temp', 'test',
            'tmp', 'upload', 'uploads', 'user', 'users', 'var', 'web', 'wp-admin',
            'wp-content', 'wp-includes', '.git', '.env', 'robots.txt', 'sitemap.xml'
        ]
        
        tasks = []
        for directory in common_dirs:
            url = f"{self.base_url}/{directory}"
            tasks.append(self.check_resource(session, url, 'directory'))
        
        await asyncio.gather(*tasks, return_exceptions=True)

    async def file_discovery(self, session):
        """Real-time file discovery"""
        console.print("[bold cyan]File Discovery:[/bold cyan]")
        
        common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', 'crossdomain.xml',
            'phpinfo.php', 'info.php', 'test.php', 'config.php', 'database.php',
            'wp-config.php', '.env', '.git/config', 'package.json', 'composer.json',
            'readme.txt', 'README.md', 'changelog.txt', 'version.txt', 'backup.sql',
            'dump.sql', 'error_log', 'access_log', 'server-status', 'server-info'
        ]
        
        tasks = []
        for file in common_files:
            url = f"{self.base_url}/{file}"
            tasks.append(self.check_resource(session, url, 'file'))
        
        await asyncio.gather(*tasks, return_exceptions=True)

    async def check_resource(self, session, url, resource_type):
        """Check if resource exists"""
        try:
            async with session.head(url, timeout=5, ssl=False) as response:
                if response.status in [200, 301, 302, 403]:
                    if resource_type == 'directory':
                        self.discovered_resources['directories'].add(url)
                    else:
                        self.discovered_resources['files'].add(url)
                    
                    status_color = "green" if response.status == 200 else "yellow"
                    console.print(f"  [bold {status_color}][{response.status}] {url}[/bold {status_color}]")
                    return url
        except Exception:
            pass
        return None

    async def technology_detection(self, session):
        """Real-time technology stack detection"""
        console.print("[bold cyan]Technology Detection:[/bold cyan]")
        
        try:
            async with session.get(self.target_url, timeout=10, ssl=False) as response:
                headers = dict(response.headers)
                content = await response.text()
                
                # Server detection
                server = headers.get('Server', 'Unknown')
                self.discovered_resources['technologies']['Server'] = server
                console.print(f"  [green]Server:[/green] {server}")
                
                # Framework detection
                frameworks = {
                    'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
                    'Drupal': ['sites/default', 'modules/', 'themes/'],
                    'Joomla': ['components/', 'modules/', 'templates/'],
                    'Laravel': ['laravel_session', 'XSRF-TOKEN'],
                    'Django': ['csrfmiddlewaretoken', 'django'],
                    'React': ['react', 'ReactDOM'],
                    'Angular': ['ng-', 'angular'],
                    'Vue.js': ['vue', 'v-'],
                    'Bootstrap': ['bootstrap', 'btn-'],
                    'jQuery': ['jquery', '$']
                }
                
                for framework, indicators in frameworks.items():
                    if any(indicator in content.lower() for indicator in indicators):
                        self.discovered_resources['technologies'][framework] = 'Detected'
                        console.print(f"  [green]{framework}:[/green] Detected")
                
                # Security headers
                security_headers = [
                    'X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy',
                    'Strict-Transport-Security', 'X-Content-Type-Options'
                ]
                
                for header in security_headers:
                    if header in headers:
                        self.discovered_resources['headers'][header] = headers[header]
                        console.print(f"  [green]{header}:[/green] {headers[header]}")
                    else:
                        console.print(f"  [red]{header}:[/red] Missing")
                        
        except Exception as e:
            console.print(f"[red]Technology detection failed: {e}[/red]")

    async def endpoint_discovery(self, session):
        """API endpoint discovery"""
        console.print("[bold cyan]API Endpoint Discovery:[/bold cyan]")
        
        api_paths = [
            'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'webhook',
            'api/users', 'api/admin', 'api/auth', 'api/login', 'api/config'
        ]
        
        for path in api_paths:
            url = f"{self.base_url}/{path}"
            try:
                async with session.get(url, timeout=5, ssl=False) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'json' in content_type or 'api' in content_type:
                            self.discovered_resources['endpoints'].add(url)
                            console.print(f"  [green][+] API Endpoint: {url}[/green]")
            except Exception:
                continue

    async def parameter_discovery(self, session):
        """Parameter fuzzing"""
        console.print("[bold cyan]Parameter Discovery:[/bold cyan]")
        
        common_params = [
            'id', 'user', 'admin', 'page', 'file', 'path', 'url', 'redirect',
            'search', 'q', 'query', 'keyword', 'category', 'type', 'action',
            'cmd', 'exec', 'debug', 'test', 'dev', 'api_key', 'token'
        ]
        
        for param in common_params:
            test_url = f"{self.target_url}?{param}=test"
            try:
                async with session.get(test_url, timeout=3, ssl=False) as response:
                    if response.status == 200:
                        original_response = await session.get(self.target_url, timeout=3, ssl=False)
                        if len(await response.text()) != len(await original_response.text()):
                            self.discovered_resources['parameters'].add(param)
                            console.print(f"  [green][+] Parameter: {param}[/green]")
            except Exception:
                continue

async def run_resource_discovery(session, url):
    """Main resource discovery function"""
    console.print(f"\n[bold red]Advanced Resource Discovery Scanner[/bold red]")
    console.print(f"[dim]Target: {url}[/dim]\n")
    
    discovery = ResourceDiscovery(url)
    
    # Run all discovery methods
    await discovery.dns_enumeration()
    await discovery.subdomain_enumeration()
    await discovery.directory_bruteforce(session)
    await discovery.file_discovery(session)
    await discovery.technology_detection(session)
    await discovery.endpoint_discovery(session)
    await discovery.parameter_discovery(session)
    
    # Summary
    console.print(f"\n[bold yellow]Discovery Summary:[/bold yellow]")
    console.print(f"  [cyan]Subdomains Found:[/cyan] {len(discovery.discovered_resources['subdomains'])}")
    console.print(f"  [cyan]Directories Found:[/cyan] {len(discovery.discovered_resources['directories'])}")
    console.print(f"  [cyan]Files Found:[/cyan] {len(discovery.discovered_resources['files'])}")
    console.print(f"  [cyan]API Endpoints:[/cyan] {len(discovery.discovered_resources['endpoints'])}")
    console.print(f"  [cyan]Parameters:[/cyan] {len(discovery.discovered_resources['parameters'])}")
    console.print(f"  [cyan]Technologies:[/cyan] {len(discovery.discovered_resources['technologies'])}")
    
    return discovery.discovered_resources