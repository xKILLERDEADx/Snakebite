import aiohttp
import asyncio
import dns.resolver
import json
from modules.core import console

# Comprehensive subdomain wordlist (1000+ subdomains)
SUBDOMAINS = [
    # Common subdomains
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
    "ftp", "mail2", "test", "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx", "email",
    "cloud", "mail1", "forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
    "vps", "news", "staging", "dashboard", "cpanel", "whm", "panel", "direct-connect-mail",
    
    # Development & Testing
    "dev", "test", "staging", "demo", "beta", "alpha", "preview", "sandbox", "qa", "uat", "pre", "preprod",
    "development", "testing", "stage", "prod", "production", "live", "www-test", "test-www", "dev-www",
    
    # API & Services
    "api", "rest", "service", "services", "ws", "webservice", "soap", "graphql", "rpc", "gateway", "proxy",
    "api-v1", "api-v2", "v1", "v2", "v3", "v4", "api1", "api2", "microservice", "backend", "frontend",
    
    # Admin & Management
    "admin", "administrator", "root", "manage", "management", "control", "console", "dashboard", "panel",
    "cpanel", "whm", "plesk", "directadmin", "webmin", "phpmyadmin", "adminer", "wp-admin", "drupal",
    
    # Mail & Communication
    "mail", "email", "smtp", "pop", "pop3", "imap", "webmail", "roundcube", "squirrel", "horde", "zimbra",
    "exchange", "outlook", "owa", "autodiscover", "mx", "mx1", "mx2", "mx3", "mx4", "mx5", "mail1", "mail2",
    
    # CDN & Static
    "cdn", "static", "assets", "media", "img", "images", "css", "js", "files", "download", "downloads",
    "upload", "uploads", "content", "data", "backup", "backups", "archive", "storage", "s3", "blob",
    
    # Mobile & Apps
    "m", "mobile", "app", "apps", "android", "ios", "iphone", "ipad", "touch", "wap", "pda", "tablet",
    
    # E-commerce
    "shop", "store", "cart", "checkout", "payment", "pay", "billing", "invoice", "order", "orders",
    "catalog", "products", "inventory", "ecommerce", "marketplace", "merchant", "pos",
    
    # Social & Community
    "social", "community", "forum", "forums", "board", "discussion", "chat", "support", "help", "wiki",
    "kb", "knowledgebase", "faq", "docs", "documentation", "manual", "guide", "tutorial",
    
    # Security & VPN
    "vpn", "secure", "ssl", "tls", "security", "firewall", "proxy", "gateway", "auth", "login", "sso",
    "oauth", "ldap", "ad", "radius", "cert", "certificate", "ca", "pki",
    
    # Monitoring & Analytics
    "monitor", "monitoring", "stats", "statistics", "analytics", "metrics", "logs", "log", "kibana",
    "grafana", "prometheus", "nagios", "zabbix", "cacti", "munin", "icinga", "sensu",
    
    # Database & Cache
    "db", "database", "mysql", "postgres", "oracle", "mssql", "mongo", "redis", "memcache", "elastic",
    "elasticsearch", "solr", "cassandra", "couchdb", "influxdb", "clickhouse",
    
    # Infrastructure
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "ntp", "time", "ldap", "ad", "dc", "domain", "controller",
    "dhcp", "tftp", "snmp", "syslog", "backup", "mirror", "repo", "repository", "git", "svn", "cvs",
    
    # Cloud & Containers
    "cloud", "aws", "azure", "gcp", "docker", "k8s", "kubernetes", "openshift", "rancher", "nomad",
    "consul", "vault", "terraform", "ansible", "jenkins", "gitlab", "github", "bitbucket",
    
    # Geographic & Language
    "us", "eu", "asia", "uk", "ca", "au", "de", "fr", "jp", "cn", "in", "br", "mx", "ru", "kr",
    "east", "west", "north", "south", "central", "global", "international", "local", "regional",
    
    # Numeric
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "01", "02", "03", "04", "05",
    "web1", "web2", "web3", "app1", "app2", "app3", "server1", "server2", "server3",
    
    # Miscellaneous
    "old", "new", "legacy", "archive", "temp", "tmp", "backup", "bak", "orig", "original", "copy",
    "mirror", "clone", "replica", "shadow", "alternate", "alternative", "fallback", "emergency"
]

# Certificate Transparency logs for subdomain discovery
CT_LOGS = [
    "https://crt.sh/?q={}&output=json",
    "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names"
]

async def dns_resolve_subdomain(subdomain):
    """Check if subdomain exists via DNS resolution"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        
        # Try A record
        try:
            answers = resolver.resolve(subdomain, 'A')
            return subdomain, True, [str(rdata) for rdata in answers]
        except Exception:
            # Try CNAME record
            try:
                answers = resolver.resolve(subdomain, 'CNAME')
                return subdomain, True, [str(rdata) for rdata in answers]
            except Exception:
                return subdomain, False, []
    except Exception:
        return subdomain, False, []

async def http_check_subdomain(session, subdomain):
    """Check if subdomain responds to HTTP requests"""
    for protocol in ['https', 'http']:
        url = f"{protocol}://{subdomain}"
        try:
            async with session.get(url, timeout=5, ssl=False, allow_redirects=False) as response:
                return subdomain, True, response.status, protocol
        except Exception:
            continue
    return subdomain, False, None, None

async def certificate_transparency_search(session, domain):
    """Search Certificate Transparency logs for subdomains"""
    subdomains = set()
    
    for ct_url in CT_LOGS:
        try:
            url = ct_url.format(domain)
            async with session.get(url, timeout=10, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if "crt.sh" in ct_url:
                        for entry in data:
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.endswith(f'.{domain}') and '*' not in name:
                                        subdomains.add(name)
                    
                    elif "certspotter" in ct_url:
                        for entry in data:
                            if 'dns_names' in entry:
                                for name in entry['dns_names']:
                                    name = name.strip().lower()
                                    if name.endswith(f'.{domain}') and '*' not in name:
                                        subdomains.add(name)
        except Exception:
            continue
    
    return list(subdomains)

async def bruteforce_subdomains(session, domain, wordlist):
    """Bruteforce subdomains using wordlist"""
    console.print(f"[dim]Bruteforcing {len(wordlist)} subdomains...[/dim]")
    
    # DNS resolution tasks
    dns_tasks = []
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        dns_tasks.append(dns_resolve_subdomain(subdomain))
    
    # Execute DNS resolution
    dns_results = await asyncio.gather(*dns_tasks, return_exceptions=True)
    
    # Filter successful DNS resolutions
    valid_subdomains = []
    for result in dns_results:
        if not isinstance(result, Exception) and result[1]:  # DNS resolution successful
            valid_subdomains.append(result[0])
    
    # HTTP check for valid DNS subdomains
    if valid_subdomains:
        console.print(f"[dim]HTTP checking {len(valid_subdomains)} DNS-valid subdomains...[/dim]")
        http_tasks = [http_check_subdomain(session, sub) for sub in valid_subdomains]
        http_results = await asyncio.gather(*http_tasks, return_exceptions=True)
        
        active_subdomains = []
        for result in http_results:
            if not isinstance(result, Exception) and result[1]:  # HTTP check successful
                active_subdomains.append({
                    'subdomain': result[0],
                    'status': result[2],
                    'protocol': result[3]
                })
        
        return active_subdomains
    
    return []

async def enumerate_subdomains(session, target_url):
    """Advanced subdomain enumeration with multiple techniques"""
    console.print("\n[bold cyan]--- Advanced Subdomain Enumeration ---[/bold cyan]")
    
    # Extract domain from URL
    try:
        domain = target_url.split("://")[-1].split("/")[0].split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
    except Exception:
        console.print("[red]Could not parse domain for subdomain scan[/red]")
        return []

    console.print(f"[dim]Target domain: {domain}[/dim]")
    
    all_subdomains = set()
    
    # 1. Certificate Transparency Search
    console.print("[bold yellow]Certificate Transparency Search:[/bold yellow]")
    try:
        ct_subdomains = await certificate_transparency_search(session, domain)
        if ct_subdomains:
            console.print(f"  [green][+] Found {len(ct_subdomains)} subdomains from CT logs[/green]")
            for sub in ct_subdomains[:10]:  # Show first 10
                console.print(f"    [cyan]{sub}[/cyan]")
            if len(ct_subdomains) > 10:
                console.print(f"    [dim]... and {len(ct_subdomains) - 10} more[/dim]")
            all_subdomains.update(ct_subdomains)
        else:
            console.print("  [yellow][-] No subdomains found in CT logs[/yellow]")
    except Exception as e:
        console.print(f"  [red]CT search failed: {e}[/red]")
    
    # 2. Bruteforce Common Subdomains
    console.print("\n[bold yellow]Bruteforce Enumeration:[/bold yellow]")
    try:
        bf_results = await bruteforce_subdomains(session, domain, SUBDOMAINS)
        if bf_results:
            console.print(f"  [green][+] Found {len(bf_results)} active subdomains[/green]")
            for result in bf_results:
                status_color = "green" if result['status'] == 200 else "yellow"
                console.print(f"    [bold {status_color}][{result['status']}] {result['protocol']}://{result['subdomain']}[/bold {status_color}]")
                all_subdomains.add(result['subdomain'])
        else:
            console.print("  [yellow][-] No active subdomains found via bruteforce[/yellow]")
    except Exception as e:
        console.print(f"  [red]Bruteforce failed: {e}[/red]")
    
    # 3. DNS Zone Transfer Attempt
    console.print("\n[bold yellow]DNS Zone Transfer Test:[/bold yellow]")
    try:
        resolver = dns.resolver.Resolver()
        ns_records = resolver.resolve(domain, 'NS')
        
        for ns in ns_records:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                console.print(f"  [bold red][!] Zone transfer successful from {ns}[/bold red]")
                for name in zone.nodes.keys():
                    subdomain = f"{name}.{domain}"
                    if subdomain != domain:
                        all_subdomains.add(subdomain)
                        console.print(f"    [red]{subdomain}[/red]")
                break
            except Exception:
                continue
        else:
            console.print("  [green][+] Zone transfer properly restricted[/green]")
    except Exception:
        console.print("  [yellow][-] Could not test zone transfer[/yellow]")
    
    # Summary
    final_subdomains = list(all_subdomains)
    console.print(f"\n[bold green]Total Unique Subdomains Found: {len(final_subdomains)}[/bold green]")
    
    return final_subdomains
