"""Google Dork Generator — generates targeted search queries for reconnaissance."""

from urllib.parse import urlparse, quote_plus
from modules.core import console

def generate_dorks(domain):
    """Generate comprehensive Google dork queries for a target domain."""
    dorks = {
        'Sensitive Files': [
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:bak',
            f'site:{domain} filetype:old',
            f'site:{domain} filetype:conf',
            f'site:{domain} filetype:cfg',
            f'site:{domain} filetype:ini',
            f'site:{domain} filetype:xml',
            f'site:{domain} filetype:json',
            f'site:{domain} filetype:yml',
            f'site:{domain} filetype:csv',
            f'site:{domain} filetype:pem',
            f'site:{domain} filetype:key',
        ],
        'Admin Panels': [
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:dashboard',
            f'site:{domain} inurl:cpanel',
            f'site:{domain} inurl:phpmyadmin',
            f'site:{domain} intitle:"admin" inurl:admin',
            f'site:{domain} intitle:"login" inurl:login',
            f'site:{domain} intitle:"dashboard"',
        ],
        'Exposed Data': [
            f'site:{domain} intext:"password"',
            f'site:{domain} intext:"username" intext:"password"',
            f'site:{domain} intext:"api_key"',
            f'site:{domain} intext:"access_token"',
            f'site:{domain} intext:"secret_key"',
            f'site:{domain} intext:"database" filetype:sql',
            f'site:{domain} ext:txt intext:"password"',
        ],
        'Error Pages & Debug': [
            f'site:{domain} intext:"Fatal error"',
            f'site:{domain} intext:"Warning:" intext:"on line"',
            f'site:{domain} intext:"SQL syntax" intext:"mysql"',
            f'site:{domain} intext:"Stack Trace"',
            f'site:{domain} intext:"DEBUG" intext:"True"',
            f'site:{domain} intitle:"phpinfo()"',
            f'site:{domain} intext:"server at" intext:"port"',
        ],
        'Directory Listings': [
            f'site:{domain} intitle:"index of /"',
            f'site:{domain} intitle:"index of" "parent directory"',
            f'site:{domain} intitle:"index of" ".git"',
            f'site:{domain} intitle:"index of" "backup"',
        ],
        'Exposed APIs': [
            f'site:{domain} inurl:api',
            f'site:{domain} inurl:swagger',
            f'site:{domain} inurl:graphql',
            f'site:{domain} inurl:rest',
            f'site:{domain} inurl:v1',
            f'site:{domain} inurl:v2',
            f'site:{domain} ext:json inurl:api',
            f'site:{domain} inurl:".json" -inurl:".js"',
        ],
        'Backup & Config': [
            f'site:{domain} inurl:backup',
            f'site:{domain} inurl:config',
            f'site:{domain} inurl:".env"',
            f'site:{domain} inurl:"wp-config.php"',
            f'site:{domain} inurl:"web.config"',
            f'site:{domain} inurl:".git/HEAD"',
            f'site:{domain} inurl:".svn"',
            f'site:{domain} inurl:"robots.txt"',
            f'site:{domain} inurl:"sitemap.xml"',
        ],
        'Subdomains': [
            f'site:*.{domain}',
            f'site:*.{domain} -www',
            f'site:{domain} -www -site:www.{domain}',
        ],
    }
    return dorks


async def scan_google_dorks(session, url):
    """Generate and display Google dork queries for target."""
    console.print(f"\n[bold cyan]--- Google Dork Intelligence ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    dorks = generate_dorks(domain)
    total = sum(len(v) for v in dorks.values())
    console.print(f"  [green]Generated {total} targeted Google dorks for {domain}[/green]\n")

    results = {'domain': domain, 'categories': {}, 'total': total, 'urls': []}

    for category, queries in dorks.items():
        console.print(f"  [bold yellow]📂 {category}:[/bold yellow]")
        cat_urls = []
        for query in queries:
            search_url = f"https://www.google.com/search?q={quote_plus(query)}"
            console.print(f"    [dim]{query}[/dim]")
            cat_urls.append({'query': query, 'url': search_url})

        results['categories'][category] = cat_urls
        results['urls'].extend(cat_urls)
        console.print()

    console.print(f"  [bold green]💡 Copy any query into Google to find exposed data[/bold green]")
    console.print(f"  [dim]Tip: Use Google Hacking Database (exploit-db.com/google-hacking-database) for more[/dim]")

    return results
