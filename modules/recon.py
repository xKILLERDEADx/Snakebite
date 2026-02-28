import aiohttp
import asyncio
import ssl
import socket
import re
import hashlib
import json
from urllib.parse import urlparse
from datetime import datetime
from modules.core import console

try:
    import whois
    _WHOIS_AVAILABLE = True
except Exception:
    _WHOIS_AVAILABLE = False

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except Exception:
    _DNS_AVAILABLE = False

try:
    import mmh3
    _MMH3_AVAILABLE = True
except Exception:
    _MMH3_AVAILABLE = False


SECURITY_HEADERS = {
    'Strict-Transport-Security': {'name': 'HSTS', 'severity': 'High'},
    'Content-Security-Policy': {'name': 'CSP', 'severity': 'High'},
    'X-Frame-Options': {'name': 'X-Frame-Options', 'severity': 'Medium'},
    'X-Content-Type-Options': {'name': 'X-Content-Type-Options', 'severity': 'Medium'},
    'X-XSS-Protection': {'name': 'X-XSS-Protection', 'severity': 'Low'},
    'Referrer-Policy': {'name': 'Referrer-Policy', 'severity': 'Low'},
    'Permissions-Policy': {'name': 'Permissions-Policy', 'severity': 'Medium'},
    'Cross-Origin-Opener-Policy': {'name': 'COOP', 'severity': 'Low'},
    'Cross-Origin-Resource-Policy': {'name': 'CORP', 'severity': 'Low'},
    'Cross-Origin-Embedder-Policy': {'name': 'COEP', 'severity': 'Low'},
    'X-Permitted-Cross-Domain-Policies': {'name': 'X-Permitted-Cross-Domain', 'severity': 'Low'},
    'Cache-Control': {'name': 'Cache-Control', 'severity': 'Info'},
    'Pragma': {'name': 'Pragma', 'severity': 'Info'},
    'X-DNS-Prefetch-Control': {'name': 'DNS-Prefetch-Control', 'severity': 'Info'},
    'Feature-Policy': {'name': 'Feature-Policy', 'severity': 'Low'},
}

WAF_SIGNATURES = {
    'Cloudflare': {'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'], 'server': ['cloudflare'], 'cookies': ['__cfduid', '__cf_bm', 'cf_clearance']},
    'AWS WAF/Shield': {'headers': ['x-amzn-requestid', 'x-amz-cf-id'], 'server': ['amazons3', 'awselb', 'cloudfront'], 'cookies': ['awsalb', 'awsalbcors']},
    'Akamai': {'headers': ['x-akamai-transformed'], 'server': ['akamaghost', 'akamai'], 'cookies': ['akamai']},
    'Imperva/Incapsula': {'headers': ['x-iinfo', 'x-cdn'], 'server': ['imperva', 'incapsula'], 'cookies': ['incap_ses', 'visid_incap']},
    'Sucuri': {'headers': ['x-sucuri-id', 'x-sucuri-cache'], 'server': ['sucuri'], 'cookies': ['sucuri']},
    'F5 BIG-IP': {'headers': ['x-wa-info'], 'server': ['big-ip', 'bigip', 'f5'], 'cookies': ['bigipserver', 'ts', 'f5']},
    'Barracuda': {'headers': ['barra_counter_session'], 'server': ['barracuda'], 'cookies': ['barra_counter_session']},
    'Fortinet/FortiWeb': {'headers': ['fortiwafsid'], 'server': ['fortiweb'], 'cookies': ['cookiesession1']},
    'Citrix NetScaler': {'headers': ['cneonction', 'nncoection'], 'server': ['netscaler'], 'cookies': ['ns_af', 'citrix_ns_id']},
    'ModSecurity': {'headers': [], 'server': ['mod_security', 'modsecurity'], 'cookies': []},
    'Wordfence': {'headers': [], 'server': ['wordfence'], 'cookies': ['wfwaf-authcookie']},
    'DDoS-Guard': {'headers': [], 'server': ['ddos-guard'], 'cookies': ['__ddg']},
    'StackPath': {'headers': ['x-sp-url', 'x-sp-wl'], 'server': ['stackpath'], 'cookies': []},
    'Fastly': {'headers': ['x-served-by', 'x-cache', 'x-cache-hits', 'x-timer'], 'server': ['fastly'], 'cookies': []},
    'Varnish': {'headers': ['x-varnish', 'via'], 'server': ['varnish'], 'cookies': []},
    'Reblaze': {'headers': ['rbzid'], 'server': ['reblaze'], 'cookies': ['rbzid']},
    'SiteLock': {'headers': ['x-sitelock'], 'server': ['sitelock'], 'cookies': []},
    'Comodo': {'headers': ['x-cw-kid'], 'server': ['comodo'], 'cookies': []},
    'Edgecast/Verizon': {'headers': ['x-ec-custom-error'], 'server': ['ecs', 'ecd'], 'cookies': []},
    'KeyCDN': {'headers': ['x-edge-location'], 'server': ['keycdn'], 'cookies': []},
    'ArvanCloud': {'headers': ['ar-poweredby', 'ar-sid'], 'server': ['arvancloud'], 'cookies': []},
    'Azure WAF': {'headers': ['x-azure-ref'], 'server': ['microsoft-azure'], 'cookies': []},
    'Google Cloud Armor': {'headers': ['x-goog-request-info'], 'server': ['gws', 'gse'], 'cookies': []},
    'Alibaba Cloud WAF': {'headers': ['ali-swift-global-savetime'], 'server': ['tengine'], 'cookies': ['ali_beacon_id']},
}

SOCIAL_MEDIA_PATTERNS = {
    'Twitter/X': [r'(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/[\w]+', r'@[\w]+'],
    'Facebook': [r'(?:https?://)?(?:www\.)?facebook\.com/[\w.]+'],
    'Instagram': [r'(?:https?://)?(?:www\.)?instagram\.com/[\w.]+'],
    'LinkedIn': [r'(?:https?://)?(?:www\.)?linkedin\.com/(?:company|in)/[\w-]+'],
    'GitHub': [r'(?:https?://)?(?:www\.)?github\.com/[\w-]+'],
    'YouTube': [r'(?:https?://)?(?:www\.)?youtube\.com/(?:c/|channel/|@)[\w-]+'],
    'TikTok': [r'(?:https?://)?(?:www\.)?tiktok\.com/@[\w.]+'],
    'Pinterest': [r'(?:https?://)?(?:www\.)?pinterest\.com/[\w]+'],
    'Telegram': [r'(?:https?://)?(?:t\.me|telegram\.me)/[\w]+'],
    'Discord': [r'(?:https?://)?discord\.(?:gg|com/invite)/[\w]+'],
}

EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


async def whois_lookup(domain):
    """Perform WHOIS lookup on domain."""
    results = {}
    if not _WHOIS_AVAILABLE:
        console.print("  [yellow][!] python-whois not installed. Run: pip install python-whois[/yellow]")
        return results

    try:
        w = whois.whois(domain)
        if w:
            results['domain_name'] = str(w.domain_name) if w.domain_name else domain
            results['registrar'] = str(w.registrar) if w.registrar else 'N/A'

            if w.creation_date:
                cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                results['created'] = str(cd)
            else:
                results['created'] = 'N/A'

            if w.expiration_date:
                ed = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                results['expires'] = str(ed)
                if isinstance(ed, datetime):
                    try:
                        ed_naive = ed.replace(tzinfo=None) if ed.tzinfo else ed
                        days = (ed_naive - datetime.now()).days
                        results['days_until_expiry'] = days
                    except Exception:
                        pass
            else:
                results['expires'] = 'N/A'

            if w.updated_date:
                ud = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date
                results['updated'] = str(ud)

            results['country'] = str(w.country) if w.country else 'N/A'
            results['state'] = str(w.state) if w.state else 'N/A'
            results['org'] = str(w.org) if w.org else 'N/A'
            results['emails'] = w.emails if w.emails else []

            if w.name_servers:
                ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                results['nameservers'] = [str(n).lower() for n in ns]
            else:
                results['nameservers'] = []

            results['dnssec'] = str(w.dnssec) if hasattr(w, 'dnssec') and w.dnssec else 'N/A'
            results['status'] = w.status if w.status else []

            console.print("  [bold cyan]🌐 WHOIS Information[/bold cyan]")
            console.print(f"    [green]Domain:[/green]     {results.get('domain_name', 'N/A')}")
            console.print(f"    [green]Registrar:[/green]  {results.get('registrar', 'N/A')}")
            console.print(f"    [green]Created:[/green]    {results.get('created', 'N/A')}")
            console.print(f"    [green]Expires:[/green]    {results.get('expires', 'N/A')}")
            if 'days_until_expiry' in results:
                color = "red" if results['days_until_expiry'] < 30 else "yellow" if results['days_until_expiry'] < 90 else "green"
                console.print(f"    [green]Days Left:[/green]  [{color}]{results['days_until_expiry']} days[/{color}]")
            console.print(f"    [green]Country:[/green]    {results.get('country', 'N/A')}")
            console.print(f"    [green]Org:[/green]        {results.get('org', 'N/A')}")
            if results.get('nameservers'):
                console.print(f"    [green]Nameservers:[/green] {', '.join(results['nameservers'][:4])}")
            if results.get('emails'):
                emails = results['emails'] if isinstance(results['emails'], list) else [results['emails']]
                console.print(f"    [green]WHOIS Emails:[/green] {', '.join(emails[:5])}")
    except Exception as e:
        console.print(f"  [red][!] WHOIS lookup failed: {e}[/red]")
        results['error'] = str(e)

    return results


async def dns_records(domain):
    """Fetch all DNS record types."""
    results = {}
    if not _DNS_AVAILABLE:
        console.print("  [yellow][!] dnspython not installed[/yellow]")
        return results

    console.print("  [bold cyan]📡 DNS Records[/bold cyan]")

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    for rtype in record_types:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(domain, rtype)
            records = []

            for rdata in answers:
                if rtype == 'MX':
                    records.append({'priority': rdata.preference, 'server': str(rdata.exchange).rstrip('.')})
                elif rtype == 'SOA':
                    records.append({
                        'mname': str(rdata.mname).rstrip('.'),
                        'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    })
                else:
                    records.append(str(rdata).rstrip('.').strip('"'))

            if records:
                results[rtype] = records
                if rtype == 'MX':
                    mx_str = ', '.join([f"{r['server']} (pri:{r['priority']})" for r in records[:5]])
                    console.print(f"    [green]{rtype}:[/green] {mx_str}")
                elif rtype == 'SOA':
                    console.print(f"    [green]{rtype}:[/green] {records[0]['mname']} (serial: {records[0]['serial']})")
                elif rtype == 'TXT':
                    for txt in records[:3]:
                        display = txt[:80] + '...' if len(txt) > 80 else txt
                        console.print(f"    [green]{rtype}:[/green] {display}")
                else:
                    console.print(f"    [green]{rtype}:[/green] {', '.join(records[:5])}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            console.print(f"    [red]{rtype}: Domain does not exist[/red]")
            break
        except Exception:
            pass

    return results


async def ip_geolocation(session, ip_address):
    """Get IP geolocation data from ip-api.com (free, no key)."""
    results = {}
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            data = await resp.json()
            if data.get('status') == 'success':
                results = {
                    'ip': data.get('query', ip_address),
                    'country': data.get('country', 'N/A'),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'zip': data.get('zip', ''),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'timezone': data.get('timezone', ''),
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'asn': data.get('as', 'N/A'),
                    'as_name': data.get('asname', 'N/A'),
                    'reverse_dns': data.get('reverse', ''),
                    'is_proxy': data.get('proxy', False),
                    'is_hosting': data.get('hosting', False),
                    'is_mobile': data.get('mobile', False),
                }

                console.print("  [bold cyan]📍 IP Intelligence[/bold cyan]")
                console.print(f"    [green]IP:[/green]        {results['ip']}")
                console.print(f"    [green]Country:[/green]   {results['country']} ({results['country_code']})")
                console.print(f"    [green]City:[/green]      {results['city']}, {results['region']}")
                console.print(f"    [green]ISP:[/green]       {results['isp']}")
                console.print(f"    [green]Org:[/green]       {results['org']}")
                console.print(f"    [green]ASN:[/green]       {results['asn']}")
                console.print(f"    [green]Coords:[/green]    {results['lat']}, {results['lon']}")
                if results['reverse_dns']:
                    console.print(f"    [green]rDNS:[/green]      {results['reverse_dns']}")
                if results['is_proxy']:
                    console.print(f"    [bold yellow]⚠ Proxy/VPN detected[/bold yellow]")
                if results['is_hosting']:
                    console.print(f"    [dim]Hosting provider IP[/dim]")
    except Exception as e:
        console.print(f"  [red][!] IP geolocation failed: {e}[/red]")

    return results


async def reverse_ip_lookup(session, ip_address):
    """Find other domains on the same IP."""
    results = []
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            text = await resp.text()
            if 'error' not in text.lower() and 'no records' not in text.lower() and 'API count' not in text:
                domains = [d.strip() for d in text.strip().split('\n') if d.strip() and '.' in d]
                results = domains[:50]

                console.print(f"  [bold cyan]🔁 Reverse IP Lookup[/bold cyan]")
                console.print(f"    [green]Domains on same IP:[/green] {len(results)} found")
                for d in results[:10]:
                    console.print(f"      [dim]• {d}[/dim]")
                if len(results) > 10:
                    console.print(f"      [dim]... and {len(results) - 10} more[/dim]")
    except Exception as e:
        console.print(f"  [red][!] Reverse IP failed: {e}[/red]")

    return results


async def check_security_headers(headers_dict):
    """Comprehensive security header analysis — 15+ headers."""
    results = {'present': {}, 'missing': [], 'score': 0}
    present_count = 0
    total = len(SECURITY_HEADERS)

    console.print("  [bold cyan]🔒 Security Headers Analysis[/bold cyan]")

    for header, info in SECURITY_HEADERS.items():
        found = False
        for h_key, h_val in headers_dict.items():
            if h_key.lower() == header.lower():
                results['present'][info['name']] = str(h_val)
                present_count += 1
                found = True
                console.print(f"    [green]✓ {info['name']}:[/green] {str(h_val)[:80]}")
                break
        if not found:
            results['missing'].append({'name': info['name'], 'severity': info['severity']})
            sev_color = 'red' if info['severity'] == 'High' else 'yellow' if info['severity'] == 'Medium' else 'dim'
            console.print(f"    [{sev_color}]✗ {info['name']}: MISSING ({info['severity']})[/{sev_color}]")

    results['score'] = round((present_count / total) * 100)
    color = 'red' if results['score'] < 40 else 'yellow' if results['score'] < 70 else 'green'
    console.print(f"    [{color}]Score: {results['score']}% ({present_count}/{total} present)[/{color}]")

    return results


async def detect_waf(headers_dict, cookies_dict, server_header, response_body=""):
    """Detect WAF/CDN from 25+ signatures."""
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in headers_dict.items()}
    server_lower = server_header.lower()
    cookies_lower = {k.lower(): v.lower() for k, v in cookies_dict.items()} if cookies_dict else {}

    for waf_name, sigs in WAF_SIGNATURES.items():
        confidence = 0

        for h in sigs.get('headers', []):
            if h.lower() in headers_lower:
                confidence += 40
                break

        for s in sigs.get('server', []):
            if s in server_lower:
                confidence += 50
                break

        for c in sigs.get('cookies', []):
            for cookie_name in cookies_lower:
                if c.lower() in cookie_name:
                    confidence += 30
                    break

        if confidence >= 30:
            detected.append({'name': waf_name, 'confidence': min(confidence, 100)})

    if detected:
        console.print("  [bold cyan]🛡️ WAF/CDN Detection[/bold cyan]")
        for waf in detected:
            color = 'bold red' if waf['confidence'] >= 70 else 'bold yellow'
            console.print(f"    [{color}]{waf['name']}[/{color}] (confidence: {waf['confidence']}%)")
    else:
        console.print("  [bold cyan]🛡️ WAF/CDN Detection[/bold cyan]")
        console.print("    [green]No WAF/CDN detected[/green]")

    return detected


async def fingerprint_technology(headers_dict, response_body=""):
    """Fingerprint server technology from headers."""
    tech = {}

    server = headers_dict.get('Server', headers_dict.get('server', ''))
    if server:
        tech['server'] = server

    powered = headers_dict.get('X-Powered-By', headers_dict.get('x-powered-by', ''))
    if powered:
        tech['powered_by'] = powered

    aspnet = headers_dict.get('X-AspNet-Version', headers_dict.get('x-aspnet-version', ''))
    if aspnet:
        tech['aspnet_version'] = aspnet

    aspnetmvc = headers_dict.get('X-AspNetMvc-Version', '')
    if aspnetmvc:
        tech['aspnetmvc_version'] = aspnetmvc

    gen = headers_dict.get('X-Generator', headers_dict.get('x-generator', ''))
    if gen:
        tech['generator'] = gen

    drupal = headers_dict.get('X-Drupal-Cache', '')
    if drupal:
        tech['cms'] = 'Drupal'

    wp_indicator = headers_dict.get('Link', '')
    if 'wp-json' in wp_indicator:
        tech['cms'] = 'WordPress'

    via = headers_dict.get('Via', '')
    if via:
        tech['proxy_via'] = via

    if tech:
        console.print("  [bold cyan]⚙️ Technology Fingerprint[/bold cyan]")
        for key, val in tech.items():
            name = key.replace('_', ' ').title()
            console.print(f"    [green]{name}:[/green] {val}")

    return tech


async def ssl_certificate_info(hostname):
    """Get SSL certificate details."""
    results = {}
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(10)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        if cert:
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            sans = [entry[1] for entry in cert.get('subjectAltName', []) if entry[0] == 'DNS']

            not_before = cert.get('notBefore', '')
            not_after = cert.get('notAfter', '')

            days_remaining = 0
            if not_after:
                try:
                    expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_dt - datetime.now()).days
                except Exception:
                    pass

            results = {
                'common_name': subject.get('commonName', 'N/A'),
                'issuer_cn': issuer.get('commonName', 'N/A'),
                'issuer_org': issuer.get('organizationName', 'N/A'),
                'not_before': not_before,
                'not_after': not_after,
                'days_remaining': days_remaining,
                'serial': cert.get('serialNumber', ''),
                'version': cert.get('version', ''),
                'sans': sans[:20],
                'san_count': len(sans),
            }

            console.print("  [bold cyan]🔐 SSL Certificate[/bold cyan]")
            console.print(f"    [green]CN:[/green]          {results['common_name']}")
            console.print(f"    [green]Issuer:[/green]      {results['issuer_cn']} ({results['issuer_org']})")
            console.print(f"    [green]Valid From:[/green]   {results['not_before']}")
            console.print(f"    [green]Valid Until:[/green]  {results['not_after']}")
            exp_color = 'red' if days_remaining < 30 else 'yellow' if days_remaining < 90 else 'green'
            console.print(f"    [{exp_color}]Days Left:   {days_remaining} days[/{exp_color}]")
            console.print(f"    [green]SANs:[/green]        {len(sans)} domains")
            for san in sans[:5]:
                console.print(f"      [dim]• {san}[/dim]")
            if len(sans) > 5:
                console.print(f"      [dim]... and {len(sans) - 5} more[/dim]")
    except Exception as e:
        console.print(f"  [dim]SSL info unavailable: {e}[/dim]")
        results['error'] = str(e)

    return results


async def wayback_urls(session, domain):
    """Get historical URLs from the Wayback Machine."""
    results = []
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20), ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                data = json.loads(text)
                if data and len(data) > 1:
                    results = [row[0] for row in data[1:] if row]

                    console.print(f"  [bold cyan]📜 Wayback Machine URLs[/bold cyan]")
                    console.print(f"    [green]Archived URLs found:[/green] {len(results)}")

                    interesting = [u for u in results if any(x in u.lower() for x in
                        ['admin', 'login', 'api', 'config', 'backup', '.env', 'dashboard', 'panel',
                         'upload', 'secret', 'token', 'password', 'database', '.sql', '.zip',
                         '.bak', 'phpinfo', 'wp-config', '.git', 'swagger'])]

                    if interesting:
                        console.print(f"    [bold yellow]Interesting paths: {len(interesting)}[/bold yellow]")
                        for u in interesting[:8]:
                            console.print(f"      [yellow]• {u[:100]}[/yellow]")
                else:
                    console.print(f"  [bold cyan]📜 Wayback Machine URLs[/bold cyan]")
                    console.print(f"    [dim]No archived URLs found[/dim]")
    except Exception as e:
        console.print(f"  [dim]Wayback Machine unavailable: {e}[/dim]")

    return results


async def extract_emails(response_body, domain):
    """Extract email addresses from page content."""
    results = []
    try:
        emails = set(re.findall(EMAIL_PATTERN, response_body))
        emails = [e for e in emails if not e.endswith(('.png', '.jpg', '.gif', '.css', '.js', '.svg', '.woff', '.woff2'))]
        results = list(emails)[:30]

        if results:
            console.print(f"  [bold cyan]📧 Email Addresses Found[/bold cyan]")
            for email in results[:10]:
                highlight = "bold yellow" if domain in email else "dim"
                console.print(f"    [{highlight}]• {email}[/{highlight}]")
            if len(results) > 10:
                console.print(f"    [dim]... and {len(results) - 10} more[/dim]")
    except Exception:
        pass

    return results


async def extract_social_media(response_body):
    """Extract social media links from page content."""
    results = {}
    try:
        for platform, patterns in SOCIAL_MEDIA_PATTERNS.items():
            found = set()
            for pat in patterns:
                matches = re.findall(pat, response_body, re.IGNORECASE)
                for m in matches:
                    if len(m) > 5 and len(m) < 200:
                        found.add(m.strip())
            if found:
                results[platform] = list(found)[:5]

        if results:
            console.print(f"  [bold cyan]📱 Social Media Links[/bold cyan]")
            for platform, links in results.items():
                for link in links[:2]:
                    console.print(f"    [green]{platform}:[/green] {link}")
    except Exception:
        pass

    return results


async def favicon_hash(session, base_url):
    """Calculate favicon hash for Shodan fingerprinting."""
    results = {}
    if not _MMH3_AVAILABLE:
        return results

    favicon_paths = ['/favicon.ico', '/assets/favicon.ico', '/images/favicon.ico']

    for path in favicon_paths:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    if len(content) > 0:
                        import codecs
                        b64 = codecs.encode(content, 'base64')
                        fav_hash = mmh3.hash(b64)
                        results = {
                            'hash': fav_hash,
                            'path': path,
                            'size': len(content),
                            'shodan_query': f'http.favicon.hash:{fav_hash}'
                        }
                        console.print(f"  [bold cyan]🎨 Favicon Hash[/bold cyan]")
                        console.print(f"    [green]Hash:[/green]   {fav_hash}")
                        console.print(f"    [green]Shodan:[/green] http.favicon.hash:{fav_hash}")
                        console.print(f"    [dim]Path: {path} ({len(content)} bytes)[/dim]")
                        break
        except Exception:
            continue

    return results


async def full_http_analysis(session, url):
    """Complete HTTP response analysis."""
    results = {}
    try:
        import time as _t
        start = _t.time()
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False, allow_redirects=True) as resp:
            elapsed = _t.time() - start
            body = await resp.text(errors='replace')

            headers_dict = dict(resp.headers)
            cookies_dict = {k: v.value for k, v in resp.cookies.items()} if resp.cookies else {}

            results = {
                'status_code': resp.status,
                'response_time': round(elapsed, 3),
                'final_url': str(resp.url),
                'content_length': len(body),
                'content_type': resp.headers.get('Content-Type', ''),
                'headers': headers_dict,
                'cookies': cookies_dict,
                'cookie_count': len(cookies_dict),
                'redirect_count': len(resp.history),
                'body': body,
            }

            if resp.history:
                results['redirects'] = [str(r.url) for r in resp.history]

            console.print("  [bold cyan]🌍 HTTP Response Analysis[/bold cyan]")
            status_color = 'green' if resp.status == 200 else 'yellow' if resp.status < 400 else 'red'
            console.print(f"    [green]Status:[/green]    [{status_color}]{resp.status}[/{status_color}]")
            console.print(f"    [green]Time:[/green]      {elapsed:.3f}s")
            console.print(f"    [green]Size:[/green]      {len(body):,} bytes")
            console.print(f"    [green]Type:[/green]      {results['content_type']}")
            console.print(f"    [green]Cookies:[/green]   {len(cookies_dict)}")
            if resp.history:
                console.print(f"    [green]Redirects:[/green] {len(resp.history)}")
                for r in resp.history:
                    console.print(f"      [dim]→ {r.url}[/dim]")
            console.print(f"    [green]Final URL:[/green] {resp.url}")
    except Exception as e:
        console.print(f"  [red][!] HTTP analysis failed: {e}[/red]")

    return results


async def run_recon(session, url):
    """Ultra Intelligence Reconnaissance Engine — gathers ALL information about a target."""
    console.print("\n[bold red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]")
    console.print("[bold red]  🐍 SNAKEBITE INTELLIGENCE RECONNAISSANCE ENGINE[/bold red]")
    console.print("[bold red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]\n")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    results = {
        'target': url,
        'domain': domain,
        'base_url': base_url,
    }

    try:
        ip_address = socket.gethostbyname(domain)
        results['ip'] = ip_address
        console.print(f"  [green]Target:[/green] {url}")
        console.print(f"  [green]Domain:[/green] {domain}")
        console.print(f"  [green]IP:[/green]     {ip_address}\n")
    except Exception:
        ip_address = None
        console.print(f"  [green]Target:[/green] {url}")
        console.print(f"  [green]Domain:[/green] {domain}\n")

    console.print("[bold magenta]Phase 1: HTTP & Technology Analysis[/bold magenta]")
    http_data = await full_http_analysis(session, url)
    results['http'] = http_data
    print()

    headers_dict = http_data.get('headers', {})
    cookies_dict = http_data.get('cookies', {})
    body = http_data.get('body', '')
    server_header = headers_dict.get('Server', headers_dict.get('server', ''))

    sec_headers = await check_security_headers(headers_dict)
    results['security_headers'] = sec_headers
    print()

    waf_data = await detect_waf(headers_dict, cookies_dict, server_header, body)
    results['waf'] = waf_data
    print()

    tech_data = await fingerprint_technology(headers_dict, body)
    results['technology'] = tech_data
    print()

    console.print("[bold magenta]Phase 2: Domain Intelligence[/bold magenta]")
    whois_data = await whois_lookup(domain)
    results['whois'] = whois_data
    print()

    dns_data = await dns_records(domain)
    results['dns'] = dns_data
    print()

    console.print("[bold magenta]Phase 3: IP Intelligence[/bold magenta]")
    if ip_address:
        geo_data = await ip_geolocation(session, ip_address)
        results['geolocation'] = geo_data
        print()

        reverse_data = await reverse_ip_lookup(session, ip_address)
        results['reverse_ip'] = reverse_data
        results['shared_hosting_count'] = len(reverse_data)
        print()

    console.print("[bold magenta]Phase 4: SSL & Cryptography[/bold magenta]")
    ssl_data = await ssl_certificate_info(domain)
    results['ssl'] = ssl_data
    print()

    console.print("[bold magenta]Phase 5: OSINT & Historical Data[/bold magenta]")
    wayback_data = await wayback_urls(session, domain)
    results['wayback'] = wayback_data
    results['wayback_count'] = len(wayback_data)
    print()

    emails = await extract_emails(body, domain)
    results['emails'] = emails
    print()

    social = await extract_social_media(body)
    results['social_media'] = social
    print()

    console.print("[bold magenta]Phase 6: Fingerprinting[/bold magenta]")
    fav_data = await favicon_hash(session, base_url)
    results['favicon'] = fav_data
    print()

    console.print("[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]")
    console.print("[bold green]  ✅ INTELLIGENCE GATHERING COMPLETE[/bold green]")

    stats = []
    if results.get('whois') and 'error' not in results['whois']: stats.append("WHOIS ✓")
    if results.get('dns'): stats.append(f"DNS ({len(results['dns'])} types) ✓")
    if results.get('geolocation'): stats.append("GeoIP ✓")
    if results.get('reverse_ip'): stats.append(f"Reverse IP ({len(results['reverse_ip'])} domains) ✓")
    if results.get('ssl') and 'error' not in results.get('ssl', {}): stats.append("SSL ✓")
    if results.get('wayback'): stats.append(f"Wayback ({len(results['wayback'])} URLs) ✓")
    if results.get('emails'): stats.append(f"Emails ({len(results['emails'])}) ✓")
    if results.get('social_media'): stats.append(f"Social ({len(results['social_media'])} platforms) ✓")
    if results.get('waf'): stats.append(f"WAF ({len(results['waf'])} detected) ✓")
    if results.get('favicon'): stats.append("Favicon ✓")

    console.print(f"  [dim]{' | '.join(stats)}[/dim]")
    console.print("[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]\n")

    return results