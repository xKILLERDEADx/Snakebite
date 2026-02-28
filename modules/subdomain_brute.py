"""Subdomain Brute Force — discover subdomains via DNS brute forcing."""

import asyncio
import socket
from modules.core import console

SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
    'smtp', 'secure', 'vpn', 'admin', 'api', 'dev', 'staging', 'test',
    'web', 'portal', 'ftp', 'cdn', 'cloud', 'git', 'gitlab', 'jenkins',
    'ci', 'docs', 'status', 'monitoring', 'grafana', 'prometheus',
    'app', 'mobile', 'm', 'beta', 'alpha', 'preview', 'demo',
    'internal', 'intranet', 'extranet', 'private', 'secret',
    'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
    'login', 'sso', 'auth', 'oauth', 'id', 'identity',
    'shop', 'store', 'checkout', 'payment', 'pay', 'billing',
    'support', 'help', 'helpdesk', 'ticket', 'jira', 'service',
    'chat', 'im', 'slack', 'teams', 'meet', 'zoom',
    'backup', 'bak', 'old', 'legacy', 'archive', 'temp',
    'proxy', 'gateway', 'edge', 'lb', 'load', 'balancer',
    'k8s', 'kubernetes', 'docker', 'registry', 'container',
    'aws', 'azure', 'gcp', 'cloud', 's3', 'storage',
    'api1', 'api2', 'api3', 'v1', 'v2', 'v3',
    'stage', 'stg', 'uat', 'qa', 'prod', 'production',
    'mx', 'mx1', 'mx2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
    'img', 'images', 'static', 'assets', 'media', 'files',
    'cpanel', 'whm', 'plesk', 'panel', 'control',
    'exchange', 'owa', 'autodiscover', 'webdav',
    'vpn1', 'vpn2', 'remote1', 'access', 'connect',
    'wiki', 'confluence', 'knowledge', 'docs', 'doc',
    'crm', 'erp', 'hr', 'finance', 'accounting',
    'dev1', 'dev2', 'test1', 'test2', 'sandbox',
    'monitor', 'nagios', 'zabbix', 'splunk', 'elk', 'kibana',
    'repo', 'svn', 'cvs', 'hg', 'code', 'source',
    'analytics', 'stats', 'tracking', 'metrics',
    'relay', 'smtp2', 'imap', 'pop', 'pop3',
    'sentry', 'error', 'log', 'logs', 'audit',
    'cache', 'memcache', 'varnish', 'squid',
    'mq', 'rabbit', 'kafka', 'queue', 'worker',
    'ws', 'websocket', 'socket', 'realtime', 'push',
]


async def _resolve_subdomain(domain, semaphore):
    """Resolve a single subdomain."""
    async with semaphore:
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            return {'subdomain': domain, 'ip': ip, 'alive': True}
        except Exception:
            return None


async def scan_subdomain_brute(session, url):
    """Brute force subdomains via DNS resolution."""
    console.print(f"\n[bold cyan]--- Subdomain Brute Force ---[/bold cyan]")

    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    parts = domain.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    console.print(f"  [cyan]Brute forcing {len(SUBDOMAIN_WORDLIST)} subdomains for {base_domain}...[/cyan]")

    semaphore = asyncio.Semaphore(50)
    tasks = []
    for word in SUBDOMAIN_WORDLIST:
        sub = f"{word}.{base_domain}"
        tasks.append(_resolve_subdomain(sub, semaphore))

    results_raw = await asyncio.gather(*tasks)
    found = [r for r in results_raw if r]

    categorized = {
        'admin': [], 'dev': [], 'api': [], 'mail': [],
        'cloud': [], 'monitoring': [], 'other': [],
    }

    for entry in found:
        sub = entry['subdomain'].split('.')[0]
        if sub in ('admin', 'panel', 'cpanel', 'control', 'whm', 'plesk'):
            categorized['admin'].append(entry)
        elif sub in ('dev', 'staging', 'test', 'beta', 'sandbox', 'uat'):
            categorized['dev'].append(entry)
        elif sub in ('api', 'api1', 'api2', 'v1', 'v2', 'graphql'):
            categorized['api'].append(entry)
        elif sub in ('mail', 'smtp', 'imap', 'pop', 'mx', 'webmail', 'exchange'):
            categorized['mail'].append(entry)
        elif sub in ('aws', 'azure', 'gcp', 'cloud', 's3', 'k8s', 'docker'):
            categorized['cloud'].append(entry)
        elif sub in ('monitor', 'grafana', 'prometheus', 'nagios', 'kibana', 'splunk'):
            categorized['monitoring'].append(entry)
        else:
            categorized['other'].append(entry)

    unique_ips = set(f['ip'] for f in found)

    if found:
        console.print(f"\n  [bold green]{len(found)} subdomains found ({len(unique_ips)} unique IPs)[/bold green]")

        for cat, entries in categorized.items():
            if entries:
                cat_color = 'red' if cat in ('admin', 'dev') else 'yellow' if cat in ('api', 'cloud') else 'dim'
                console.print(f"\n  [{cat_color}]{cat.upper()} ({len(entries)}):[/{cat_color}]")
                for e in entries[:5]:
                    console.print(f"    [{cat_color}]{e['subdomain']} → {e['ip']}[/{cat_color}]")
    else:
        console.print(f"\n  [dim]No subdomains found via brute force[/dim]")

    return {
        'domain': base_domain,
        'total_found': len(found),
        'unique_ips': len(unique_ips),
        'subdomains': found,
        'categories': {k: len(v) for k, v in categorized.items()},
    }
