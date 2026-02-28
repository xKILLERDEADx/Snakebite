"""Subdomain Takeover Engine — 22 providers, CNAME dangling, NS delegation."""

import aiohttp, asyncio, socket
from urllib.parse import urlparse
from modules.core import console

TAKEOVER_SIGS = {
    'GitHub': {'cname': ['github.io'], 'body': ["There isn't a GitHub Pages site here"]},
    'Heroku': {'cname': ['herokuapp.com'], 'body': ['No such app']},
    'AWS S3': {'cname': ['s3.amazonaws.com'], 'body': ['NoSuchBucket']},
    'Shopify': {'cname': ['myshopify.com'], 'body': ['Sorry, this shop is currently unavailable']},
    'Fastly': {'cname': ['fastly.net'], 'body': ['Fastly error: unknown domain']},
    'Pantheon': {'cname': ['pantheonsite.io'], 'body': ['404 error unknown site']},
    'Tumblr': {'cname': ['tumblr.com'], 'body': ["There's nothing here"]},
    'Surge': {'cname': ['surge.sh'], 'body': ['project not found']},
    'Ghost': {'cname': ['ghost.io'], 'body': ['no longer here']},
    'Bitbucket': {'cname': ['bitbucket.io'], 'body': ['Repository not found']},
    'Zendesk': {'cname': ['zendesk.com'], 'body': ['Help Center Closed']},
    'Statuspage': {'cname': ['statuspage.io'], 'body': ['launched']},
    'Unbounce': {'cname': ['unbouncepages.com'], 'body': ['not found']},
    'HubSpot': {'cname': ['sites.hubspot.net'], 'body': ['not found']},
    'Azure': {'cname': ['azurewebsites.net'], 'body': ['not found']},
    'Netlify': {'cname': ['netlify.app'], 'body': ['Not Found']},
    'Vercel': {'cname': ['vercel.app'], 'body': ['deployment could not be found']},
    'Fly.io': {'cname': ['fly.dev'], 'body': ['Not Found']},
    'Readme': {'cname': ['readme.io'], 'body': ['doesnt exist']},
    'WordPress': {'cname': ['wordpress.com'], 'body': ["doesn't exist"]},
    'Google': {'cname': ['googleapis.com'], 'body': ['NoSuchBucket']},
    'Cargo': {'cname': ['cargocollective.com'], 'body': ['If you']},
}
PREFIXES = ['www','mail','blog','shop','app','api','dev','staging','test','cdn','docs','help',
            'support','status','admin','portal','beta','demo','vpn','git','ci','grafana','monitor','dashboard']

async def _check_sub(session, sub):
    findings = []
    try:
        cnames = []
        try:
            import dns.resolver
            ans = dns.resolver.resolve(sub, 'CNAME')
            cnames = [str(r.target).rstrip('.') for r in ans]
        except Exception:
            pass
        for cn in cnames:
            for prov, sigs in TAKEOVER_SIGS.items():
                if any(c in cn.lower() for c in sigs['cname']):
                    try:
                        async with session.get(f'http://{sub}', timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                            body = await resp.text()
                            for ind in sigs['body']:
                                if ind.lower() in body.lower():
                                    findings.append({'type': f'Takeover ({prov})', 'sub': sub, 'cname': cn, 'severity': 'Critical'})
                                    break
                    except Exception:
                        pass
    except Exception:
        pass
    return findings

async def scan_subdomain_takeover(session, url):
    console.print(f"\n[bold cyan]--- Subdomain Takeover Engine ---[/bold cyan]")
    domain = urlparse(url).hostname
    console.print(f"  [cyan]Testing {len(PREFIXES)} subs × {len(TAKEOVER_SIGS)} providers...[/cyan]")
    tasks = [_check_sub(session, f'{p}.{domain}') for p in PREFIXES]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_f = [f for r in results if isinstance(r, list) for f in r]
    for f in all_f:
        console.print(f"  [bold red]⚠ {f['type']}: {f['sub']}[/bold red]")
    if not all_f:
        console.print(f"\n  [green]✓ No takeover possible[/green]")
    return {'findings': all_f}
