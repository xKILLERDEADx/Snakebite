"""Email Harvester — extract email addresses from target and public sources."""

import aiohttp
import asyncio
import re
from urllib.parse import urlparse, urljoin
from modules.core import console

EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

COMMON_PAGES = [
    '/', '/contact', '/about', '/team', '/staff', '/people',
    '/contact-us', '/about-us', '/our-team', '/leadership',
    '/privacy', '/privacy-policy', '/terms', '/support',
    '/careers', '/jobs', '/press', '/investors',
    '/sitemap.xml', '/humans.txt',
]

SEARCH_ENGINES = [
    'https://www.google.com/search?q="%40{domain}"+email',
    'https://www.bing.com/search?q="%40{domain}"+email',
]

IGNORE_PATTERNS = [
    'example.com', 'test.com', 'domain.com', 'email.com',
    'yoursite.com', 'sentry.io', 'wixpress.com', 'w3.org',
    'schema.org', 'googleapis.com', 'wordpress.org',
]


async def _extract_emails_from_page(session, url):
    """Extract email addresses from a single page."""
    emails = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                body = await resp.text()
                found = re.findall(EMAIL_REGEX, body)
                for email in found:
                    email_lower = email.lower()
                    if not any(ig in email_lower for ig in IGNORE_PATTERNS):
                        emails.add(email_lower)
    except Exception:
        pass
    return emails


async def _extract_from_metadata(session, url):
    """Extract emails from page metadata, headers, SSL cert."""
    emails = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            meta_patterns = [
                r'<meta[^>]+content=["\']([^"\']*@[^"\']*)["\']',
                r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                r'href=["\']mailto:([^"\'?]+)',
            ]
            for pattern in meta_patterns:
                matches = re.findall(pattern, body, re.I)
                for match in matches:
                    clean = re.findall(EMAIL_REGEX, match)
                    for email in clean:
                        if not any(ig in email.lower() for ig in IGNORE_PATTERNS):
                            emails.add(email.lower())
    except Exception:
        pass
    return emails


async def _search_public_sources(session, domain):
    """Search public sources for email addresses."""
    emails = set()
    try:
        url = f'https://api.hunter.io/v2/domain-search?domain={domain}&limit=10'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                for email_data in data.get('data', {}).get('emails', []):
                    emails.add(email_data.get('value', '').lower())
    except Exception:
        pass

    try:
        url = f'https://emailrep.io/{domain}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False, headers={'User-Agent': 'Snakebite'}) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get('email'):
                    emails.add(data['email'].lower())
    except Exception:
        pass

    return emails


def _categorize_emails(emails, domain):
    """Categorize emails by type."""
    categories = {
        'employee': [],
        'generic': [],
        'external': [],
    }
    generic_prefixes = ['info', 'contact', 'support', 'admin', 'sales',
                        'help', 'noreply', 'no-reply', 'webmaster', 'postmaster',
                        'abuse', 'security', 'privacy', 'press', 'hr', 'careers']

    for email in sorted(emails):
        local_part = email.split('@')[0]
        email_domain = email.split('@')[1]

        if domain in email_domain:
            if local_part in generic_prefixes:
                categories['generic'].append(email)
            else:
                categories['employee'].append(email)
        else:
            categories['external'].append(email)

    return categories


async def scan_email_harvester(session, url):
    """Harvest email addresses from target."""
    console.print(f"\n[bold cyan]--- Email Harvester ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    parts = domain.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    all_emails = set()

    console.print(f"  [cyan]Scanning {len(COMMON_PAGES)} pages for emails...[/cyan]")
    page_urls = [urljoin(url, page) for page in COMMON_PAGES]
    tasks = [_extract_emails_from_page(session, page_url) for page_url in page_urls]
    results = await asyncio.gather(*tasks)
    for email_set in results:
        all_emails.update(email_set)

    console.print(f"  [cyan]Extracting from metadata...[/cyan]")
    meta_emails = await _extract_from_metadata(session, url)
    all_emails.update(meta_emails)

    console.print(f"  [cyan]Searching public sources...[/cyan]")
    public_emails = await _search_public_sources(session, base_domain)
    all_emails.update(public_emails)

    categories = _categorize_emails(all_emails, base_domain)

    if categories['employee']:
        console.print(f"\n  [bold red]Employee Emails ({len(categories['employee'])}):[/bold red]")
        for email in categories['employee'][:15]:
            console.print(f"    [red]• {email}[/red]")

    if categories['generic']:
        console.print(f"\n  [yellow]Generic Emails ({len(categories['generic'])}):[/yellow]")
        for email in categories['generic'][:10]:
            console.print(f"    [dim]• {email}[/dim]")

    if categories['external']:
        console.print(f"\n  [dim]External ({len(categories['external'])}):[/dim]")
        for email in categories['external'][:5]:
            console.print(f"    [dim]• {email}[/dim]")

    console.print(f"\n  [bold]Total: {len(all_emails)} unique emails[/bold]")

    return {
        'domain': base_domain,
        'total': len(all_emails),
        'emails': sorted(all_emails),
        'categories': {k: v for k, v in categories.items()},
    }
