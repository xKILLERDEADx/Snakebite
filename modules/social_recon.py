"""Social Recon — OSINT on company, employees, and tech stack from public data."""

import aiohttp
import asyncio
import re
from urllib.parse import urlparse, quote
from modules.core import console

async def _search_github_org(session, domain):
    """Search GitHub for organization repos and tech stack."""
    results = {'repos': [], 'languages': {}, 'org_name': ''}
    org_name = domain.split('.')[0]

    try:
        url = f'https://api.github.com/search/repositories?q=org:{org_name}&sort=stars&per_page=10'
        headers = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'Snakebite'}
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                results['org_name'] = org_name
                for repo in data.get('items', []):
                    results['repos'].append({
                        'name': repo.get('full_name', ''),
                        'description': repo.get('description', '')[:100],
                        'stars': repo.get('stargazers_count', 0),
                        'language': repo.get('language', ''),
                        'url': repo.get('html_url', ''),
                    })
                    lang = repo.get('language', '')
                    if lang:
                        results['languages'][lang] = results['languages'].get(lang, 0) + 1
    except Exception:
        pass

    if not results['repos']:
        try:
            url = f'https://api.github.com/search/repositories?q={domain}&sort=stars&per_page=5'
            headers = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'Snakebite'}
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for repo in data.get('items', []):
                        results['repos'].append({
                            'name': repo.get('full_name', ''),
                            'description': repo.get('description', '')[:100],
                            'stars': repo.get('stargazers_count', 0),
                            'language': repo.get('language', ''),
                            'url': repo.get('html_url', ''),
                        })
        except Exception:
            pass

    return results


async def _search_social_profiles(session, domain):
    """Search for company social media profiles."""
    org_name = domain.split('.')[0]
    profiles = {}

    social_platforms = {
        'Twitter': f'https://twitter.com/{org_name}',
        'LinkedIn': f'https://www.linkedin.com/company/{org_name}',
        'Facebook': f'https://www.facebook.com/{org_name}',
        'Instagram': f'https://www.instagram.com/{org_name}',
        'YouTube': f'https://www.youtube.com/@{org_name}',
    }

    for platform, url in social_platforms.items():
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False, allow_redirects=True) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if org_name.lower() in body.lower() and 'not found' not in body.lower() and '404' not in body[:200]:
                        profiles[platform] = url
        except Exception:
            pass

    return profiles


async def _extract_org_info(session, url):
    """Extract organization info from target website."""
    info = {'company_name': '', 'phone': [], 'address': '', 'founded': ''}

    try:
        pages = [url, url.rstrip('/') + '/about', url.rstrip('/') + '/about-us']
        for page_url in pages:
            try:
                async with session.get(page_url, timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()

                        phones = re.findall(r'[\+]?[1-9][\d\s\-\(\)]{7,15}', body)
                        for phone in phones[:3]:
                            clean = phone.strip()
                            if len(clean) >= 10:
                                info['phone'].append(clean)

                        og_title = re.search(r'property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)', body, re.I)
                        if og_title:
                            info['company_name'] = og_title.group(1)

                        title = re.search(r'<title>([^<]+)</title>', body, re.I)
                        if title and not info['company_name']:
                            info['company_name'] = title.group(1).split('|')[0].split('-')[0].strip()

                        founded = re.search(r'(?:founded|established|since)\s+(?:in\s+)?(\d{4})', body, re.I)
                        if founded:
                            info['founded'] = founded.group(1)
            except Exception:
                pass

    except Exception:
        pass

    info['phone'] = list(set(info['phone']))[:5]
    return info


async def scan_social_recon(session, url):
    """Perform social/OSINT reconnaissance."""
    console.print(f"\n[bold cyan]--- Social Recon / OSINT ---[/bold cyan]")

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    parts = domain.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    results = {
        'domain': base_domain,
        'org_info': {},
        'github': {},
        'social_profiles': {},
    }

    console.print(f"  [cyan]Extracting organization info...[/cyan]")
    org_info = await _extract_org_info(session, url)
    results['org_info'] = org_info
    if org_info['company_name']:
        console.print(f"  [green]Company: {org_info['company_name']}[/green]")
    if org_info['founded']:
        console.print(f"  [dim]Founded: {org_info['founded']}[/dim]")
    if org_info['phone']:
        for phone in org_info['phone']:
            console.print(f"  [dim]Phone: {phone}[/dim]")

    console.print(f"\n  [cyan]Searching GitHub...[/cyan]")
    github = await _search_github_org(session, base_domain)
    results['github'] = github

    if github['repos']:
        console.print(f"  [green]GitHub repos: {len(github['repos'])}[/green]")
        for repo in github['repos'][:5]:
            console.print(f"    [dim]⭐{repo['stars']} {repo['name']} [{repo['language']}][/dim]")
        if github['languages']:
            console.print(f"  [cyan]Tech stack: {', '.join(github['languages'].keys())}[/cyan]")

    console.print(f"\n  [cyan]Checking social profiles...[/cyan]")
    profiles = await _search_social_profiles(session, base_domain)
    results['social_profiles'] = profiles

    if profiles:
        for platform, profile_url in profiles.items():
            console.print(f"  [green]{platform}: {profile_url}[/green]")
    else:
        console.print(f"  [dim]No social profiles found[/dim]")

    return results
