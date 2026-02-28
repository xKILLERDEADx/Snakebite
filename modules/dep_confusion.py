"""Dependency Confusion Scanner — npm/pip/maven namespace hijacking detection."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin
from modules.core import console

PACKAGE_PATTERNS = {
    'npm': [
        (r'from\s+["\'](@?[\w/-]+)["\']', 'JS import'),
        (r'require\s*\(\s*["\'](@?[\w/-]+)["\']', 'require()'),
        (r'"dependencies"\s*:\s*\{([^}]+)\}', 'package.json deps'),
        (r'"devDependencies"\s*:\s*\{([^}]+)\}', 'package.json devDeps'),
    ],
    'pip': [
        (r'(?:import|from)\s+([\w_]+)', 'Python import'),
        (r'([\w_-]+)==[\d.]+', 'requirements.txt'),
    ],
}

NPM_REGISTRY = 'https://registry.npmjs.org'
PYPI_REGISTRY = 'https://pypi.org/pypi'

async def _extract_packages(session, url):
    """Extract package names from page sources."""
    packages = {'npm': set(), 'pip': set()}
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            body = await resp.text()
            scripts = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
            all_js = [body]
            for src in scripts[:10]:
                js_url = urljoin(url, src)
                try:
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False) as jr:
                        if jr.status == 200:
                            all_js.append(await jr.text())
                except Exception:
                    pass

            for js in all_js:
                for pattern, _ in PACKAGE_PATTERNS['npm']:
                    for match in re.finditer(pattern, js):
                        pkg = match.group(1).strip()
                        if pkg and len(pkg) > 1 and not pkg.startswith('.') and not pkg.startswith('/'):
                            packages['npm'].add(pkg)
    except Exception:
        pass

    exposed_paths = ['/package.json', '/package-lock.json', '/requirements.txt',
                     '/Pipfile', '/yarn.lock', '/composer.json', '/pom.xml']
    for path in exposed_paths:
        try:
            async with session.get(urljoin(url, path), timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if 'dependencies' in body or 'require' in body:
                        dep_names = re.findall(r'"(@?[\w/-]+)"\s*:', body)
                        for name in dep_names:
                            if name not in ('name', 'version', 'description', 'main', 'scripts', 'license'):
                                packages['npm'].add(name)
                    if '==' in body:
                        pip_pkgs = re.findall(r'^([\w_-]+)==', body, re.M)
                        for p in pip_pkgs:
                            packages['pip'].add(p)
        except Exception:
            pass

    return packages


async def _check_npm_exists(session, package_name):
    """Check if npm package exists on public registry."""
    try:
        async with session.get(f'{NPM_REGISTRY}/{package_name}',
                               timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return {'exists': True, 'name': package_name,
                        'latest': data.get('dist-tags', {}).get('latest', '?'),
                        'downloads': True}
            elif resp.status == 404:
                return {'exists': False, 'name': package_name}
    except Exception:
        pass
    return {'exists': None, 'name': package_name}


async def _check_pypi_exists(session, package_name):
    """Check if PyPI package exists."""
    try:
        async with session.get(f'{PYPI_REGISTRY}/{package_name}/json',
                               timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                return {'exists': True, 'name': package_name}
            elif resp.status == 404:
                return {'exists': False, 'name': package_name}
    except Exception:
        pass
    return {'exists': None, 'name': package_name}


async def _check_confusion(session, packages):
    """Check for dependency confusion attack vectors."""
    findings = []

    internal_patterns = [r'^@[\w-]+/', r'^internal-', r'^corp-', r'^priv-',
                         r'^company-', r'-(internal|private|corp)$']

    for pkg in list(packages['npm'])[:30]:
        is_scoped = pkg.startswith('@')
        is_internal = any(re.match(p, pkg) for p in internal_patterns)

        result = await _check_npm_exists(session, pkg)
        if result['exists'] is False:
            severity = 'Critical' if is_internal or is_scoped else 'High'
            findings.append({
                'type': f'NPM Not Found: {pkg}',
                'severity': severity,
                'detail': 'Package name available for hijacking on npmjs.com',
            })
        elif result['exists'] and is_internal:
            findings.append({
                'type': f'NPM Possible Confusion: {pkg}',
                'severity': 'Medium',
                'detail': 'Internal-looking package exists on public registry',
            })

    for pkg in list(packages['pip'])[:15]:
        result = await _check_pypi_exists(session, pkg)
        if result['exists'] is False:
            findings.append({
                'type': f'PyPI Not Found: {pkg}',
                'severity': 'High',
                'detail': 'Package name available for hijacking on pypi.org',
            })

    return findings


async def scan_dep_confusion(session, url):
    console.print(f"\n[bold cyan]--- Dependency Confusion Scanner ---[/bold cyan]")
    console.print(f"  [cyan]Extracting package references...[/cyan]")
    packages = await _extract_packages(session, url)
    console.print(f"  [dim]NPM: {len(packages['npm'])} | PyPI: {len(packages['pip'])}[/dim]")

    if not packages['npm'] and not packages['pip']:
        console.print(f"  [dim]No package refs found[/dim]")
        return {'packages': {}, 'findings': []}

    console.print(f"  [cyan]Checking public registry availability...[/cyan]")
    findings = await _check_confusion(session, packages)

    for f in findings:
        color = 'red' if f['severity'] in ('Critical', 'High') else 'yellow'
        console.print(f"  [{color}]⚠ {f['type']}[/{color}]")
    if not findings:
        console.print(f"\n  [green]✓ No dependency confusion risks[/green]")
    return {'packages': {k: list(v) for k, v in packages.items()}, 'findings': findings}
