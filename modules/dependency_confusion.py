"""Dependency Confusion Scanner — detect supply chain attack vectors."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin
from modules.core import console

PACKAGE_FILES = {
    'npm': ['/package.json', '/package-lock.json', '/yarn.lock'],
    'pip': ['/requirements.txt', '/Pipfile', '/setup.py', '/pyproject.toml'],
    'gem': ['/Gemfile', '/Gemfile.lock'],
    'composer': ['/composer.json', '/composer.lock'],
    'maven': ['/pom.xml'],
    'nuget': ['/packages.config', '/*.csproj'],
    'go': ['/go.mod', '/go.sum'],
    'cargo': ['/Cargo.toml', '/Cargo.lock'],
}


async def _check_npm_registry(session, package_name):
    """Check if private package name is unclaimed on npm."""
    try:
        url = f'https://registry.npmjs.org/{package_name}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 404:
                return {'package': package_name, 'registry': 'npm', 'available': True}
            elif resp.status == 200:
                data = await resp.json()
                return {'package': package_name, 'registry': 'npm', 'available': False,
                        'latest': data.get('dist-tags', {}).get('latest', '?')}
    except Exception:
        pass
    return None


async def _check_pypi(session, package_name):
    """Check if package exists on PyPI."""
    try:
        url = f'https://pypi.org/pypi/{package_name}/json'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 404:
                return {'package': package_name, 'registry': 'pypi', 'available': True}
            elif resp.status == 200:
                return {'package': package_name, 'registry': 'pypi', 'available': False}
    except Exception:
        pass
    return None


async def _extract_packages(session, url, path, pkg_type):
    """Extract package names from dependency files."""
    packages = set()
    test_url = urljoin(url, path)

    try:
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            if resp.status != 200:
                return packages
            body = await resp.text()

            if pkg_type == 'npm' and 'json' in path:
                try:
                    import json
                    data = json.loads(body)
                    for key in ['dependencies', 'devDependencies', 'peerDependencies']:
                        deps = data.get(key, {})
                        if isinstance(deps, dict):
                            packages.update(deps.keys())
                except Exception:
                    pass

            elif pkg_type == 'pip':
                for line in body.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('-'):
                        pkg = re.split(r'[>=<!~\[]', line)[0].strip()
                        if pkg and len(pkg) > 1:
                            packages.add(pkg)

            elif pkg_type == 'gem':
                matches = re.findall(r"gem\s+['\"]([^'\"]+)['\"]", body)
                packages.update(matches)

            elif pkg_type == 'composer' and 'json' in path:
                try:
                    import json
                    data = json.loads(body)
                    for key in ['require', 'require-dev']:
                        deps = data.get(key, {})
                        if isinstance(deps, dict):
                            packages.update(deps.keys())
                except Exception:
                    pass
    except Exception:
        pass

    return packages


async def scan_dependency_confusion(session, url):
    """Scan for dependency confusion attack vectors."""
    console.print(f"\n[bold cyan]--- Dependency Confusion Scanner ---[/bold cyan]")

    results = {'exposed_files': [], 'packages': {}, 'confusable': []}

    for pkg_type, paths in PACKAGE_FILES.items():
        for path in paths:
            if '*' in path:
                continue
            packages = await _extract_packages(session, url, path, pkg_type)
            if packages:
                results['exposed_files'].append({'type': pkg_type, 'path': path, 'count': len(packages)})
                console.print(f"  [green]{pkg_type}: {path} ({len(packages)} packages)[/green]")

                private_looking = [p for p in packages if
                                   '-' in p and not p.startswith('@') and
                                   any(kw in p.lower() for kw in ['internal', 'private', 'core', 'common', 'shared', 'utils', 'lib'])]

                for pkg in private_looking[:5]:
                    if pkg_type == 'npm':
                        check = await _check_npm_registry(session, pkg)
                    elif pkg_type == 'pip':
                        check = await _check_pypi(session, pkg)
                    else:
                        check = None

                    if check and check.get('available'):
                        results['confusable'].append(check)
                        console.print(f"  [bold red]⚠ CONFUSABLE: {pkg} not claimed on {check['registry']}![/bold red]")

                results['packages'][pkg_type] = list(packages)[:20]

    if results['confusable']:
        console.print(f"\n  [bold red]{len(results['confusable'])} dependency confusion vectors![/bold red]")
    elif results['exposed_files']:
        console.print(f"\n  [yellow]Dependency files exposed but no confusion found[/yellow]")
    else:
        console.print(f"\n  [green]✓ No dependency files exposed[/green]")

    return results
