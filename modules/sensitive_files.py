"""Sensitive File Finder — deep scan for exposed sensitive files and backups."""

import aiohttp
import asyncio
from urllib.parse import urljoin
from modules.core import console

SENSITIVE_FILES = {
    'Configuration': [
        '/.env', '/.env.local', '/.env.production', '/.env.staging',
        '/.env.backup', '/.env.old', '/.env.dev',
        '/config.php', '/config.yml', '/config.json', '/config.xml',
        '/settings.py', '/settings.json', '/application.properties',
        '/application.yml', '/appsettings.json', '/web.config',
        '/database.yml', '/secrets.yml', '/credentials.json',
    ],
    'Version Control': [
        '/.git/config', '/.git/HEAD', '/.git/index',
        '/.gitignore', '/.gitattributes',
        '/.svn/entries', '/.svn/wc.db',
        '/.hg/dirstate', '/.bzr/branch/format',
    ],
    'Backup Files': [
        '/backup.sql', '/backup.tar.gz', '/backup.zip',
        '/db.sql', '/database.sql', '/dump.sql',
        '/site.zip', '/www.zip', '/public.zip',
        '/backup.sql.gz', '/data.sql', '/export.sql',
        '/full-backup.tar', '/site-backup.zip',
    ],
    'Log Files': [
        '/error.log', '/access.log', '/debug.log',
        '/app.log', '/application.log', '/server.log',
        '/logs/error.log', '/logs/access.log',
        '/var/log/apache2/error.log', '/log/production.log',
        '/wp-content/debug.log',
    ],
    'Package Managers': [
        '/package.json', '/package-lock.json', '/yarn.lock',
        '/composer.json', '/composer.lock',
        '/Gemfile', '/Gemfile.lock',
        '/requirements.txt', '/Pipfile', '/Pipfile.lock',
        '/go.mod', '/go.sum', '/Cargo.toml',
    ],
    'Docker/CI': [
        '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
        '/.dockerignore', '/.gitlab-ci.yml', '/.travis.yml',
        '/.github/workflows/main.yml', '/Jenkinsfile',
        '/Vagrantfile', '/Procfile',
    ],
    'IDE/Editor': [
        '/.idea/workspace.xml', '/.vscode/settings.json',
        '/.editorconfig', '/.project', '/.classpath',
        '/nbproject/project.properties',
    ],
    'Keys & Certs': [
        '/id_rsa', '/id_rsa.pub', '/id_dsa',
        '/server.key', '/server.crt', '/server.pem',
        '/private.key', '/certificate.pem',
        '/.ssh/authorized_keys', '/.ssh/id_rsa',
        '/ssl/private.key', '/certs/server.key',
    ],
    'Debug/Admin': [
        '/info.php', '/phpinfo.php', '/test.php',
        '/adminer.php', '/phpmyadmin/',
        '/server-status', '/server-info',
        '/_debug/', '/debug/', '/trace/',
        '/elmah.axd', '/actuator/', '/actuator/env',
        '/console/', '/__debug__/',
    ],
}

SENSITIVE_KEYWORDS = {
    'password', 'secret', 'token', 'api_key', 'access_key',
    'private_key', 'database', 'DB_PASSWORD', 'AWS_SECRET',
    'BEGIN RSA', 'BEGIN PRIVATE', 'mysql://', 'postgres://',
}


async def _check_file(session, url, path, category):
    """Check if a sensitive file is accessible."""
    test_url = urljoin(url, path)
    try:
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6),
                               ssl=False, allow_redirects=False) as resp:
            if resp.status == 200:
                body = await resp.text()
                if len(body) > 20:
                    has_secrets = any(kw.lower() in body.lower() for kw in SENSITIVE_KEYWORDS)
                    severity = 'Critical' if has_secrets else 'High' if category in ('Keys & Certs', 'Configuration', 'Backup Files') else 'Medium'
                    return {
                        'url': test_url,
                        'path': path,
                        'category': category,
                        'status': resp.status,
                        'size': len(body),
                        'has_secrets': has_secrets,
                        'severity': severity,
                    }
    except Exception:
        pass
    return None


async def scan_sensitive_files(session, url):
    """Deep scan for exposed sensitive files."""
    console.print(f"\n[bold cyan]--- Sensitive File Finder ---[/bold cyan]")

    total_files = sum(len(files) for files in SENSITIVE_FILES.values())
    console.print(f"  [cyan]Scanning {total_files} sensitive paths across {len(SENSITIVE_FILES)} categories...[/cyan]")

    results = {'findings': [], 'categories_found': {}}

    for category, paths in SENSITIVE_FILES.items():
        tasks = [_check_file(session, url, path, category) for path in paths]
        found = await asyncio.gather(*tasks)

        category_findings = [f for f in found if f]
        if category_findings:
            results['categories_found'][category] = len(category_findings)
            for f in category_findings:
                results['findings'].append(f)
                sev_color = 'red' if f['severity'] == 'Critical' else 'yellow'
                secret_tag = ' 🔑 SECRETS!' if f['has_secrets'] else ''
                console.print(f"  [{sev_color}]{category}: {f['path']} ({f['size']}B){secret_tag}[/{sev_color}]")

        await asyncio.sleep(0.1)

    if results['findings']:
        console.print(f"\n  [bold red]{len(results['findings'])} sensitive files exposed![/bold red]")
        critical = sum(1 for f in results['findings'] if f['severity'] == 'Critical')
        if critical:
            console.print(f"  [bold red]⚠ {critical} contain actual secrets/credentials![/bold red]")
    else:
        console.print(f"\n  [green]✓ No sensitive files exposed[/green]")

    return results
