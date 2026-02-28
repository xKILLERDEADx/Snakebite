"""Nuclei Template Engine — YAML-based custom vulnerability scanner."""

import os
import json
import re
import aiohttp
import asyncio
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
from modules.core import console


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates')

BUILTIN_TEMPLATES = [
    {
        'id': 'git-config-exposed',
        'info': {'name': 'Git Config Exposed', 'severity': 'Medium'},
        'requests': [{'path': '/.git/config', 'method': 'GET',
                      'matchers': [{'type': 'word', 'words': ['[core]', '[remote']}]}],
    },
    {
        'id': 'env-file-exposed',
        'info': {'name': '.env File Exposed', 'severity': 'High'},
        'requests': [{'path': '/.env', 'method': 'GET',
                      'matchers': [{'type': 'word', 'words': ['DB_PASSWORD', 'APP_KEY', 'SECRET_KEY', 'AWS_ACCESS']}]}],
    },
    {
        'id': 'debug-mode-enabled',
        'info': {'name': 'Debug Mode Enabled', 'severity': 'Medium'},
        'requests': [{'path': '/', 'method': 'GET',
                      'matchers': [{'type': 'word', 'words': ['Traceback (most recent', 'DJANGO_SETTINGS_MODULE',
                                                              'Laravel', 'stack trace', 'Debug = True']}]}],
    },
    {
        'id': 'phpinfo-exposed',
        'info': {'name': 'phpinfo() Exposed', 'severity': 'Low'},
        'requests': [{'path': '/phpinfo.php', 'method': 'GET',
                      'matchers': [{'type': 'word', 'words': ['phpinfo()', 'PHP Version', 'PHP Extension']}]}],
    },
    {
        'id': 'server-status-exposed',
        'info': {'name': 'Apache Server Status', 'severity': 'Low'},
        'requests': [{'path': '/server-status', 'method': 'GET',
                      'matchers': [{'type': 'word', 'words': ['Apache Server Status', 'Server uptime']}]}],
    },
    {
        'id': 'ds-store-exposed',
        'info': {'name': '.DS_Store File', 'severity': 'Low'},
        'requests': [{'path': '/.DS_Store', 'method': 'GET',
                      'matchers': [{'type': 'status', 'status': [200]},
                                   {'type': 'binary', 'binary': [b'\x00\x00\x00\x01Bud1']}]}],
    },
    {
        'id': 'backup-files',
        'info': {'name': 'Backup File Found', 'severity': 'High'},
        'requests': [
            {'path': '/backup.sql', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['CREATE TABLE', 'INSERT INTO']}]},
            {'path': '/db.sql', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['CREATE TABLE', 'INSERT INTO']}]},
            {'path': '/dump.sql', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['CREATE TABLE', 'INSERT INTO']}]},
            {'path': '/backup.zip', 'method': 'GET', 'matchers': [{'type': 'status', 'status': [200]}]},
        ],
    },
    {
        'id': 'wp-config-backup',
        'info': {'name': 'WordPress Config Backup', 'severity': 'Critical'},
        'requests': [
            {'path': '/wp-config.php.bak', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['DB_PASSWORD', 'DB_NAME']}]},
            {'path': '/wp-config.php~', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['DB_PASSWORD']}]},
            {'path': '/wp-config.old', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['DB_PASSWORD']}]},
        ],
    },
    {
        'id': 'exposed-panels',
        'info': {'name': 'Admin Panel Exposed', 'severity': 'Medium'},
        'requests': [
            {'path': '/admin/', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['login', 'password', 'admin']}]},
            {'path': '/administrator/', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['login', 'password']}]},
            {'path': '/wp-admin/', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['WordPress', 'wp-login']}]},
        ],
    },
    {
        'id': 'api-docs-exposed',
        'info': {'name': 'API Documentation Exposed', 'severity': 'Low'},
        'requests': [
            {'path': '/swagger-ui.html', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['swagger', 'api']}]},
            {'path': '/api-docs', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['openapi', 'swagger', 'paths']}]},
            {'path': '/redoc', 'method': 'GET', 'matchers': [{'type': 'word', 'words': ['ReDoc', 'API']}]},
        ],
    },
]


def load_custom_templates():
    """Load YAML templates from templates/ directory."""
    templates = []
    if not os.path.exists(TEMPLATES_DIR):
        os.makedirs(TEMPLATES_DIR, exist_ok=True)
        example = os.path.join(TEMPLATES_DIR, '_example_template.json')
        if not os.path.exists(example):
            with open(example, 'w') as f:
                json.dump({
                    'id': 'custom-check',
                    'info': {'name': 'Custom Check', 'severity': 'Medium', 'author': 'you'},
                    'requests': [{'path': '/custom-path', 'method': 'GET',
                                  'matchers': [{'type': 'word', 'words': ['sensitive_keyword']}]}],
                }, f, indent=2)
        return templates

    for fname in sorted(os.listdir(TEMPLATES_DIR)):
        if fname.startswith('_'):
            continue
        filepath = os.path.join(TEMPLATES_DIR, fname)
        try:
            if fname.endswith('.json'):
                with open(filepath, 'r') as f:
                    tpl = json.load(f)
            elif fname.endswith(('.yaml', '.yml')) and HAS_YAML:
                with open(filepath, 'r') as f:
                    tpl = yaml.safe_load(f)
            else:
                continue
            if tpl and 'id' in tpl and 'requests' in tpl:
                templates.append(tpl)
        except Exception:
            pass
    return templates


async def _match_response(body, status, matchers):
    """Check if response matches template matchers."""
    for matcher in matchers:
        mtype = matcher.get('type', '')
        if mtype == 'word':
            words = matcher.get('words', [])
            if any(w.lower() in body.lower() for w in words):
                return True
        elif mtype == 'status':
            statuses = matcher.get('status', [])
            if status in statuses:
                return True
        elif mtype == 'regex':
            patterns = matcher.get('regex', [])
            if any(re.search(p, body, re.I) for p in patterns):
                return True
    return False


async def _run_template(session, url, template):
    """Execute a single template against target."""
    findings = []
    info = template.get('info', {})

    for req in template.get('requests', []):
        path = req.get('path', '/')
        method = req.get('method', 'GET').upper()
        test_url = url.rstrip('/') + path

        try:
            if method == 'GET':
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                                       ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    if await _match_response(body, resp.status, req.get('matchers', [])):
                        findings.append({
                            'template': template['id'],
                            'name': info.get('name', template['id']),
                            'severity': info.get('severity', 'Info'),
                            'url': test_url,
                            'status': resp.status,
                            'type': info.get('name', ''),
                        })
            elif method == 'POST':
                data = req.get('body', {})
                async with session.post(test_url, data=data,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as resp:
                    body = await resp.text()
                    if await _match_response(body, resp.status, req.get('matchers', [])):
                        findings.append({
                            'template': template['id'],
                            'name': info.get('name', template['id']),
                            'severity': info.get('severity', 'Info'),
                            'url': test_url,
                            'status': resp.status,
                            'type': info.get('name', ''),
                        })
        except Exception:
            pass

    return findings


async def scan_nuclei_templates(session, url):
    """Run all nuclei-style templates against target."""
    console.print(f"\n[bold cyan]--- Nuclei Template Engine ---[/bold cyan]")

    custom_templates = load_custom_templates()
    all_templates = BUILTIN_TEMPLATES + custom_templates

    console.print(f"  [cyan]Running {len(BUILTIN_TEMPLATES)} built-in + {len(custom_templates)} custom templates[/cyan]")

    all_findings = []
    for tpl in all_templates:
        findings = await _run_template(session, url, tpl)
        all_findings.extend(findings)
        for f in findings:
            sev = f['severity']
            sev_color = {'Critical': 'red', 'High': 'red', 'Medium': 'yellow', 'Low': 'blue'}.get(sev, 'dim')
            console.print(f"  [{sev_color}][{sev}] {f['name']} — {f['url']}[/{sev_color}]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} template matches found![/bold red]")
    else:
        console.print(f"\n  [green]No template matches[/green]")

    console.print(f"  [dim]Drop .yaml templates in templates/ to add custom checks[/dim]")
    return all_findings
