"""CI/CD Pipeline Detector — find exposed CI/CD configs and dashboards."""

import aiohttp
import asyncio
from urllib.parse import urljoin
from modules.core import console

CICD_PATHS = {
    'Jenkins': [
        '/jenkins/', '/jenkins/api/json', '/jenkins/login',
        '/job/', '/api/json', '/manage',
    ],
    'GitLab CI': [
        '/.gitlab-ci.yml', '/ci/lint', '/-/pipelines',
        '/-/jobs', '/-/settings/ci_cd',
    ],
    'GitHub Actions': [
        '/.github/workflows/', '/.github/workflows/ci.yml',
        '/.github/workflows/main.yml', '/.github/workflows/build.yml',
        '/.github/workflows/deploy.yml', '/.github/workflows/test.yml',
    ],
    'Travis CI': [
        '/.travis.yml',
    ],
    'CircleCI': [
        '/.circleci/config.yml',
    ],
    'Azure DevOps': [
        '/azure-pipelines.yml', '/_apis/build/builds',
    ],
    'Drone CI': [
        '/.drone.yml', '/api/repos',
    ],
    'Kubernetes': [
        '/k8s/', '/.kube/config', '/kubernetes-dashboard/',
    ],
    'Docker': [
        '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
        '/.dockerignore', '/v2/_catalog',
    ],
    'Terraform': [
        '/.terraform/', '/main.tf', '/terraform.tfstate',
        '/terraform.tfvars',
    ],
    'Ansible': [
        '/playbook.yml', '/ansible.cfg', '/inventory',
    ],
    'ArgoCD': [
        '/argocd/', '/api/v1/applications',
    ],
}

SENSITIVE_KEYWORDS = [
    'password', 'secret', 'token', 'api_key', 'access_key',
    'private_key', 'credentials', 'auth', 'deploy_key',
    'ssh_key', 'aws_access', 'database_url', 'connection_string',
]


async def _check_cicd_path(session, url, path, service):
    """Check if a CI/CD path is accessible."""
    test_url = urljoin(url, path)
    try:
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=True) as resp:
            if resp.status == 200:
                body = await resp.text()
                if len(body) > 50:
                    has_secrets = any(kw in body.lower() for kw in SENSITIVE_KEYWORDS)
                    return {
                        'service': service,
                        'path': path,
                        'url': test_url,
                        'status': resp.status,
                        'size': len(body),
                        'has_secrets': has_secrets,
                        'severity': 'Critical' if has_secrets else 'High' if '.yml' in path or '.yaml' in path else 'Medium',
                    }
    except Exception:
        pass
    return None


async def scan_cicd_pipelines(session, url):
    """Detect exposed CI/CD configurations and dashboards."""
    console.print(f"\n[bold cyan]--- CI/CD Pipeline Detector ---[/bold cyan]")

    total_paths = sum(len(paths) for paths in CICD_PATHS.values())
    console.print(f"  [cyan]Checking {total_paths} CI/CD paths across {len(CICD_PATHS)} services...[/cyan]")

    results = {'findings': [], 'services_detected': []}

    for service, paths in CICD_PATHS.items():
        tasks = [_check_cicd_path(session, url, path, service) for path in paths]
        found = await asyncio.gather(*tasks)

        for result in found:
            if result:
                results['findings'].append(result)
                if service not in results['services_detected']:
                    results['services_detected'].append(service)

                sev_color = 'red' if result['severity'] in ('Critical', 'High') else 'yellow'
                console.print(f"  [{sev_color}]{service}: {result['path']}[/{sev_color}]")
                if result['has_secrets']:
                    console.print(f"    [bold red]⚠ SECRETS DETECTED IN CONFIG![/bold red]")

        await asyncio.sleep(0.1)

    if results['findings']:
        console.print(f"\n  [bold red]{len(results['findings'])} CI/CD configs exposed![/bold red]")
        console.print(f"  [dim]Services: {', '.join(results['services_detected'])}[/dim]")
    else:
        console.print(f"\n  [green]✓ No exposed CI/CD configurations found[/green]")

    return results
