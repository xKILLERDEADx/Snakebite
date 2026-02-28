"""GraphQL Introspection Deep — full schema dump, mutation abuse, nested DoS."""

import aiohttp
import asyncio
import json
from urllib.parse import urljoin
from modules.core import console

GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/gql',
                 '/query', '/api/query', '/graphql/v1', '/api/v2/graphql']

INTROSPECTION_QUERY = '''
{__schema{queryType{name}mutationType{name}subscriptionType{name}
types{name kind description fields(includeDeprecated:true){name
description args{name description type{name kind ofType{name kind}}}
type{name kind ofType{name kind ofType{name kind}}}isDeprecated
deprecationReason}inputFields{name description type{name kind
ofType{name kind}}}interfaces{name}enumValues(includeDeprecated:true)
{name description isDeprecated deprecationReason}possibleTypes{name}}
directives{name description locations args{name description type
{name kind ofType{name kind}}}}}}
'''

async def _find_graphql(session, url):
    """Discover GraphQL endpoints."""
    found = []
    for path in GRAPHQL_PATHS:
        test_url = urljoin(url, path)
        try:
            payload = {'query': '{__typename}'}
            async with session.post(test_url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=8),
                                    ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if '__typename' in body or 'data' in body or 'errors' in body:
                        found.append(test_url)
        except Exception:
            pass

        try:
            async with session.get(test_url, params={'query': '{__typename}'},
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if '__typename' in body or 'data' in body:
                        if test_url not in found:
                            found.append(test_url)
        except Exception:
            pass

    return found


async def _introspect(session, gql_url):
    """Run full introspection query."""
    try:
        payload = {'query': INTROSPECTION_QUERY}
        async with session.post(gql_url, json=payload,
                                timeout=aiohttp.ClientTimeout(total=15),
                                ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if 'data' in data and '__schema' in data.get('data', {}):
                    schema = data['data']['__schema']
                    types = schema.get('types', [])
                    queries, mutations, sensitive_fields = [], [], []

                    sensitive_names = ['password', 'secret', 'token', 'key', 'auth',
                                      'credential', 'ssn', 'credit', 'private', 'admin',
                                      'internal', 'debug', 'config', 'email', 'phone']

                    for t in types:
                        if t['name'].startswith('__'):
                            continue
                        for field in (t.get('fields') or []):
                            fname = field['name'].lower()
                            if t.get('name') == schema.get('queryType', {}).get('name'):
                                queries.append(field['name'])
                            if t.get('name') == schema.get('mutationType', {}).get('name'):
                                mutations.append(field['name'])
                            if any(s in fname for s in sensitive_names):
                                sensitive_fields.append({'type': t['name'], 'field': field['name']})

                    return {
                        'introspection_enabled': True,
                        'types_count': len([t for t in types if not t['name'].startswith('__')]),
                        'queries': queries, 'mutations': mutations,
                        'sensitive_fields': sensitive_fields,
                        'has_subscriptions': schema.get('subscriptionType') is not None,
                    }
    except Exception:
        pass
    return {'introspection_enabled': False}


async def _test_batch_query(session, gql_url):
    """Test for batch query / query aliasing DoS."""
    findings = []
    batch = [{'query': '{__typename}'} for _ in range(50)]
    try:
        async with session.post(gql_url, json=batch,
                                timeout=aiohttp.ClientTimeout(total=10),
                                ssl=False) as resp:
            if resp.status == 200:
                body = await resp.text()
                if body.count('__typename') >= 10:
                    findings.append({'type': 'Batch Query Allowed (DoS)', 'severity': 'High',
                                     'detail': '50 queries in single request accepted'})
    except Exception:
        pass

    alias_query = ' '.join([f'a{i}:__typename' for i in range(100)])
    try:
        payload = {'query': f'{{{alias_query}}}'}
        async with session.post(gql_url, json=payload,
                                timeout=aiohttp.ClientTimeout(total=10),
                                ssl=False) as resp:
            if resp.status == 200:
                findings.append({'type': 'Query Aliasing (100 aliases)', 'severity': 'Medium',
                                 'detail': 'No alias limit detected'})
    except Exception:
        pass

    return findings


async def _test_auth_bypass(session, gql_url, mutations):
    """Test mutation access without authentication."""
    findings = []
    dangerous = [m for m in mutations if any(k in m.lower()
                 for k in ['create', 'update', 'delete', 'admin', 'user', 'role'])]

    for mutation in dangerous[:5]:
        try:
            payload = {'query': f'mutation {{ {mutation} }}'}
            async with session.post(gql_url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=8),
                                    ssl=False) as resp:
                body = await resp.text()
                if resp.status == 200 and 'unauthorized' not in body.lower():
                    if 'errors' not in body or 'argument' in body.lower():
                        findings.append({'type': f'Unauth Mutation: {mutation}', 'severity': 'Critical'})
        except Exception:
            pass
    return findings


async def scan_graphql_deep(session, url):
    """Deep GraphQL introspection and vulnerability scanner."""
    console.print(f"\n[bold cyan]--- GraphQL Deep Scanner ---[/bold cyan]")
    endpoints = await _find_graphql(session, url)

    if not endpoints:
        console.print(f"  [dim]No GraphQL endpoints found[/dim]")
        return {'endpoints': [], 'findings': []}

    console.print(f"  [green]Found {len(endpoints)} endpoint(s)[/green]")
    all_findings = []

    for gql_url in endpoints:
        console.print(f"\n  [green]Endpoint: {gql_url}[/green]")
        schema = await _introspect(session, gql_url)

        if schema.get('introspection_enabled'):
            console.print(f"  [bold red]⚠ Introspection ENABLED![/bold red]")
            all_findings.append({'type': 'GraphQL Introspection Enabled', 'severity': 'High',
                                 'detail': f"{schema['types_count']} types, {len(schema['queries'])} queries"})

            for sf in schema.get('sensitive_fields', []):
                all_findings.append({'type': f'Sensitive: {sf["type"]}.{sf["field"]}', 'severity': 'High'})
                console.print(f"  [red]Sensitive: {sf['type']}.{sf['field']}[/red]")

            batch = await _test_batch_query(session, gql_url)
            all_findings.extend(batch)
            auth = await _test_auth_bypass(session, gql_url, schema.get('mutations', []))
            all_findings.extend(auth)

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} GraphQL vulns![/bold red]")
    else:
        console.print(f"\n  [green]✓ No GraphQL issues[/green]")

    return {'endpoints': endpoints, 'schema': schema, 'findings': all_findings}
