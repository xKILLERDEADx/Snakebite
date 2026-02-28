"""API Key Validator — validate found API keys against real services."""

import aiohttp
import asyncio
from modules.core import console


VALIDATORS = {
    'AWS': {
        'pattern_hints': ['AKIA', 'aws_access_key', 'aws_secret'],
        'validate': '_validate_aws',
    },
    'Google Maps': {
        'pattern_hints': ['AIza'],
        'validate': '_validate_google_maps',
    },
    'Stripe': {
        'pattern_hints': ['sk_live_', 'sk_test_', 'pk_live_', 'pk_test_', 'rk_live_', 'rk_test_'],
        'validate': '_validate_stripe',
    },
    'GitHub': {
        'pattern_hints': ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'],
        'validate': '_validate_github',
    },
    'Slack': {
        'pattern_hints': ['xoxb-', 'xoxp-', 'xoxa-', 'xoxr-'],
        'validate': '_validate_slack',
    },
    'Twilio': {
        'pattern_hints': ['SK', 'AC'],
        'validate': '_validate_twilio',
    },
    'Mailgun': {
        'pattern_hints': ['key-'],
        'validate': '_validate_mailgun',
    },
    'SendGrid': {
        'pattern_hints': ['SG.'],
        'validate': '_validate_sendgrid',
    },
    'Telegram Bot': {
        'pattern_hints': [':AA'],
        'validate': '_validate_telegram',
    },
    'Firebase': {
        'pattern_hints': ['AIza'],
        'validate': '_validate_firebase',
    },
}


async def _validate_github(session, key):
    """Validate GitHub token via API."""
    try:
        headers = {'Authorization': f'token {key}', 'User-Agent': 'Snakebite/2.0'}
        async with session.get('https://api.github.com/user', headers=headers,
                               timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {'valid': True, 'user': data.get('login', ''), 'scopes': resp.headers.get('X-OAuth-Scopes', '')}
            return {'valid': False, 'reason': f'Status {resp.status}'}
    except Exception as e:
        return {'valid': False, 'reason': str(e)[:50]}


async def _validate_slack(session, key):
    """Validate Slack token via API."""
    try:
        async with session.post('https://slack.com/api/auth.test',
                                data={'token': key},
                                timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            data = await resp.json()
            if data.get('ok'):
                return {'valid': True, 'team': data.get('team', ''), 'user': data.get('user', '')}
            return {'valid': False, 'reason': data.get('error', 'unknown')}
    except Exception as e:
        return {'valid': False, 'reason': str(e)[:50]}


async def _validate_google_maps(session, key):
    """Validate Google Maps API key."""
    try:
        url = f'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            data = await resp.json()
            if data.get('status') != 'REQUEST_DENIED':
                return {'valid': True, 'status': data.get('status', '')}
            return {'valid': False, 'reason': 'Denied'}
    except Exception as e:
        return {'valid': False, 'reason': str(e)[:50]}


async def _validate_stripe(session, key):
    """Validate Stripe API key."""
    try:
        headers = {'Authorization': f'Bearer {key}'}
        async with session.get('https://api.stripe.com/v1/charges?limit=1',
                               headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                return {'valid': True, 'type': 'live' if 'live' in key else 'test'}
            return {'valid': False, 'reason': f'Status {resp.status}'}
    except Exception as e:
        return {'valid': False, 'reason': str(e)[:50]}


async def _validate_telegram(session, key):
    """Validate Telegram Bot token."""
    try:
        url = f'https://api.telegram.org/bot{key}/getMe'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            data = await resp.json()
            if data.get('ok'):
                return {'valid': True, 'bot': data['result'].get('username', '')}
            return {'valid': False, 'reason': data.get('description', '')}
    except Exception as e:
        return {'valid': False, 'reason': str(e)[:50]}


async def _validate_sendgrid(session, key):
    """Validate SendGrid API key."""
    try:
        headers = {'Authorization': f'Bearer {key}'}
        async with session.get('https://api.sendgrid.com/v3/scopes',
                               headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                return {'valid': True}
            return {'valid': False, 'reason': f'Status {resp.status}'}
    except Exception as e:
        return {'valid': False, 'reason': str(e)[:50]}


async def _validate_firebase(session, key):
    """Validate Firebase API key."""
    try:
        url = f'https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={key}'
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                return {'valid': True}
            return {'valid': False, 'reason': f'Status {resp.status}'}
    except Exception as e:
        return {'valid': False, 'reason': str(e)[:50]}


def identify_key_type(key):
    """Identify the service a key belongs to based on prefix/pattern."""
    for service, info in VALIDATORS.items():
        for hint in info['pattern_hints']:
            if key.startswith(hint) or hint in key[:10]:
                return service
    return None


async def validate_api_keys(session, found_keys):
    """Validate a list of found API keys against real services."""
    console.print(f"\n[bold cyan]--- API Key Validator ---[/bold cyan]")

    if not found_keys:
        console.print(f"  [dim]No API keys to validate[/dim]")
        return []

    console.print(f"  [cyan]Validating {len(found_keys)} API keys...[/cyan]\n")

    validations = {
        '_validate_github': _validate_github,
        '_validate_slack': _validate_slack,
        '_validate_google_maps': _validate_google_maps,
        '_validate_stripe': _validate_stripe,
        '_validate_telegram': _validate_telegram,
        '_validate_sendgrid': _validate_sendgrid,
        '_validate_firebase': _validate_firebase,
    }

    results = []
    for key_info in found_keys[:20]:
        key = key_info if isinstance(key_info, str) else key_info.get('key', key_info.get('value', ''))
        if not key or len(key) < 10:
            continue

        service = identify_key_type(key)
        if not service:
            results.append({
                'key': key[:20] + '...',
                'service': 'Unknown',
                'valid': None,
                'details': 'Unrecognized key pattern',
            })
            continue

        validator_name = VALIDATORS[service]['validate']
        validator_fn = validations.get(validator_name)

        if validator_fn:
            console.print(f"  [dim]Checking {service}: {key[:15]}...[/dim]")
            result = await validator_fn(session, key)
            status_color = 'red' if result.get('valid') else 'green'
            status_text = 'VALID (LEAKED!)' if result.get('valid') else 'Invalid/Revoked'

            console.print(f"    [{status_color}]{service}: {status_text}[/{status_color}]")
            if result.get('valid'):
                for k, v in result.items():
                    if k != 'valid':
                        console.print(f"      [red]{k}: {v}[/red]")

            results.append({
                'key': key[:20] + '...',
                'service': service,
                'valid': result.get('valid'),
                'details': result,
            })

            await asyncio.sleep(0.5)
        else:
            results.append({
                'key': key[:20] + '...',
                'service': service,
                'valid': None,
                'details': 'No validator available',
            })

    valid_count = sum(1 for r in results if r.get('valid'))
    if valid_count > 0:
        console.print(f"\n  [bold red]⚠ {valid_count} VALID leaked API keys found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No valid leaked keys detected[/green]")

    return results
