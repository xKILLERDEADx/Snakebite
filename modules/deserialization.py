"""Insecure Deserialization Scanner — detect Java/PHP/Python/.NET deserialization."""

import aiohttp
import asyncio
import base64
from modules.core import console

JAVA_PAYLOADS = [
    base64.b64encode(b'\xac\xed\x00\x05').decode(),
    'rO0ABXNyAA1qYXZhLnV0aWwuSGFzaE1hcA==',
    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==',
]

PHP_PAYLOADS = [
    'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
    'a:1:{s:4:"test";s:4:"test";}',
    'O:3:"Foo":1:{s:3:"bar";s:6:"system";}',
    'C:11:"ArrayObject":37:{x:i:0;a:1:{s:4:"test";s:4:"test";};}',
]

PYTHON_PAYLOADS = [
    base64.b64encode(b'\x80\x04\x95').decode(),
    'gASVMAAAAAAAAACMCGJ1aWx0aW5zlIwFcHJpbnSUk5SMBXRlc3SUhZRSlC4=',
]

DOTNET_PAYLOADS = [
    'AAEAAAD/////AQAAAAAAAAAEAQAAAA==',
]

INJECTION_POINTS = [
    'session', 'data', 'token', 'state', 'viewstate',
    '__VIEWSTATE', 'payload', 'object', 'serialized',
]


async def _test_deser_headers(session, url):
    """Test for deserialization indicators in response."""
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False) as resp:
            body = await resp.text()
            headers = {k.lower(): v for k, v in resp.headers.items()}

            cookies = headers.get('set-cookie', '')
            if any(indicator in cookies for indicator in ['rO0AB', 'AAEAAA', 'O:8:', 'gASV']):
                findings.append({
                    'type': 'Serialized Data in Cookie',
                    'severity': 'High',
                    'detail': 'Serialized object detected in Set-Cookie header',
                })

            if '__VIEWSTATE' in body or 'ViewState' in body:
                findings.append({
                    'type': '.NET ViewState Detected',
                    'severity': 'Medium',
                    'detail': 'ASP.NET ViewState — potential deserialization target',
                })

            if 'application/x-java-serialized-object' in str(headers):
                findings.append({
                    'type': 'Java Serialized Content-Type',
                    'severity': 'Critical',
                })

    except Exception:
        pass
    return findings


async def _test_deser_injection(session, url, payloads, runtime):
    """Inject serialized payloads and check for deserialization behavior."""
    findings = []

    for param in INJECTION_POINTS:
        for payload in payloads[:2]:
            try:
                async with session.post(url, data={param: payload},
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as resp:
                    body = await resp.text()
                    status = resp.status

                    indicators = [
                        'ClassNotFoundException', 'UnserializeException',
                        'pickle', 'unpickle', 'ObjectInputStream',
                        'Serializable', 'deserializ', 'unserializ',
                        'ClassCastException', 'InvalidClassException',
                        'StreamCorruptedException', 'NotSerializableException',
                    ]
                    for indicator in indicators:
                        if indicator.lower() in body.lower():
                            findings.append({
                                'type': f'Insecure Deserialization ({runtime})',
                                'param': param,
                                'indicator': indicator,
                                'severity': 'Critical',
                            })
                            break

                    if status == 500 and runtime.lower() in body.lower():
                        findings.append({
                            'type': f'Deserialization Error ({runtime})',
                            'param': param,
                            'severity': 'High',
                        })
            except Exception:
                pass

        try:
            headers = {'Cookie': f'{param}={payloads[0]}'}
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                body = await resp.text()
                if resp.status == 500:
                    findings.append({
                        'type': f'Cookie Deserialization Error ({runtime})',
                        'param': param,
                        'severity': 'High',
                    })
        except Exception:
            pass

    return findings


async def scan_deserialization(session, url):
    """Scan for insecure deserialization vulnerabilities."""
    console.print(f"\n[bold cyan]--- Insecure Deserialization Scanner ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Checking for serialization indicators...[/cyan]")
    indicator_findings = await _test_deser_headers(session, url)
    all_findings.extend(indicator_findings)
    for f in indicator_findings:
        console.print(f"  [yellow]{f['type']}[/yellow]")

    runtimes = [
        ('Java', JAVA_PAYLOADS),
        ('PHP', PHP_PAYLOADS),
        ('Python', PYTHON_PAYLOADS),
        ('.NET', DOTNET_PAYLOADS),
    ]

    for runtime, payloads in runtimes:
        console.print(f"  [cyan]Testing {runtime} deserialization...[/cyan]")
        findings = await _test_deser_injection(session, url, payloads, runtime)
        all_findings.extend(findings)
        for f in findings:
            console.print(f"  [bold red]⚠ {f['type']}: {f.get('param', '')}[/bold red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} deserialization vectors found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No insecure deserialization detected[/green]")

    return {'findings': all_findings}
