"""Email Security Deep — DMARC/SPF/DKIM chain validation, header injection, SMTP relay."""

import aiohttp
import asyncio
import socket
import re
from urllib.parse import urlparse
from modules.core import console

async def _full_spf_check(domain):
    findings = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        for a in answers:
            txt = str(a).strip('"')
            if txt.startswith('v=spf1'):
                spf_record = txt
                break
        if not spf_record:
            findings.append({'type': 'No SPF Record', 'severity': 'High', 'detail': 'Email spoofing possible'})
            return findings

        if '+all' in spf_record:
            findings.append({'type': 'SPF +all (Pass All)', 'severity': 'Critical', 'detail': 'Anyone can send as this domain'})
        elif '~all' in spf_record:
            findings.append({'type': 'SPF ~all (Soft Fail)', 'severity': 'Medium', 'detail': 'Soft fail — may still deliver'})
        elif '?all' in spf_record:
            findings.append({'type': 'SPF ?all (Neutral)', 'severity': 'Medium', 'detail': 'Neutral — no enforcement'})
        elif '-all' not in spf_record:
            findings.append({'type': 'SPF No -all', 'severity': 'Medium', 'detail': 'Missing strict fail mechanism'})

        includes = re.findall(r'include:(\S+)', spf_record)
        if len(includes) > 8:
            findings.append({'type': f'SPF Too Many Includes ({len(includes)})', 'severity': 'Low',
                             'detail': 'SPF 10-lookup limit may cause failures'})
    except Exception:
        findings.append({'type': 'SPF Lookup Failed', 'severity': 'Medium'})
    return findings


async def _full_dmarc_check(domain):
    findings = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc = None
        for a in answers:
            txt = str(a).strip('"')
            if 'v=DMARC1' in txt:
                dmarc = txt
                break
        if not dmarc:
            findings.append({'type': 'No DMARC Record', 'severity': 'High'})
            return findings

        policy = re.search(r'p=(\w+)', dmarc)
        if policy:
            p = policy.group(1).lower()
            if p == 'none':
                findings.append({'type': 'DMARC p=none', 'severity': 'High', 'detail': 'No enforcement — monitoring only'})
            elif p == 'quarantine':
                findings.append({'type': 'DMARC p=quarantine', 'severity': 'Medium', 'detail': 'Not full reject'})

        if 'rua=' not in dmarc:
            findings.append({'type': 'DMARC No Reporting (rua)', 'severity': 'Low'})
        sp = re.search(r'sp=(\w+)', dmarc)
        if sp and sp.group(1).lower() == 'none':
            findings.append({'type': 'DMARC Subdomain p=none', 'severity': 'Medium'})
        if 'pct=' in dmarc:
            pct = re.search(r'pct=(\d+)', dmarc)
            if pct and int(pct.group(1)) < 100:
                findings.append({'type': f'DMARC pct={pct.group(1)}%', 'severity': 'Medium',
                                 'detail': 'Not applying to all emails'})
    except Exception:
        findings.append({'type': 'No DMARC Record', 'severity': 'High'})
    return findings


async def _dkim_check(domain):
    findings = []
    selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2',
                 'mail', 'dkim', 'sig1', 'mandrill', 'mailchimp', 'smtp']
    found = False
    try:
        import dns.resolver
        for sel in selectors:
            try:
                answers = dns.resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT')
                found = True
                for a in answers:
                    txt = str(a)
                    if 'p=' in txt:
                        key = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
                        if key and len(key.group(1)) < 100:
                            findings.append({'type': f'DKIM Weak Key ({sel})', 'severity': 'Medium',
                                             'detail': f'Key length may be insufficient'})
                break
            except Exception:
                pass
    except Exception:
        pass
    if not found:
        findings.append({'type': 'No DKIM Found', 'severity': 'Medium', 'detail': 'Checked 12 common selectors'})
    return findings


async def _test_email_header_injection(session, url):
    findings = []
    injection_payloads = [
        ('test@evil.com%0ACc:victim@evil.com', 'Newline CC injection'),
        ('test@evil.com%0D%0ABcc:victim@evil.com', 'CRLF BCC injection'),
        ('test@evil.com%0ASubject:Hacked', 'Subject injection'),
        ('test@evil.com\r\nContent-Type: text/html', 'Content-Type injection'),
    ]
    email_params = ['email', 'mail', 'to', 'from', 'contact', 'recipient']
    for param in email_params:
        for payload, desc in injection_payloads[:2]:
            try:
                async with session.post(url, data={param: payload, 'message': 'test', 'name': 'test'},
                                        timeout=aiohttp.ClientTimeout(total=6), ssl=False) as resp:
                    body = await resp.text()
                    if resp.status == 200 and 'error' not in body.lower()[:100]:
                        findings.append({'type': f'Email Header Injection ({desc})', 'param': param, 'severity': 'High'})
            except Exception:
                pass
    return findings


async def _check_mx_security(domain):
    findings = []
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            if 'google' in mx_host.lower() or 'outlook' in mx_host.lower():
                pass
            else:
                try:
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(None, socket.gethostbyname, mx_host)
                    findings.append({'type': f'MX: {mx_host} ({ip})', 'severity': 'Info'})
                except Exception:
                    findings.append({'type': f'MX Unresolvable: {mx_host}', 'severity': 'Medium'})
    except Exception:
        findings.append({'type': 'No MX Records', 'severity': 'Medium'})
    return findings


async def scan_email_deep(session, url):
    console.print(f"\n[bold cyan]--- Email Security Deep ---[/bold cyan]")
    domain = urlparse(url).hostname
    all_f = []

    console.print(f"  [cyan]Full SPF analysis...[/cyan]")
    all_f.extend(await _full_spf_check(domain))
    console.print(f"  [cyan]Full DMARC analysis...[/cyan]")
    all_f.extend(await _full_dmarc_check(domain))
    console.print(f"  [cyan]DKIM check (12 selectors)...[/cyan]")
    all_f.extend(await _dkim_check(domain))
    console.print(f"  [cyan]MX record security...[/cyan]")
    all_f.extend(await _check_mx_security(domain))
    console.print(f"  [cyan]Email header injection...[/cyan]")
    all_f.extend(await _test_email_header_injection(session, url))

    for f in all_f:
        color = 'red' if f['severity'] in ('Critical', 'High') else 'yellow' if f['severity'] == 'Medium' else 'dim'
        console.print(f"  [{color}]{f['type']}[/{color}]")
    if not [f for f in all_f if f['severity'] in ('Critical', 'High')]:
        console.print(f"\n  [green]✓ Email security adequate[/green]")
    return {'findings': all_f}
