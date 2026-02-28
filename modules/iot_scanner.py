"""IoT/Firmware Scanner — UPnP discovery, default creds, exposed management panels."""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin
from modules.core import console

MANAGEMENT_PATHS = [
    '/admin', '/administrator', '/management', '/manager', '/console',
    '/system', '/config', '/setup', '/panel', '/dashboard', '/control',
    '/webui', '/web', '/portal', '/gui', '/cgi-bin/', '/goform/',
    '/login.cgi', '/status.cgi', '/admin.cgi', '/firmware',
]

DEFAULT_CREDS = [
    ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
    ('admin', '12345'), ('admin', ''), ('root', 'root'),
    ('root', 'admin'), ('root', 'password'), ('root', 'toor'),
    ('root', ''), ('user', 'user'), ('test', 'test'),
    ('admin', 'admin123'), ('admin', 'pass'), ('guest', 'guest'),
    ('admin', 'changeme'), ('admin', 'default'), ('superadmin', 'admin'),
    ('administrator', 'administrator'), ('cisco', 'cisco'),
    ('ubnt', 'ubnt'), ('pi', 'raspberry'), ('admin', 'mikrotik'),
    ('admin', 'Admin@123'), ('admin', 'P@ssw0rd'), ('support', 'support'),
]

IOT_INDICATORS = {
    'Router': ['router', 'gateway', 'firewall', 'netgear', 'linksys', 'tplink', 'tp-link',
               'dlink', 'd-link', 'asus', 'mikrotik', 'ubiquiti', 'cisco', 'zyxel'],
    'Camera': ['camera', 'ipcam', 'webcam', 'dvr', 'nvr', 'hikvision', 'dahua',
               'axis', 'foscam', 'amcrest', 'reolink', 'wyze'],
    'Printer': ['printer', 'cups', 'jetdirect', 'hp ', 'epson', 'brother', 'canon',
                'xerox', 'ricoh', 'lexmark'],
    'NAS': ['nas', 'synology', 'qnap', 'western digital', 'freenas', 'truenas',
            'buffalo', 'drobo', 'netgear readynas'],
    'Smart Home': ['smart', 'iot', 'home assistant', 'openhab', 'domoticz',
                   'philips hue', 'sonos', 'nest', 'ring'],
}

UPNP_PATHS = ['/upnp.xml', '/description.xml', '/rootDesc.xml', '/devicedesc.xml',
              '/gatedesc.xml', '/IGDdevicedesc.xml', '/WANIPConnection.xml']


async def _scan_management_panels(session, url):
    findings = []
    for path in MANAGEMENT_PATHS:
        test_url = urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status in (200, 401):
                    body = '' if resp.status == 401 else await resp.text()
                    has_login = bool(re.search(r'<(?:input|form).*(?:password|login|user)', body, re.I))

                    if resp.status == 401:
                        auth_type = resp.headers.get('WWW-Authenticate', '')
                        findings.append({
                            'type': f'Management Panel: {path}',
                            'auth': auth_type[:30],
                            'severity': 'High',
                        })
                    elif has_login:
                        device_type = 'Unknown'
                        body_lower = body.lower()
                        for dtype, indicators in IOT_INDICATORS.items():
                            if any(ind in body_lower for ind in indicators):
                                device_type = dtype
                                break
                        findings.append({
                            'type': f'Login Panel: {path} ({device_type})',
                            'severity': 'High',
                            'size': len(body),
                        })
        except Exception:
            pass
    return findings


async def _test_default_creds(session, url, panels):
    findings = []
    for panel in panels[:5]:
        path = panel.get('type', '').split(': ')[1].split(' ')[0] if ': ' in panel.get('type', '') else '/admin'
        login_url = urljoin(url, path)

        for username, password in DEFAULT_CREDS[:15]:
            try:
                data = {'username': username, 'password': password,
                        'user': username, 'pass': password,
                        'login': username, 'pwd': password}
                async with session.post(login_url, data=data,
                                        timeout=aiohttp.ClientTimeout(total=5),
                                        ssl=False, allow_redirects=False) as resp:
                    if resp.status in (302, 303):
                        location = resp.headers.get('Location', '')
                        if any(k in location.lower() for k in ['dashboard', 'admin', 'home', 'index', 'welcome']):
                            findings.append({
                                'type': f'Default Creds: {username}:{password}',
                                'path': path,
                                'severity': 'Critical',
                            })
                            break
                    elif resp.status == 200:
                        body = await resp.text()
                        if any(k in body.lower() for k in ['dashboard', 'welcome', 'logout', 'sign out']):
                            if 'invalid' not in body.lower() and 'error' not in body.lower()[:200]:
                                findings.append({
                                    'type': f'Default Creds: {username}:{password}',
                                    'path': path,
                                    'severity': 'Critical',
                                })
                                break
            except Exception:
                pass

            try:
                auth = aiohttp.BasicAuth(username, password)
                async with session.get(login_url, auth=auth,
                                       timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if len(body) > 100:
                            findings.append({
                                'type': f'Basic Auth Default: {username}:{password}',
                                'path': path,
                                'severity': 'Critical',
                            })
                            break
            except Exception:
                pass
    return findings


async def _scan_upnp(session, url):
    findings = []
    for path in UPNP_PATHS:
        try:
            async with session.get(urljoin(url, path),
                                   timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if any(k in body.lower() for k in ['<device', 'upnp', '<service', 'urn:']):
                        model = re.search(r'<modelName>([^<]+)', body)
                        manufacturer = re.search(r'<manufacturer>([^<]+)', body)
                        findings.append({
                            'type': f'UPnP Exposed: {path}',
                            'model': model.group(1) if model else 'Unknown',
                            'manufacturer': manufacturer.group(1) if manufacturer else 'Unknown',
                            'severity': 'High',
                        })
        except Exception:
            pass
    return findings


async def _check_firmware_exposure(session, url):
    findings = []
    fw_paths = ['/firmware', '/fw', '/update', '/upgrade', '/backup',
                '/config.bin', '/config.cfg', '/backup.cfg', '/export',
                '/cgi-bin/export_settings', '/system/config', '/rom-0']
    for path in fw_paths:
        try:
            async with session.get(urljoin(url, path),
                                   timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status == 200:
                    ct = resp.headers.get('Content-Type', '')
                    if 'octet' in ct or 'binary' in ct or 'download' in ct:
                        findings.append({
                            'type': f'Firmware/Config Download: {path}',
                            'severity': 'Critical',
                            'content_type': ct,
                        })
        except Exception:
            pass
    return findings


async def scan_iot(session, url):
    console.print(f"\n[bold cyan]--- IoT/Firmware Scanner ---[/bold cyan]")
    all_findings = []

    console.print(f"  [cyan]Scanning management panels ({len(MANAGEMENT_PATHS)} paths)...[/cyan]")
    panels = await _scan_management_panels(session, url)
    all_findings.extend(panels)

    if panels:
        console.print(f"  [cyan]Testing default credentials ({len(DEFAULT_CREDS)} combos)...[/cyan]")
        creds = await _test_default_creds(session, url, panels)
        all_findings.extend(creds)
        for f in creds:
            console.print(f"  [bold red]⚠ {f['type']}[/bold red]")

    console.print(f"  [cyan]Scanning UPnP ({len(UPNP_PATHS)} paths)...[/cyan]")
    upnp = await _scan_upnp(session, url)
    all_findings.extend(upnp)

    console.print(f"  [cyan]Checking firmware/config exposure...[/cyan]")
    firmware = await _check_firmware_exposure(session, url)
    all_findings.extend(firmware)

    for f in all_findings:
        if f not in panels:
            console.print(f"  [bold red]⚠ {f['type']}[/bold red]")
    if not all_findings:
        console.print(f"\n  [green]✓ No IoT/management panels found[/green]")
    return {'findings': all_findings}
